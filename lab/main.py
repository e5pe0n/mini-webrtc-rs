import asyncio
import struct
from fractions import Fraction
from typing import Awaitable, Callable, cast

from aiortc import MediaStreamTrack, RTCPeerConnection
from aiortc.rtcdtlstransport import SRTP_AEAD_AES_128_GCM
from av import AudioFrame
from scapy.all import wrpcap


def _iter_dtls_transports(pc):
    # aiortc stores DTLS transports in a name-mangled private list.
    return list(getattr(pc, "_RTCPeerConnection__dtlsTransports", []))

# 1. Create a dummy media track to force SRTP packet flow
class DummyAudioTrack(MediaStreamTrack):
    kind = "audio"

    async def recv(self):
        await asyncio.sleep(0.02)  # 50Hz RTP stream (20ms frames)
        # Provide a silent mono 16-bit frame (20ms @ 48kHz) so aiortc can packetize RTP.
        frame = AudioFrame(format="s16", layout="mono", samples=960)
        for plane in frame.planes:
            plane.update(bytes(plane.buffer_size))
        frame.sample_rate = 48_000
        frame.time_base = Fraction(1, frame.sample_rate)
        return frame

async def run_capture():
    # Capture two views of the same outbound media flow.
    # - plain_packets: payload passed into RTCDtlsTransport._send_rtp (pre-SRTP protect)
    # - encrypted_packets: payload sent by RTCIceTransport._send (post-SRTP protect)
    plain_packets = []
    encrypted_packets = []

    # Local loopback peer setup
    pc_a = RTCPeerConnection()
    pc_b = RTCPeerConnection()

    # Add track from A to B and get A's DTLS transport from the sender.
    track = DummyAudioTrack()
    sender_a = pc_a.addTrack(track)
    dtls_a = sender_a.transport

    # FORCE EXACT CIPHER SUITE: Override aiortc's default OpenSSL context
    # Note: Modern aiortc configures this on its underlying ContextFactory
    # The OpenSSL context is not exposed pre-handshake in current aiortc.
    # We can still request the AEAD AES-GCM SRTP profile before negotiation.
    dtls_a._srtp_profiles = [SRTP_AEAD_AES_128_GCM]

    # Intercept pre-protection RTP/RTCP bytes.
    original_send = cast(Callable[[bytes], Awaitable[None]], dtls_a._send_rtp)

    # Intercept wire-level packets emitted by DTLS transport.
    # This path also carries DTLS handshake records, so filter to RTP/RTCP packet range.
    original_transport_send = cast(Callable[[bytes], Awaitable[None]], dtls_a.transport._send)

    async def hook_transport_send(data: bytes) -> None:
        if len(data) > 1 and 127 < data[0] < 192:
            encrypted_packets.append(data)
        await original_transport_send(data)

    async def hook_send(data: bytes) -> None:
        plain_packets.append(data)
        await original_send(data)

    setattr(dtls_a, "_send_rtp", hook_send)
    setattr(dtls_a.transport, "_send", hook_transport_send)

    # Standard WebRTC Signaling Handshake (Local O/A)
    offer = await pc_a.createOffer()
    await pc_a.setLocalDescription(offer)
    await pc_b.setRemoteDescription(pc_a.localDescription)

    # Once B has remote media, it has DTLS transports we can profile-pin too.
    for dtls_transport in _iter_dtls_transports(pc_b):
        dtls_transport._srtp_profiles = [SRTP_AEAD_AES_128_GCM]

    answer = await pc_b.createAnswer()
    await pc_b.setLocalDescription(answer)
    await pc_a.setRemoteDescription(pc_b.localDescription)

    print("[*] Handshake initiated with ECDHE-ECDSA-AES128-GCM-SHA256...")

    # Ensure we capture at least one RTP packet in both plain and encrypted forms.
    for _ in range(50):
        if dtls_a.state == "connected":
            break
        await asyncio.sleep(0.1)

    if dtls_a.state != "connected":
        raise RuntimeError("DTLS transport did not reach connected state")

    probe_rtp = struct.pack(
        "!BBHII",
        0x80,       # V=2, P=0, X=0, CC=0
        96,         # dynamic payload type
        1,          # sequence number
        0x10203040, # timestamp
        0x11223344, # SSRC
    ) + b"mini-webrtc-rs-srtp-probe"
    await dtls_a._send_rtp(probe_rtp)
    print("[*] Injected one RTP probe packet for fixture generation")

    # Let the stream run for 2 seconds to gather a clean burst of media packets
    await asyncio.sleep(2.0)

    # Extract Keying Material for your test log assertion
    # This allows your Rust test runner to know exactly what the key was
    if dtls_a._ssl is None:
        raise RuntimeError("DTLS SSL connection not ready; cannot export keying material")

    selected_profile = dtls_a._ssl.get_selected_srtp_profile()
    print(f"[*] Negotiated SRTP profile: {selected_profile.decode()}")
    if selected_profile != SRTP_AEAD_AES_128_GCM.openssl_profile:
        raise RuntimeError(
            f"unexpected SRTP profile {selected_profile!r}; expected {SRTP_AEAD_AES_128_GCM.openssl_profile!r}"
        )

    key_material_len = 2 * (
        SRTP_AEAD_AES_128_GCM.key_length + SRTP_AEAD_AES_128_GCM.salt_length
    )
    srtp_key_material = dtls_a._ssl.export_keying_material(
        b"EXTRACTOR-dtls_srtp", key_material_len, None
    )

    print(f"[*] Exported SRTP Key Material (Hex): {srtp_key_material.hex()}")
    with open("srtp_test_keys.txt", "w") as f:
        f.write(srtp_key_material.hex())

    # Save to PCAP as synthetic loopback UDP packets.
    from scapy.layers.inet import IP, UDP

    plain_scapy_packets = []
    encrypted_scapy_packets = []

    for payload in plain_packets:
        pkt = IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=5004, dport=5004)/payload
        plain_scapy_packets.append(pkt)

    for payload in encrypted_packets:
        pkt = IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=5004, dport=5004)/payload
        encrypted_scapy_packets.append(pkt)

    wrpcap("captured_srtp_gcm128_plain.pcap", plain_scapy_packets)
    wrpcap("captured_srtp_gcm128_encrypted.pcap", encrypted_scapy_packets)

    # Keep legacy file name for compatibility, now pointing to encrypted packets.
    wrpcap("captured_srtp_gcm128.pcap", encrypted_scapy_packets)

    print(
        "[*] Successfully saved "
        f"{len(plain_scapy_packets)} plain packets to captured_srtp_gcm128_plain.pcap and "
        f"{len(encrypted_scapy_packets)} encrypted packets to captured_srtp_gcm128_encrypted.pcap"
    )

    await pc_a.close()
    await pc_b.close()

if __name__ == "__main__":
    asyncio.run(run_capture())
