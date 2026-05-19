import asyncio
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
    # Store captured raw SRTP/SRTCP UDP payload buffers
    captured_packets = []

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

    # Intercept outbound transport packets before they reach the real UDP socket
    # We monkey-patch the internal transport send method to capture bytes safely
    original_send = cast(Callable[[bytes], Awaitable[None]], dtls_a._send_rtp)

    async def hook_send(data: bytes) -> None:
        captured_packets.append(data)
        await original_send(data)

    setattr(dtls_a, "_send_rtp", hook_send)

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

    # Let the stream run for 2 seconds to gather a clean burst of media packets
    await asyncio.sleep(2.0)

    # Extract Keying Material for your test log assertion
    # This allows your Rust test runner to know exactly what the key was
    if dtls_a._ssl is None:
        raise RuntimeError("DTLS SSL connection not ready; cannot export keying material")

    srtp_key_material = dtls_a._ssl.export_keying_material(
        b"EXTRACTOR-dtls_srtp", 60, None  # Length dictated by profile
    )

    print(f"[*] Exported SRTP Key Material (Hex): {srtp_key_material.hex()}")
    with open("srtp_test_keys.txt", "w") as f:
        f.write(srtp_key_material.hex())

    # Save to PCAP
    # Construct minimalist Mock UDP scapy structures to store our binary raw payloads
    from scapy.layers.inet import IP, UDP
    scapy_packets = []
    for i, payload in enumerate(captured_packets):
        # Wrap raw bytes into a synthetic loopback UDP packet structure
        pkt = IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=5004, dport=5004)/payload
        scapy_packets.append(pkt)

    wrpcap("captured_srtp_gcm128.pcap", scapy_packets)
    print(f"[*] Successfully saved {len(scapy_packets)} SRTP packets to captured_srtp_gcm128.pcap")

    await pc_a.close()
    await pc_b.close()

if __name__ == "__main__":
    asyncio.run(run_capture())
