from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap


@dataclass(frozen=True)
class RtpPacketView:
    raw: bytes
    payload: bytes
    seq: int
    timestamp: int
    ssrc: int
    payload_type: int


def is_rtp_packet(data: bytes) -> bool:
    if len(data) < 12:
        return False
    payload_type = data[1] & 0b01111111
    return payload_type <= 35 or 96 <= payload_type <= 127


def parse_udp_payloads_from_raw_ipv4_pcap(pcap_path: Path) -> list[bytes]:
    payloads: list[bytes] = []
    packets = rdpcap(str(pcap_path))

    for packet in packets:
        if IP not in packet or UDP not in packet:
            continue

        udp_payload = bytes(packet[UDP].payload)
        if not udp_payload:
            continue
        payloads.append(udp_payload)

    return payloads


def parse_rtp_packets(payloads: Iterable[bytes]) -> list[RtpPacketView]:
    packets: list[RtpPacketView] = []
    for raw in payloads:
        if not is_rtp_packet(raw):
            continue

        # https://docs.python.org/3/library/struct.html#format-strings
        seq = struct.unpack("!H", raw[2:4])[0]
        timestamp = struct.unpack("!I", raw[4:8])[0]
        ssrc = struct.unpack("!I", raw[8:12])[0]
        payload_type = raw[1] & 0x7F
        packets.append(
            RtpPacketView(
                raw=raw,
                payload=raw[12:],
                seq=seq,
                timestamp=timestamp,
                ssrc=ssrc,
                payload_type=payload_type,
            )
        )
    return packets


def packet_key(pkt: RtpPacketView) -> tuple[int, int, int, int]:
    return (pkt.seq, pkt.timestamp, pkt.ssrc, pkt.payload_type)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare plain and encrypted RTP captures and print matched packet pairs."
        )
    )
    parser.add_argument(
        "--plain",
        type=Path,
        default=Path("captured_srtp_gcm128_plain.pcap"),
        help="Plain RTP capture path",
    )
    parser.add_argument(
        "--encrypted",
        type=Path,
        default=Path("captured_srtp_gcm128_encrypted.pcap"),
        help="Encrypted SRTP capture path",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Fail if header bytes differ or encrypted RTP payload length is not plain+16"
        ),
    )
    args = parser.parse_args()

    plain_payloads = parse_udp_payloads_from_raw_ipv4_pcap(args.plain)
    encrypted_payloads = parse_udp_payloads_from_raw_ipv4_pcap(args.encrypted)

    plain_rtp = parse_rtp_packets(plain_payloads)
    encrypted_rtp = parse_rtp_packets(encrypted_payloads)

    plain_by_key = {packet_key(p): p for p in plain_rtp}
    encrypted_by_key = {packet_key(p): p for p in encrypted_rtp}

    common_keys = sorted(set(plain_by_key).intersection(encrypted_by_key))
    plain_only = sorted(set(plain_by_key) - set(encrypted_by_key))
    encrypted_only = sorted(set(encrypted_by_key) - set(plain_by_key))

    print(
        f"plain RTP packets: {len(plain_rtp)} | encrypted RTP packets: {len(encrypted_rtp)} | paired: {len(common_keys)}"
    )

    if common_keys:
        print(
            "idx seq timestamp ssrc payload_type plain_payload_len encrypted_payload_len encrypted_minus_plain"
        )

    had_strict_error = False
    for idx, key in enumerate(common_keys, start=1):
        plain_pkt = plain_by_key[key]
        encrypted_pkt = encrypted_by_key[key]
        delta = len(encrypted_pkt.payload) - len(plain_pkt.payload)

        print(
            f"{idx:>3} {plain_pkt.seq:>4} {plain_pkt.timestamp:>10} 0x{plain_pkt.ssrc:08x}"
            f" {plain_pkt.payload_type:>11} {len(plain_pkt.payload):>17}"
            f" {len(encrypted_pkt.payload):>21} {delta:>22}"
        )

        if args.strict:
            if plain_pkt.raw[:12] != encrypted_pkt.raw[:12]:
                had_strict_error = True
                print(
                    f"[strict] header mismatch for seq={plain_pkt.seq} ssrc=0x{plain_pkt.ssrc:08x}"
                )
            if delta != 16:
                had_strict_error = True
                print(
                    f"[strict] expected encrypted payload length to be plain+16 for seq={plain_pkt.seq}, got delta={delta}"
                )

    if plain_only:
        print("plain-only packet keys:")
        for k in plain_only:
            print(f"  seq={k[0]} ts={k[1]} ssrc=0x{k[2]:08x} pt={k[3]}")

    if encrypted_only:
        print("encrypted-only packet keys:")
        for k in encrypted_only:
            print(f"  seq={k[0]} ts={k[1]} ssrc=0x{k[2]:08x} pt={k[3]}")

    if not common_keys:
        print("No matching RTP packet keys found between captures.")
        return 1

    if args.strict and had_strict_error:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
