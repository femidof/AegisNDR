#!/usr/bin/env python3
"""Generate the deterministic packet capture used by the sensor acceptance test.

The fixture intentionally uses documentation-only address ranges.  It contains a
complete HTTP exchange and a DNS query/answer so both Suricata and Zeek exercise
real protocol decoders without requiring host networking or capture privileges.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import struct
from pathlib import Path


PCAP_TIMESTAMP = 1_785_891_300
CLIENT_IP = "10.77.0.10"
SERVER_IP = "10.77.0.20"
DNS_IP = "10.77.0.53"
ANSWER_IP = "203.0.113.55"
CLIENT_MAC = bytes.fromhex("02000000000a")
SERVER_MAC = bytes.fromhex("020000000014")
DNS_MAC = bytes.fromhex("020000000035")


def checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    words = struct.unpack(f"!{len(payload) // 2}H", payload)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, source: bytes, destination: bytes) -> bytes:
    return destination + source + struct.pack("!H", 0x0800) + payload


def ipv4(payload: bytes, source: str, destination: str, protocol: int, packet_id: int) -> bytes:
    source_bytes = ipaddress.ip_address(source).packed
    destination_bytes = ipaddress.ip_address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        packet_id,
        0x4000,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(
    payload: bytes,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
) -> bytes:
    header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64_240,
        0,
        0,
    )
    pseudo_header = (
        ipaddress.ip_address(source_ip).packed
        + ipaddress.ip_address(destination_ip).packed
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    tcp_checksum = checksum(pseudo_header + header + payload)
    return header[:16] + struct.pack("!H", tcp_checksum) + header[18:] + payload


def udp(payload: bytes, source_ip: str, destination_ip: str, source_port: int, destination_port: int) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", source_port, destination_port, length, 0)
    pseudo_header = (
        ipaddress.ip_address(source_ip).packed
        + ipaddress.ip_address(destination_ip).packed
        + struct.pack("!BBH", 0, 17, length)
    )
    udp_checksum = checksum(pseudo_header + header + payload) or 0xFFFF
    return struct.pack("!HHHH", source_port, destination_port, length, udp_checksum) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def packets() -> list[bytes]:
    request = (
        b"GET /hybrid-ndr-sensor-acceptance HTTP/1.1\r\n"
        b"Host: sensor-acceptance.hybrid-ndr.test\r\n"
        b"User-Agent: hybrid-ndr-fixture/1.0\r\n"
        b"Connection: close\r\n\r\n"
    )
    response_body = b"hybrid-ndr-sensor-pipeline-ok\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
        + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
        + response_body
    )

    client_sequence = 1_000
    server_sequence = 7_000
    frames: list[bytes] = []

    def tcp_frame(
        source_ip: str,
        destination_ip: str,
        source_mac: bytes,
        destination_mac: bytes,
        source_port: int,
        destination_port: int,
        sequence: int,
        acknowledgement: int,
        flags: int,
        payload: bytes,
        packet_id: int,
    ) -> None:
        segment = tcp(
            payload,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            sequence,
            acknowledgement,
            flags,
        )
        frames.append(ethernet(ipv4(segment, source_ip, destination_ip, 6, packet_id), source_mac, destination_mac))

    tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, 45_678, 8_080, client_sequence, 0, 0x02, b"", 1)
    tcp_frame(SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC, 8_080, 45_678, server_sequence, client_sequence + 1, 0x12, b"", 2)
    tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, 45_678, 8_080, client_sequence + 1, server_sequence + 1, 0x10, b"", 3)
    tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, 45_678, 8_080, client_sequence + 1, server_sequence + 1, 0x18, request, 4)
    tcp_frame(
        SERVER_IP,
        CLIENT_IP,
        SERVER_MAC,
        CLIENT_MAC,
        8_080,
        45_678,
        server_sequence + 1,
        client_sequence + 1 + len(request),
        0x18,
        response,
        5,
    )
    tcp_frame(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_MAC,
        SERVER_MAC,
        45_678,
        8_080,
        client_sequence + 1 + len(request),
        server_sequence + 1 + len(response),
        0x11,
        b"",
        6,
    )
    tcp_frame(
        SERVER_IP,
        CLIENT_IP,
        SERVER_MAC,
        CLIENT_MAC,
        8_080,
        45_678,
        server_sequence + 1 + len(response),
        client_sequence + 2 + len(request),
        0x11,
        b"",
        7,
    )
    tcp_frame(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_MAC,
        SERVER_MAC,
        45_678,
        8_080,
        client_sequence + 2 + len(request),
        server_sequence + 2 + len(response),
        0x10,
        b"",
        8,
    )

    question = dns_name("sensor-acceptance.hybrid-ndr.test") + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0x4E44, 0x0100, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.ip_address(ANSWER_IP).packed
    reply = struct.pack("!HHHHHH", 0x4E44, 0x8180, 1, 1, 0, 0) + question + answer

    query_datagram = udp(query, CLIENT_IP, DNS_IP, 53_000, 53)
    frames.append(ethernet(ipv4(query_datagram, CLIENT_IP, DNS_IP, 17, 9), CLIENT_MAC, DNS_MAC))
    reply_datagram = udp(reply, DNS_IP, CLIENT_IP, 53, 53_000)
    frames.append(ethernet(ipv4(reply_datagram, DNS_IP, CLIENT_IP, 17, 10), DNS_MAC, CLIENT_MAC))
    return frames


def render_pcap() -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    for index, frame in enumerate(packets()):
        microseconds = index * 100_000
        output.extend(struct.pack("<IIII", PCAP_TIMESTAMP, microseconds, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify-sha256", help="fail unless the generated capture has this digest")
    args = parser.parse_args()

    payload = render_pcap()
    digest = hashlib.sha256(payload).hexdigest()
    if args.verify_sha256 and digest != args.verify_sha256:
        raise SystemExit(f"fixture digest mismatch: expected {args.verify_sha256}, got {digest}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(f"wrote {len(packets())} packets to {args.output} (sha256={digest})")


if __name__ == "__main__":
    main()
