"""Tests for packet_parser: ParsedPacket and PacketParser."""

import struct

import pytest

from packet_parser import (
    PacketParser,
    ParsedPacket,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    ETHERTYPE_IPV4,
    TCP_SYN,
    TCP_ACK,
)


def _build_eth_ip_tcp_packet(
    src_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    dst_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 443,
    tcp_flags: int = 0x02,
    payload: bytes = b"",
) -> bytes:
    """Build Ethernet + IPv4 + TCP packet (no options)."""
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)
    # IPv4: version 4, IHL 5 (20 bytes), TOS 0, total_len, id, flags, TTL 64, protocol 6, checksum 0
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    total_len = 20 + 20 + len(payload)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", total_len)
        + b"\x00\x00\x40\x00\x40\x06\x00\x00"
        + src_b
        + dst_b
    )
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        0x50,
        tcp_flags,
        65535,
        0,
        0,
    )
    return eth + ip + tcp + payload


class TestPacketParser:
    def test_parse_minimal_tcp(self):
        pkt = _build_eth_ip_tcp_packet(
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=443,
        )
        parsed = PacketParser.parse(0, 0, pkt)
        assert parsed is not None
        assert parsed.has_ip
        assert parsed.has_tcp
        assert parsed.src_ip == "192.168.1.1"
        assert parsed.dest_ip == "8.8.8.8"
        assert parsed.src_port == 12345
        assert parsed.dest_port == 443
        assert parsed.protocol == PROTOCOL_TCP
        assert parsed.ether_type == ETHERTYPE_IPV4
        assert parsed.payload_offset == 14 + 20 + 20
        assert parsed.payload_length == 0

    def test_parse_with_payload(self):
        payload = b"GET / HTTP/1.1\r\n"
        pkt = _build_eth_ip_tcp_packet(payload=payload)
        parsed = PacketParser.parse(100, 200, pkt)
        assert parsed is not None
        assert parsed.payload_length == len(payload)
        assert parsed.payload_data == payload

    def test_parse_too_short_returns_none(self):
        assert PacketParser.parse(0, 0, b"") is None
        assert PacketParser.parse(0, 0, b"x" * 13) is None

    def test_parse_non_ip_returns_parsed_without_ip(self):
        # Ethernet with ARP (0x0806)
        eth = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x08\x06" + b"\x00" * 40
        parsed = PacketParser.parse(0, 0, eth)
        assert parsed is not None
        assert not parsed.has_ip
        assert parsed.ether_type == 0x0806

    def test_protocol_to_string(self):
        assert PacketParser.protocol_to_string(PROTOCOL_TCP) == "TCP"
        assert PacketParser.protocol_to_string(PROTOCOL_UDP) == "UDP"

    def test_tcp_flags_to_string(self):
        assert "SYN" in PacketParser.tcp_flags_to_string(TCP_SYN)
        assert "ACK" in PacketParser.tcp_flags_to_string(TCP_ACK)
