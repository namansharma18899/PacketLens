"""Parse raw packet bytes into Ethernet, IP, TCP/UDP and payload."""

import struct
from dataclasses import dataclass, field
from typing import Optional

# Protocol numbers
PROTOCOL_ICMP = 1
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

# EtherType
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# TCP flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

ETH_HEADER_LEN = 14
MIN_IP_HEADER_LEN = 20
MIN_TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8


def _ntohs(data: bytes, offset: int = 0) -> int:
    """Big-endian 16-bit from wire."""
    return (data[offset] << 8) | data[offset + 1]


def _ntohl(data: bytes, offset: int = 0) -> int:
    """Big-endian 32-bit from wire."""
    return (
        (data[offset] << 24)
        | (data[offset + 1] << 16)
        | (data[offset + 2] << 8)
        | data[offset + 3]
    )


@dataclass
class ParsedPacket:
    """Parsed packet fields (human-readable where applicable)."""
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_offset: int = 0  # offset into original packet data
    payload_data: Optional[bytes] = None  # slice of original; set by caller if needed


def _mac_to_string(data: bytes, offset: int = 0) -> str:
    if offset + 6 > len(data):
        return ""
    return ":".join(f"{data[offset + i]:02x}" for i in range(6))


def _ip_to_string(addr: int) -> str:
    return f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}"


class PacketParser:
    """Parse raw packet bytes into ParsedPacket."""

    @staticmethod
    def parse(header_ts_sec: int, header_ts_usec: int, data: bytes) -> Optional[ParsedPacket]:
        """Parse raw packet. Returns None if too short or invalid."""
        parsed = ParsedPacket(
            timestamp_sec=header_ts_sec,
            timestamp_usec=header_ts_usec,
        )
        length = len(data)
        offset = 0

        if length < ETH_HEADER_LEN:
            return None

        parsed.dest_mac = _mac_to_string(data, 0)
        parsed.src_mac = _mac_to_string(data, 6)
        parsed.ether_type = _ntohs(data, 12)
        offset = ETH_HEADER_LEN

        if parsed.ether_type != ETHERTYPE_IPV4:
            return parsed

        if length < offset + MIN_IP_HEADER_LEN:
            return parsed

        version_ihl = data[offset]
        ihl = (version_ihl & 0x0F) * 4
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        if parsed.ip_version != 4 or ihl < MIN_IP_HEADER_LEN or length < offset + ihl:
            return parsed

        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]
        src_ip = _ntohl(data, offset + 12)
        dest_ip = _ntohl(data, offset + 16)
        parsed.src_ip = _ip_to_string(src_ip)
        parsed.dest_ip = _ip_to_string(dest_ip)
        parsed.has_ip = True
        offset += ihl

        if parsed.protocol == PROTOCOL_TCP:
            if length < offset + MIN_TCP_HEADER_LEN:
                return parsed
            parsed.src_port = _ntohs(data, offset)
            parsed.dest_port = _ntohs(data, offset + 2)
            parsed.seq_number = _ntohl(data, offset + 4)
            parsed.ack_number = _ntohl(data, offset + 8)
            data_offset = (data[offset + 12] >> 4) & 0x0F
            tcp_header_len = data_offset * 4
            if tcp_header_len < MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
                return parsed
            parsed.tcp_flags = data[offset + 13]
            parsed.has_tcp = True
            offset += tcp_header_len
        elif parsed.protocol == PROTOCOL_UDP:
            if length < offset + UDP_HEADER_LEN:
                return parsed
            parsed.src_port = _ntohs(data, offset)
            parsed.dest_port = _ntohs(data, offset + 2)
            parsed.has_udp = True
            offset += UDP_HEADER_LEN

        parsed.payload_offset = offset
        parsed.payload_length = length - offset
        if parsed.payload_length > 0:
            parsed.payload_data = data[offset:]

        return parsed

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        if protocol == PROTOCOL_ICMP:
            return "ICMP"
        if protocol == PROTOCOL_TCP:
            return "TCP"
        if protocol == PROTOCOL_UDP:
            return "UDP"
        return f"Unknown({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCP_FIN:
            parts.append("FIN")
        if flags & TCP_SYN:
            parts.append("SYN")
        if flags & TCP_RST:
            parts.append("RST")
        if flags & TCP_PSH:
            parts.append("PSH")
        if flags & TCP_ACK:
            parts.append("ACK")
        if flags & TCP_URG:
            parts.append("URG")
        return " ".join(parts) if parts else "none"
