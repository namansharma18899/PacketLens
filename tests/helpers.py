"""Shared test helpers: build minimal Ethernet+IP+TCP and TLS Client Hello with SNI."""

import struct


def build_tls_client_hello_with_sni(sni: str) -> bytes:
    """Build a minimal TLS Client Hello with SNI extension (big-endian where required)."""
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack(">H", len(sni_ext)) + sni_ext
    client_hello_body = (
        struct.pack(">H", 0x0303)
        + b"\x00" * 32
        + b"\x00"
        + struct.pack(">H", 4)
        + struct.pack(">HH", 0x1301, 0x1302)
        + b"\x01\x00"
        + extensions
    )
    handshake = struct.pack("B", 0x01) + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body
    record = struct.pack("B", 0x16) + struct.pack(">HH", 0x0301, len(handshake)) + handshake
    return record


def build_eth_ip_tcp_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 443,
    payload: bytes = b"",
) -> bytes:
    """Build Ethernet + IPv4 + TCP packet (no options)."""
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)
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
        0x02,
        65535,
        0,
        0,
    )
    return eth + ip + tcp + payload
