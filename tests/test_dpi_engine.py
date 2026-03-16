"""Tests for dpi_engine: run_dpi pipeline with fixture PCAP."""

import struct
import tempfile
from pathlib import Path

import pytest

from dpi_engine import run_dpi
from rule_manager import RuleManager
from pcap_reader import PCAP_MAGIC_NATIVE

from tests.helpers import build_tls_client_hello_with_sni, build_eth_ip_tcp_packet


def _write_simple_pcap(path: Path, one_tls_packet: bytes) -> None:
    """Write a PCAP with global header and one packet (Ethernet+IP+TCP+TLS payload)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1000, 0, len(one_tls_packet), len(one_tls_packet)))
        f.write(one_tls_packet)


def _eth_ip_tcp_tls(sni: str) -> bytes:
    """Build full packet: Eth + IP + TCP + TLS Client Hello with SNI."""
    tls = build_tls_client_hello_with_sni(sni)
    return build_eth_ip_tcp_packet(dst_port=443, payload=tls)


class TestRunDpi:
    def test_run_dpi_produces_output_file(self):
        pkt = _eth_ip_tcp_tls("www.example.com")
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in.pcap"
            out = Path(tmp) / "out.pcap"
            _write_simple_pcap(inp, pkt)
            rules = RuleManager()
            ok = run_dpi(str(inp), str(out), rules, verbose=False)
            assert ok is True
            assert out.exists()
            assert out.stat().st_size > 0

    def test_run_dpi_with_block_drops_packets(self):
        # Two flows (different src ports): youtube (blocked), example.com (allowed)
        pkt_youtube = _eth_ip_tcp_tls("www.youtube.com")
        pkt_example = build_eth_ip_tcp_packet(
            src_port=54322, dst_port=443, payload=build_tls_client_hello_with_sni("www.example.com")
        )
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in.pcap"
            out = Path(tmp) / "out.pcap"
            with open(inp, "wb") as f:
                f.write(struct.pack("<IHHiIII", PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1))
                for i, data in enumerate([pkt_youtube, pkt_example]):
                    f.write(struct.pack("<IIII", 1000 + i, 0, len(data), len(data)))
                    f.write(data)
            rules = RuleManager()
            rules.block_app("YouTube")
            ok = run_dpi(str(inp), str(out), rules, verbose=False)
            assert ok is True
            # Output should have one packet (example.com); YouTube flow blocked
            with open(out, "rb") as f:
                f.read(24)  # global header
                count = 0
                while True:
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break
                    incl = struct.unpack("<I", hdr[8:12])[0]
                    f.read(incl)
                    count += 1
            assert count == 1

    def test_run_dpi_nonexistent_input_returns_false(self):
        rules = RuleManager()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            out_path = tf.name
        try:
            ok = run_dpi("/nonexistent/input.pcap", out_path, rules, verbose=False)
            assert ok is False
        finally:
            Path(out_path).unlink(missing_ok=True)
