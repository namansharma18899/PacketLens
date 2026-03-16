"""Tests for pcap_reader: headers and PcapReader."""

import struct
import tempfile
from pathlib import Path

import pytest

from pcap_reader import (
    PCAP_MAGIC_NATIVE,
    PcapGlobalHeader,
    PcapPacketHeader,
    RawPacket,
    PcapReader,
)


def _write_minimal_pcap(path: Path, num_packets: int = 2) -> None:
    """Write a minimal valid PCAP with a few packets."""
    with open(path, "wb") as f:
        # Global header (native little-endian)
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1))
        for i in range(num_packets):
            data = bytes([i] * 60)  # 60 bytes dummy payload
            f.write(struct.pack("<IIII", 1000 + i, 0, len(data), len(data)))
            f.write(data)


class TestPcapGlobalHeader:
    def test_unpack_valid(self):
        data = struct.pack("<IHHiIII", PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1)
        h = PcapGlobalHeader.unpack(data)
        assert h.magic_number == PCAP_MAGIC_NATIVE
        assert h.version_major == 2
        assert h.version_minor == 4
        assert h.snaplen == 65535
        assert h.network == 1

    def test_unpack_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            PcapGlobalHeader.unpack(b"x" * 10)

    def test_to_bytes_uses_native_magic(self):
        h = PcapGlobalHeader(0, 2, 4, 0, 0, 65535, 1)
        out = h.to_bytes()
        assert len(out) == PcapGlobalHeader.SIZE
        assert struct.unpack_from("<I", out, 0)[0] == PCAP_MAGIC_NATIVE


class TestPcapPacketHeader:
    def test_unpack(self):
        data = struct.pack("<IIII", 1000, 500000, 60, 60)
        h = PcapPacketHeader.unpack(data, byte_swap=False)
        assert h.ts_sec == 1000
        assert h.ts_usec == 500000
        assert h.incl_len == 60
        assert h.orig_len == 60

    def test_to_bytes_roundtrip(self):
        h = PcapPacketHeader(1, 2, 100, 100)
        assert PcapPacketHeader.unpack(h.to_bytes(), False).ts_sec == 1


class TestPcapReader:
    def test_open_and_read_packets(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            _write_minimal_pcap(Path(tf.name), num_packets=3)
            path = tf.name
        try:
            reader = PcapReader()
            assert reader.open(path) is True
            assert reader.is_open()
            gh = reader.get_global_header()
            assert gh.snaplen == 65535
            raw = RawPacket(header=PcapPacketHeader(0, 0, 0, 0), data=b"")
            count = 0
            while reader.read_next_packet(raw):
                count += 1
                assert len(raw.data) == 60
            assert count == 3
            reader.close()
            assert not reader.is_open()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_open_nonexistent_fails(self):
        reader = PcapReader()
        assert reader.open("/nonexistent/path/file.pcap") is False

    def test_read_past_end_returns_false(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            _write_minimal_pcap(Path(tf.name), num_packets=0)
            path = tf.name
        try:
            reader = PcapReader()
            reader.open(path)
            raw = RawPacket(header=PcapPacketHeader(0, 0, 0, 0), data=b"")
            assert reader.read_next_packet(raw) is False
        finally:
            Path(path).unlink(missing_ok=True)
