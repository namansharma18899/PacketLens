"""PCAP file reading: global header, packet headers, and raw packet data."""

import struct
from dataclasses import dataclass, field
from typing import BinaryIO, List, Optional


# Magic numbers
PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass
class PcapGlobalHeader:
    """24-byte PCAP global header."""
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int

    SIZE = 24

    @classmethod
    def unpack(cls, data: bytes) -> "PcapGlobalHeader":
        if len(data) < cls.SIZE:
            raise ValueError("Global header too short")
        return cls(
            magic_number=struct.unpack_from("<I", data, 0)[0],
            version_major=struct.unpack_from("<H", data, 4)[0],
            version_minor=struct.unpack_from("<H", data, 6)[0],
            thiszone=struct.unpack_from("<i", data, 8)[0],
            sigfigs=struct.unpack_from("<I", data, 12)[0],
            snaplen=struct.unpack_from("<I", data, 16)[0],
            network=struct.unpack_from("<I", data, 20)[0],
        )

    def to_bytes(self) -> bytes:
        """Serialize for writing output PCAP (native little-endian)."""
        return struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_NATIVE,  # output always native
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network,
        )


@dataclass
class PcapPacketHeader:
    """16-byte per-packet header."""
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int

    SIZE = 16

    @classmethod
    def unpack(cls, data: bytes, byte_swap: bool = False) -> "PcapPacketHeader":
        if len(data) < cls.SIZE:
            raise ValueError("Packet header too short")
        if byte_swap:
            ts_sec = struct.unpack(">I", data[0:4])[0]
            ts_usec = struct.unpack(">I", data[4:8])[0]
            incl_len = struct.unpack(">I", data[8:12])[0]
            orig_len = struct.unpack(">I", data[12:16])[0]
        else:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", data[:16])
        return cls(ts_sec=ts_sec, ts_usec=ts_usec, incl_len=incl_len, orig_len=orig_len)

    def to_bytes(self) -> bytes:
        return struct.pack("<IIII", self.ts_sec, self.ts_usec, self.incl_len, self.orig_len)


@dataclass
class RawPacket:
    """One captured packet: header + raw bytes."""
    header: PcapPacketHeader
    data: bytes = b""


class PcapReader:
    """Read PCAP files with correct byte order handling."""

    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self._global_header: Optional[PcapGlobalHeader] = None
        self._byte_swap: bool = False

    def open(self, filename: str) -> bool:
        """Open PCAP file and read global header. Returns True on success."""
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            print(f"Error: Could not open file: {filename}", e)
            return False

        buf = self._file.read(PcapGlobalHeader.SIZE)
        if len(buf) < PcapGlobalHeader.SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic = struct.unpack_from("<I", buf, 0)[0]
        if magic == PCAP_MAGIC_SWAPPED:
            self._byte_swap = True
            # Re-read header with big-endian for the rest of fields
            self._global_header = PcapGlobalHeader(
                magic_number=struct.unpack_from(">I", buf, 0)[0],
                version_major=struct.unpack_from(">H", buf, 4)[0],
                version_minor=struct.unpack_from(">H", buf, 6)[0],
                thiszone=struct.unpack_from(">i", buf, 8)[0],
                sigfigs=struct.unpack_from(">I", buf, 12)[0],
                snaplen=struct.unpack_from(">I", buf, 16)[0],
                network=struct.unpack_from(">I", buf, 20)[0],
            )
        elif magic == PCAP_MAGIC_NATIVE:
            self._byte_swap = False
            self._global_header = PcapGlobalHeader.unpack(buf)
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08X}")
            self.close()
            return False

        print(f"Opened PCAP file: {filename}")
        gh = self._global_header
        print(f"  Version: {gh.version_major}.{gh.version_minor}")
        print(f"  Snaplen: {gh.snaplen} bytes")
        print(f"  Link type: {gh.network} {'(Ethernet)' if gh.network == 1 else ''}")
        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._global_header = None
        self._byte_swap = False

    def is_open(self) -> bool:
        return self._file is not None

    def get_global_header(self) -> PcapGlobalHeader:
        if self._global_header is None:
            raise RuntimeError("No file open")
        return self._global_header

    def read_next_packet(self, packet: RawPacket) -> bool:
        """Read next packet into packet. Returns False when no more packets or error."""
        if self._file is None or self._global_header is None:
            return False

        hdr_buf = self._file.read(PcapPacketHeader.SIZE)
        if len(hdr_buf) < PcapPacketHeader.SIZE:
            return False

        packet.header = PcapPacketHeader.unpack(hdr_buf, self._byte_swap)
        incl = packet.header.incl_len
        if incl > self._global_header.snaplen or incl > 65535:
            print(f"Error: Invalid packet length: {incl}")
            return False

        packet.data = self._file.read(incl)
        if len(packet.data) != incl:
            print("Error: Could not read packet data")
            return False

        return True

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
