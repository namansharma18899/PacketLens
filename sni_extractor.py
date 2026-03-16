"""Extract SNI from TLS Client Hello and Host from HTTP requests."""

from typing import Optional

# TLS
CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        return 0
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    if offset + 3 > len(data):
        return 0
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


class SNIExtractor:
    """Extract Server Name Indication from TLS Client Hello payload."""

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        if payload[0] != CONTENT_TYPE_HANDSHAKE:
            return False
        version = _read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        record_len = _read_uint16_be(payload, 3)
        if record_len > len(payload) - 5:
            return False
        if payload[5] != HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS Client Hello. Returns None if not found."""
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        length = len(payload)
        offset = 5  # past TLS record header

        # Handshake header: 1 byte type + 3 bytes length
        handshake_length = _read_uint24_be(payload, offset + 1)
        offset += 4

        # Client version (2 bytes), Random (32 bytes)
        offset += 2 + 32

        if offset >= length:
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > length:
            return None
        cipher_len = _read_uint16_be(payload, offset)
        offset += 2 + cipher_len

        if offset >= length:
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        if offset + 2 > length:
            return None
        extensions_len = _read_uint16_be(payload, offset)
        offset += 2
        extensions_end = offset + extensions_len
        if extensions_end > length:
            extensions_end = length

        while offset + 4 <= extensions_end:
            ext_type = _read_uint16_be(payload, offset)
            ext_len = _read_uint16_be(payload, offset + 2)
            offset += 4
            if offset + ext_len > extensions_end:
                break
            if ext_type == EXTENSION_SNI:
                if ext_len < 5:
                    break
                sni_list_len = _read_uint16_be(payload, offset)
                if sni_list_len < 3:
                    break
                sni_type = payload[offset + 2]
                sni_len = _read_uint16_be(payload, offset + 3)
                if sni_type != SNI_TYPE_HOSTNAME:
                    break
                if sni_len > ext_len - 5:
                    break
                hostname = payload[offset + 5 : offset + 5 + sni_len].decode("utf-8", errors="replace")
                return hostname
            offset += ext_len

        return None


class HTTPHostExtractor:
    """Extract Host header from plain HTTP request."""

    _METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        for method in HTTPHostExtractor._METHODS:
            if payload[:4] == method:
                return True
        return False

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """Extract Host header value. Returns None if not found."""
        if not HTTPHostExtractor.is_http_request(payload):
            return None

        length = len(payload)
        host_label = b"Host:"
        i = 0
        while i + 5 < length:
            if (
                payload[i] in (ord("H"), ord("h"))
                and payload[i + 1] in (ord("o"), ord("O"))
                and payload[i + 2] in (ord("s"), ord("S"))
                and payload[i + 3] in (ord("t"), ord("T"))
                and payload[i + 4] == ord(":")
            ):
                start = i + 5
                while start < length and payload[start] in (ord(" "), ord("\t")):
                    start += 1
                end = start
                while end < length and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1
                if end > start:
                    host = payload[start:end].decode("utf-8", errors="replace").strip()
                    if ":" in host:
                        host = host.split(":")[0]
                    return host
                return None
            i += 1
        return None
