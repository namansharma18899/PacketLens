"""Tests for sni_extractor: TLS SNI and HTTP Host."""

import pytest

from sni_extractor import SNIExtractor, HTTPHostExtractor

from tests.helpers import build_tls_client_hello_with_sni


class TestSNIExtractor:
    def test_is_tls_client_hello_valid(self):
        payload = build_tls_client_hello_with_sni("www.example.com")
        assert SNIExtractor.is_tls_client_hello(payload) is True

    def test_is_tls_client_hello_too_short(self):
        assert SNIExtractor.is_tls_client_hello(b"") is False
        assert SNIExtractor.is_tls_client_hello(b"\x16\x03\x01\x00\x01\x01") is False

    def test_is_tls_client_hello_wrong_content_type(self):
        payload = build_tls_client_hello_with_sni("x.com")
        bad = bytes([0x17]) + payload[1:]  # Application data
        assert SNIExtractor.is_tls_client_hello(bad) is False

    def test_extract_sni(self):
        payload = build_tls_client_hello_with_sni("www.youtube.com")
        assert SNIExtractor.extract(payload) == "www.youtube.com"

    def test_extract_sni_empty_payload(self):
        assert SNIExtractor.extract(b"") is None

    def test_extract_sni_no_sni_extension(self):
        import struct
        # Build Client Hello without SNI extension (only empty extensions)
        client_hello_body = (
            struct.pack(">H", 0x0303)
            + b"\x00" * 32
            + b"\x00"
            + struct.pack(">H", 4)
            + struct.pack(">HH", 0x1301, 0x1302)
            + b"\x01\x00"
            + struct.pack(">H", 0)  # no extensions
        )
        handshake = struct.pack("B", 0x01) + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body
        record = struct.pack("B", 0x16) + struct.pack(">HH", 0x0301, len(handshake)) + handshake
        assert SNIExtractor.extract(record) is None


class TestHTTPHostExtractor:
    def test_is_http_request_get(self):
        assert HTTPHostExtractor.is_http_request(b"GET / HTTP/1.1\r\n") is True
        assert HTTPHostExtractor.is_http_request(b"POST /api HTTP/1.1\r\n") is True

    def test_is_http_request_invalid(self):
        assert HTTPHostExtractor.is_http_request(b"") is False
        assert HTTPHostExtractor.is_http_request(b"xxx ") is False

    def test_extract_host(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n"
        assert HTTPHostExtractor.extract(req) == "example.com"

    def test_extract_host_with_port_stripped(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        assert HTTPHostExtractor.extract(req) == "example.com"

    def test_extract_host_not_request_returns_none(self):
        assert HTTPHostExtractor.extract(b"HTTP/1.1 200 OK\r\n") is None
