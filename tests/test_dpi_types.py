"""Tests for dpi_types: FiveTuple, AppType, IP helpers, sni_to_app_type."""

import pytest

from dpi_types import (
    FiveTuple,
    Flow,
    AppType,
    ip_to_int,
    int_to_ip,
    app_type_to_string,
    sni_to_app_type,
)


class TestIPHelpers:
    def test_ip_to_int_basic(self):
        assert ip_to_int("0.0.0.0") == 0
        assert ip_to_int("255.255.255.255") == 0xFFFFFFFF
        assert ip_to_int("192.168.1.1") == 0xC0A80101

    def test_int_to_ip_basic(self):
        assert int_to_ip(0) == "0.0.0.0"
        assert int_to_ip(0xFFFFFFFF) == "255.255.255.255"
        assert int_to_ip(0xC0A80101) == "192.168.1.1"

    def test_ip_roundtrip(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.100.50"):
            assert int_to_ip(ip_to_int(ip)) == ip


class TestFiveTuple:
    def test_five_tuple_equality_and_hash(self):
        t1 = FiveTuple(0x0A000001, 0x0A000002, 12345, 443, 6)
        t2 = FiveTuple(0x0A000001, 0x0A000002, 12345, 443, 6)
        assert t1 == t2
        assert hash(t1) == hash(t2)
        assert t1 in {t2}

    def test_five_tuple_reverse(self):
        t = FiveTuple(0x0A000001, 0x0A000002, 12345, 443, 6)
        r = t.reverse()
        assert r.src_ip == t.dst_ip
        assert r.dst_ip == t.src_ip
        assert r.src_port == t.dst_port
        assert r.dst_port == t.src_port
        assert r.protocol == t.protocol

    def test_five_tuple_str(self):
        t = FiveTuple(ip_to_int("192.168.1.1"), ip_to_int("8.8.8.8"), 54321, 443, 6)
        s = str(t)
        assert "192.168.1.1" in s
        assert "8.8.8.8" in s
        assert "443" in s
        assert "TCP" in s


class TestAppType:
    def test_app_type_to_string_known(self):
        assert app_type_to_string(AppType.UNKNOWN) == "Unknown"
        assert app_type_to_string(AppType.HTTP) == "HTTP"
        assert app_type_to_string(AppType.YOUTUBE) == "YouTube"
        assert app_type_to_string(AppType.FACEBOOK) == "Facebook"

    def test_sni_to_app_type_youtube(self):
        assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE
        assert sni_to_app_type("youtu.be") == AppType.YOUTUBE
        assert sni_to_app_type("ytimg.com") == AppType.YOUTUBE

    def test_sni_to_app_type_facebook(self):
        assert sni_to_app_type("www.facebook.com") == AppType.FACEBOOK
        assert sni_to_app_type("fbcdn.net") == AppType.FACEBOOK

    def test_sni_to_app_type_google(self):
        assert sni_to_app_type("www.google.com") == AppType.GOOGLE
        assert sni_to_app_type("googleapis.com") == AppType.GOOGLE

    def test_sni_to_app_type_unknown_falls_back_to_https(self):
        assert sni_to_app_type("random.example.com") == AppType.HTTPS

    def test_sni_to_app_type_empty(self):
        assert sni_to_app_type("") == AppType.UNKNOWN

    def test_sni_to_app_type_case_insensitive(self):
        assert sni_to_app_type("WWW.YOUTUBE.COM") == AppType.YOUTUBE
        assert sni_to_app_type("www.YouTube.com") == AppType.YOUTUBE


class TestFlow:
    def test_flow_defaults(self):
        t = FiveTuple(1, 2, 3, 4, 6)
        f = Flow(tuple=t)
        assert f.tuple == t
        assert f.app_type == AppType.UNKNOWN
        assert f.sni == ""
        assert f.packets == 0
        assert f.bytes_count == 0
        assert f.blocked is False
