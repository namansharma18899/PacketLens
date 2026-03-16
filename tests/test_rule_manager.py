"""Tests for rule_manager: block IP/app/domain and is_blocked."""

import pytest

from dpi_types import AppType
from rule_manager import RuleManager


class TestRuleManager:
    def test_block_ip_and_is_blocked(self, capsys):
        rules = RuleManager()
        rules.block_ip("192.168.1.50")
        assert rules.is_blocked(0xC0A80132, AppType.HTTPS, "example.com") is True  # 192.168.1.50
        assert rules.is_blocked(0xC0A80133, AppType.HTTPS, "example.com") is False
        capsys.readouterr()

    def test_block_app_and_is_blocked(self, capsys):
        rules = RuleManager()
        rules.block_app("YouTube")
        assert rules.is_blocked(0x0A000001, AppType.YOUTUBE, "www.youtube.com") is True
        assert rules.is_blocked(0x0A000001, AppType.FACEBOOK, "www.facebook.com") is False
        capsys.readouterr()

    def test_block_domain_substring(self, capsys):
        rules = RuleManager()
        rules.block_domain("facebook")
        assert rules.is_blocked(0x0A000001, AppType.FACEBOOK, "www.facebook.com") is True
        assert rules.is_blocked(0x0A000001, AppType.HTTPS, "www.facebook.com") is True
        assert rules.is_blocked(0x0A000001, AppType.HTTPS, "example.com") is False
        capsys.readouterr()

    def test_no_rules_nothing_blocked(self):
        rules = RuleManager()
        assert rules.is_blocked(0x0A000001, AppType.YOUTUBE, "www.youtube.com") is False

    def test_block_app_unknown_returns_false(self, capsys):
        rules = RuleManager()
        assert rules.block_app("NonExistentApp") is False
        capsys.readouterr()
