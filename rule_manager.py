"""Blocking rules: IP, app type, and domain (substring) matching."""

from typing import Set, List

from dpi_types import AppType, ip_to_int


class RuleManager:
    """Manages block rules and answers is_blocked(src_ip, app_type, sni)."""

    def __init__(self) -> None:
        self._blocked_ips: Set[int] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: List[str] = []

    def block_ip(self, ip: str) -> None:
        addr = ip_to_int(ip)
        self._blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> bool:
        """Block by app name (e.g. 'YouTube'). Returns True if recognized."""
        from dpi_types import AppType, app_type_to_string
        for at in AppType:
            if at == AppType.APP_COUNT:
                continue
            if app_type_to_string(at) == app:
                self._blocked_apps.add(at)
                print(f"[Rules] Blocked app: {app}")
                return True
        print(f"[Rules] Unknown app: {app}")
        return False

    def block_domain(self, domain: str) -> None:
        self._blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app_type: AppType, sni: str) -> bool:
        if src_ip in self._blocked_ips:
            return True
        if app_type in self._blocked_apps:
            return True
        for dom in self._blocked_domains:
            if dom in sni:
                return True
        return False
