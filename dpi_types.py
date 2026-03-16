"""Core data structures for packet analysis and flow tracking."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Five-Tuple: Uniquely identifies a connection/flow
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FiveTuple:
    """Uniquely identifies a connection: src_ip, dst_ip, src_port, dst_port, protocol."""
    src_ip: int      # uint32
    dst_ip: int
    src_port: int    # uint16
    dst_port: int
    protocol: int    # 6=TCP, 17=UDP

    def reverse(self) -> "FiveTuple":
        """Create reverse tuple (for bidirectional flow matching)."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __str__(self) -> str:
        return (
            f"{int_to_ip(self.src_ip)}:{self.src_port} -> "
            f"{int_to_ip(self.dst_ip)}:{self.dst_port} "
            f"({'TCP' if self.protocol == 6 else 'UDP' if self.protocol == 17 else '?'})"
        )


# ---------------------------------------------------------------------------
# Application classification (matches C++ AppType)
# ---------------------------------------------------------------------------

class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


# ---------------------------------------------------------------------------
# Flow state (tracked per 5-tuple)
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    """Per-connection state for DPI."""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes_count: int = 0
    blocked: bool = False


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def ip_to_int(ip: str) -> int:
    """Parse dotted-decimal IP to uint32 (host byte order for hashing)."""
    result = 0
    octet = 0
    shift = 0
    for c in ip:
        if c == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif "0" <= c <= "9":
            octet = octet * 10 + (ord(c) - ord("0"))
    return result | (octet << shift)


def int_to_ip(addr: int) -> str:
    """Convert uint32 to dotted-decimal (handles network byte order from wire)."""
    return (
        f"{(addr >> 0) & 0xFF}."
        f"{(addr >> 8) & 0xFF}."
        f"{(addr >> 16) & 0xFF}."
        f"{(addr >> 24) & 0xFF}"
    )


def app_type_to_string(app: AppType) -> str:
    """Human-readable label for AppType."""
    _names = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return _names.get(app, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    """Map SNI/domain string to AppType (same patterns as C++ types.cpp)."""
    if not sni:
        return AppType.UNKNOWN
    lower = sni.lower()

    if "google" in lower or "gstatic" in lower or "googleapis" in lower or "ggpht" in lower or "gvt1" in lower:
        return AppType.GOOGLE
    if "youtube" in lower or "ytimg" in lower or "youtu.be" in lower or "yt3.ggpht" in lower:
        return AppType.YOUTUBE
    if "facebook" in lower or "fbcdn" in lower or "fb.com" in lower or "fbsbx" in lower or "meta.com" in lower:
        return AppType.FACEBOOK
    if "instagram" in lower or "cdninstagram" in lower:
        return AppType.INSTAGRAM
    if "whatsapp" in lower or "wa.me" in lower:
        return AppType.WHATSAPP
    if "twitter" in lower or "twimg" in lower or "x.com" in lower or "t.co" in lower:
        return AppType.TWITTER
    if "netflix" in lower or "nflxvideo" in lower or "nflximg" in lower:
        return AppType.NETFLIX
    if "amazon" in lower or "amazonaws" in lower or "cloudfront" in lower or "aws" in lower:
        return AppType.AMAZON
    if "microsoft" in lower or "msn.com" in lower or "office" in lower or "azure" in lower or "live.com" in lower or "outlook" in lower or "bing" in lower:
        return AppType.MICROSOFT
    if "apple" in lower or "icloud" in lower or "mzstatic" in lower or "itunes" in lower:
        return AppType.APPLE
    if "telegram" in lower or "t.me" in lower:
        return AppType.TELEGRAM
    if "tiktok" in lower or "tiktokcdn" in lower or "musical.ly" in lower or "bytedance" in lower:
        return AppType.TIKTOK
    if "spotify" in lower or "scdn.co" in lower:
        return AppType.SPOTIFY
    if "zoom" in lower:
        return AppType.ZOOM
    if "discord" in lower or "discordapp" in lower:
        return AppType.DISCORD
    if "github" in lower or "githubusercontent" in lower:
        return AppType.GITHUB
    if "cloudflare" in lower or "cf-" in lower:
        return AppType.CLOUDFLARE

    return AppType.HTTPS  # SNI present but unknown app
