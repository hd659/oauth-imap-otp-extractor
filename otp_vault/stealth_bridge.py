"""Stealth bridge: deterministic per-slot SOCKS5 port allocator and
timezone/locale isolated Chromium launch-flag builder.

Each "slot" is an integer index mapped to a stable local SOCKS5 port, a
dedicated user-data-dir, and a fixed timezone/locale pair, so N profiles can
be launched side by side without sharing cookies, caches, or fingerprints
derived from host locale. Nothing here opens sockets or spawns processes;
``build_launch`` returns a pure argv/env plan that callers execute.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__all__ = [
    "PortAllocator",
    "RegionProfile",
    "LaunchPlan",
    "REGIONS",
    "region_for_slot",
    "build_proxy_url",
    "build_launch",
]


@dataclass(frozen=True)
class RegionProfile:
    timezone: str
    locale: str
    accept_language: str


REGIONS: Tuple[RegionProfile, ...] = (
    RegionProfile("America/New_York", "en-US", "en-US,en;q=0.9"),
    RegionProfile("America/Chicago", "en-US", "en-US,en;q=0.9"),
    RegionProfile("America/Denver", "en-US", "en-US,en;q=0.9"),
    RegionProfile("America/Los_Angeles", "en-US", "en-US,en;q=0.9"),
)


def region_for_slot(slot: int, seed: str = "") -> RegionProfile:
    """Stable region pick: same (slot, seed) always yields the same region."""
    if slot < 0:
        raise ValueError("slot must be >= 0")
    digest = hashlib.sha256(f"{seed}:{slot}".encode()).digest()
    return REGIONS[int.from_bytes(digest[:4], "big") % len(REGIONS)]


@dataclass
class PortAllocator:
    """Maps slot -> base_port + slot, rejecting reserved/out-of-range ports."""

    base_port: int = 21080
    max_slots: int = 64
    reserved: frozenset = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not (1024 <= self.base_port <= 65535):
            raise ValueError("base_port must be in 1024..65535")
        if self.max_slots < 1 or self.base_port + self.max_slots - 1 > 65535:
            raise ValueError("port range exceeds 65535")

    def port_for(self, slot: int) -> int:
        if not (0 <= slot < self.max_slots):
            raise ValueError(f"slot {slot} out of range 0..{self.max_slots - 1}")
        port = self.base_port + slot
        if port in self.reserved:
            raise ValueError(f"port {port} is reserved")
        return port

    def allocate(self, slots: List[int]) -> Dict[int, int]:
        if len(set(slots)) != len(slots):
            raise ValueError("duplicate slots")
        return {s: self.port_for(s) for s in slots}


def build_proxy_url(host: str, port: int) -> str:
    """socks5:// URL for Chromium. Credentials are not supported by Chromium's
    --proxy-server, so auth must be terminated by a local relay on ``port``."""
    if not (1 <= port <= 65535):
        raise ValueError("invalid port")
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{host}]" if ip.version == 6 else host
    except ValueError:
        if not host or any(c in host for c in "/@: "):
            raise ValueError(f"invalid host: {host!r}")
    return f"socks5://{host}:{port}"


@dataclass(frozen=True)
class LaunchPlan:
    slot: int
    port: int
    profile_dir: Path
    region: RegionProfile
    argv: List[str]
    env: Dict[str, str]


def build_launch(
    slot: int,
    profiles_root: Path,
    allocator: Optional[PortAllocator] = None,
    chromium: str = "chromium",
    seed: str = "",
    proxy_host: str = "127.0.0.1",
    extra_flags: Optional[List[str]] = None,
) -> LaunchPlan:
    """Return an isolated Chromium launch plan for ``slot``.

    Isolation guarantees: dedicated user-data-dir, all traffic (incl. DNS)
    via SOCKS5, WebRTC restricted to proxied UDP-less paths, TZ and LANG
    pinned through env so Intl/Date APIs report the region profile.
    """
    alloc = allocator or PortAllocator()
    port = alloc.port_for(slot)
    region = region_for_slot(slot, seed)
    profile_dir = Path(profiles_root) / f"slot-{slot:03d}"
    argv = [
        chromium,
        f"--user-data-dir={profile_dir}",
        f"--proxy-server={build_proxy_url(proxy_host, port)}",
        f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {proxy_host}",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        f"--lang={region.locale}",
        f"--accept-lang={region.accept_language}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
    ]
    if extra_flags:
        clash = [f for f in extra_flags if f.split("=", 1)[0] in
                 ("--user-data-dir", "--proxy-server", "--host-resolver-rules")]
        if clash:
            raise ValueError(f"extra_flags may not override isolation: {clash}")
        argv.extend(extra_flags)
    env = {
        "TZ": region.timezone,
        "LANG": region.locale.replace("-", "_") + ".UTF-8",
        "LC_ALL": region.locale.replace("-", "_") + ".UTF-8",
        "LANGUAGE": region.locale.replace("-", "_"),
    }
    return LaunchPlan(slot, port, profile_dir, region, argv, env)
