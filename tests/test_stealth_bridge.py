from pathlib import Path

import pytest

from otp_vault.stealth_bridge import (
    REGIONS,
    PortAllocator,
    build_launch,
    build_proxy_url,
    region_for_slot,
)


def test_region_deterministic_and_seeded():
    assert region_for_slot(3, "a") == region_for_slot(3, "a")
    assert region_for_slot(3, "a") in REGIONS
    picks = {region_for_slot(i, "s") for i in range(64)}
    assert len(picks) > 1
    with pytest.raises(ValueError):
        region_for_slot(-1)


def test_port_allocator_mapping():
    a = PortAllocator(base_port=30000, max_slots=4)
    assert a.allocate([0, 3]) == {0: 30000, 3: 30003}
    with pytest.raises(ValueError):
        a.port_for(4)
    with pytest.raises(ValueError):
        a.allocate([1, 1])


def test_port_allocator_reserved_and_bounds():
    a = PortAllocator(base_port=30000, max_slots=4, reserved=frozenset({30001}))
    with pytest.raises(ValueError):
        a.port_for(1)
    with pytest.raises(ValueError):
        PortAllocator(base_port=80)
    with pytest.raises(ValueError):
        PortAllocator(base_port=65530, max_slots=10)


def test_proxy_url_variants():
    assert build_proxy_url("127.0.0.1", 1080) == "socks5://127.0.0.1:1080"
    assert build_proxy_url("::1", 1080) == "socks5://[::1]:1080"
    assert build_proxy_url("localhost", 9) == "socks5://localhost:9"
    for bad in ("", "user@host", "a/b"):
        with pytest.raises(ValueError):
            build_proxy_url(bad, 1080)
    with pytest.raises(ValueError):
        build_proxy_url("127.0.0.1", 0)


def test_build_launch_isolation(tmp_path: Path):
    plan = build_launch(2, tmp_path, PortAllocator(base_port=40000), seed="x")
    assert plan.port == 40002
    assert plan.profile_dir == tmp_path / "slot-002"
    assert f"--user-data-dir={plan.profile_dir}" in plan.argv
    assert "--proxy-server=socks5://127.0.0.1:40002" in plan.argv
    assert any(f.startswith("--host-resolver-rules=MAP * ~NOTFOUND") for f in plan.argv)
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in plan.argv
    assert plan.env["TZ"] == plan.region.timezone
    assert plan.env["LANG"] == "en_US.UTF-8"
    assert f"--lang={plan.region.locale}" in plan.argv


def test_build_launch_distinct_slots(tmp_path: Path):
    a = build_launch(0, tmp_path)
    b = build_launch(1, tmp_path)
    assert a.port != b.port and a.profile_dir != b.profile_dir


def test_extra_flags_cannot_override(tmp_path: Path):
    plan = build_launch(0, tmp_path, extra_flags=["--headless=new"])
    assert plan.argv[-1] == "--headless=new"
    with pytest.raises(ValueError):
        build_launch(0, tmp_path, extra_flags=["--proxy-server=direct://"])
