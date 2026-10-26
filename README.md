# oauth-imap-otp-extractor

Zero-GUI XOAUTH2 IMAP OTP/Magic-Link extractor and isolated SOCKS5 browser profile launcher.

## Modules

- `otp_vault/imap_xoauth2.py`: OAuth2 refresh-token -> access-token exchange, SASL XOAUTH2 string builder, and deterministic 6-digit OTP / magic-link MIME parser.
- `otp_vault/stealth_bridge.py`: deterministic per-slot SOCKS5 port allocator and timezone/locale isolated Chromium launch-plan builder (pure, no sockets or subprocesses).

## Stealth bridge usage

```python
from pathlib import Path
from otp_vault.stealth_bridge import PortAllocator, build_launch

plan = build_launch(slot=2, profiles_root=Path("./profiles"),
                    allocator=PortAllocator(base_port=21080), seed="demo")
# plan.argv -> chromium argv, plan.env -> TZ/LANG overrides
# subprocess.Popen(plan.argv, env={**os.environ, **plan.env})
```

Per-slot guarantees:

- Port: `base_port + slot`, range-checked, reserved ports rejected.
- Profile: dedicated `slot-NNN` user-data-dir.
- Network: all traffic via `socks5://`, DNS forced through proxy (`--host-resolver-rules`), WebRTC non-proxied UDP disabled.
- Region: timezone/locale picked by `sha256(seed:slot)`, stable across runs; pinned through `TZ`/`LANG` env and `--lang`.
- `extra_flags` cannot override isolation-critical flags.

Chromium's `--proxy-server` does not accept SOCKS5 credentials; run a local relay on the slot port that handles upstream auth.

## Configuration

All secrets (client id, refresh token, token endpoint) are injected at runtime via `OAuthConfig`. No credentials are stored in this repo.

## Tests

```bash
python3 -m pytest -q
```
