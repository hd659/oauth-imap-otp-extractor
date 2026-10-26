"""XOAUTH2 IMAP OTP / Magic-Link extractor.

Zero-GUI helper to refresh Microsoft OAuth2 access tokens, build the SASL
XOAUTH2 auth string, and deterministically parse 6-digit OTP codes and
magic-links out of MIME email messages.

No private credentials, domains, or API keys are embedded here; all secrets
are injected at runtime via the ``OAuthConfig`` dataclass.
"""
from __future__ import annotations

import base64
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from typing import Callable, Optional

__all__ = [
    "OAuthConfig",
    "TokenBundle",
    "build_xoauth2_string",
    "refresh_access_token",
    "extract_otp",
    "extract_magic_link",
    "parse_message",
]

# 6-digit OTP must be a standalone run of exactly six digits.
_OTP_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_MAGIC_HINTS = ("verify", "magic", "login", "signin", "sign-in", "confirm", "token", "auth")


@dataclass(frozen=True)
class OAuthConfig:
    """Static OAuth2 client configuration (no secrets hard-coded)."""

    client_id: str
    refresh_token: str
    token_endpoint: str
    client_secret: str = ""
    scope: str = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ValueError("client_id is required")
        if not self.refresh_token:
            raise ValueError("refresh_token is required")
        if not self.token_endpoint.lower().startswith("https://"):
            raise ValueError("token_endpoint must be an https URL")


@dataclass
class TokenBundle:
    """A live access token with an absolute expiry timestamp."""

    access_token: str
    expires_at: float
    refresh_token: str = ""

    def is_expired(self, now: Optional[float] = None, skew: float = 60.0) -> bool:
        return (now if now is not None else time.time()) >= (self.expires_at - skew)


def build_xoauth2_string(user: str, access_token: str) -> str:
    """Build the base64 SASL XOAUTH2 initial client response."""
    if not user or not access_token:
        raise ValueError("user and access_token are required")
    raw = f"user={user}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def refresh_access_token(
    config: OAuthConfig,
    *,
    now: Optional[float] = None,
    http_post: Optional[Callable[[str, bytes], bytes]] = None,
) -> TokenBundle:
    """Exchange the refresh token for a fresh access token.

    ``http_post`` is injectable so tests never touch the network.
    """
    import json

    form = {
        "client_id": config.client_id,
        "refresh_token": config.refresh_token,
        "grant_type": "refresh_token",
        "scope": config.scope,
    }
    if config.client_secret:
        form["client_secret"] = config.client_secret
    body = urllib.parse.urlencode(form).encode("utf-8")

    poster = http_post or _default_post
    raw = poster(config.token_endpoint, body)
    payload = json.loads(raw.decode("utf-8"))

    access = payload.get("access_token")
    if not access:
        raise RuntimeError("token endpoint returned no access_token")
    expires_in = float(payload.get("expires_in", 3600))
    base = now if now is not None else time.time()
    return TokenBundle(
        access_token=access,
        expires_at=base + expires_in,
        refresh_token=payload.get("refresh_token", config.refresh_token),
    )


def _default_post(url: str, body: bytes) -> bytes:  # pragma: no cover - network
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _message_text(msg: Message) -> str:
    """Flatten a MIME message into a single decoded text blob."""
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() in ("text/plain", "text/html"):
                parts.append(_decode_part(part))
    else:
        parts.append(_decode_part(msg))
    return "\n".join(p for p in parts if p)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def extract_otp(raw: bytes | str) -> Optional[str]:
    """Return the first deterministic 6-digit OTP, or None."""
    text = raw if isinstance(raw, str) else _message_text(message_from_bytes(raw))
    match = _OTP_RE.search(text)
    return match.group(1) if match else None


def extract_magic_link(raw: bytes | str) -> Optional[str]:
    """Return the most likely magic-link URL, or None.

    Prefers URLs whose path/query carries auth-ish hints; falls back to the
    first URL found so callers always get a deterministic result.
    """
    text = raw if isinstance(raw, str) else _message_text(message_from_bytes(raw))
    urls = _URL_RE.findall(text)
    if not urls:
        return None
    for url in urls:
        low = url.lower()
        if any(hint in low for hint in _MAGIC_HINTS):
            return url
    return urls[0]


def parse_message(raw: bytes | str) -> dict:
    """Parse a raw message into its OTP and magic-link components."""
    text = raw if isinstance(raw, str) else _message_text(message_from_bytes(raw))
    return {"otp": extract_otp(text), "magic_link": extract_magic_link(text)}
