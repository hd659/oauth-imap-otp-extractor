import base64
import json
import os
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from otp_vault.imap_xoauth2 import (  # noqa: E402
    OAuthConfig,
    TokenBundle,
    build_xoauth2_string,
    extract_magic_link,
    extract_otp,
    parse_message,
    refresh_access_token,
)

ENDPOINT = "https://login.example.test/oauth2/v2.0/token"


def _cfg(**kw):
    base = dict(client_id="cid", refresh_token="rt-old", token_endpoint=ENDPOINT)
    base.update(kw)
    return OAuthConfig(**base)


def test_xoauth2_string_format():
    s = build_xoauth2_string("user@example.test", "tok")
    assert base64.b64decode(s) == b"user=user@example.test\x01auth=Bearer tok\x01\x01"


def test_xoauth2_requires_fields():
    with pytest.raises(ValueError):
        build_xoauth2_string("", "tok")


@pytest.mark.parametrize("kw", [{"client_id": ""}, {"refresh_token": ""},
                                {"token_endpoint": "http://insecure.test"}])
def test_config_validation(kw):
    with pytest.raises(ValueError):
        _cfg(**kw)


def test_refresh_access_token_rotates():
    seen = {}

    def fake_post(url, body):
        seen["url"], seen["body"] = url, body.decode()
        return json.dumps({"access_token": "at-new", "expires_in": 1800,
                           "refresh_token": "rt-new"}).encode()

    tb = refresh_access_token(_cfg(client_secret="sec"), now=1000.0, http_post=fake_post)
    assert tb.access_token == "at-new"
    assert tb.expires_at == 2800.0
    assert tb.refresh_token == "rt-new"
    assert seen["url"] == ENDPOINT
    assert "grant_type=refresh_token" in seen["body"]
    assert "client_secret=sec" in seen["body"]


def test_refresh_keeps_old_refresh_token_and_errors():
    tb = refresh_access_token(_cfg(), now=0.0,
                              http_post=lambda u, b: b'{"access_token":"a"}')
    assert tb.refresh_token == "rt-old" and tb.expires_at == 3600.0
    assert "client_secret" not in "".join([])
    with pytest.raises(RuntimeError):
        refresh_access_token(_cfg(), http_post=lambda u, b: b'{"error":"invalid_grant"}')


def test_token_expiry_skew():
    tb = TokenBundle("a", expires_at=1000.0)
    assert not tb.is_expired(now=900.0)
    assert tb.is_expired(now=950.0)


def test_extract_otp_plain_text():
    assert extract_otp("Your verification code is 482913. Expires soon.") == "482913"
    assert extract_otp("Order 12345678 shipped") is None
    assert extract_otp("no code here") is None


def test_extract_otp_from_multipart_mime():
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your code"
    msg.attach(MIMEText("Code: 731042", "plain", "utf-8"))
    msg.attach(MIMEText("<p>Code: <b>731042</b></p>", "html", "utf-8"))
    assert extract_otp(msg.as_bytes()) == "731042"


def test_extract_magic_link_prefers_auth_hint():
    text = ("Visit https://example.test/home or "
            "https://example.test/auth/verify?token=abc123 to sign in.")
    assert extract_magic_link(text) == "https://example.test/auth/verify?token=abc123"


def test_extract_magic_link_fallback_and_none():
    assert extract_magic_link("see https://example.test/docs") == "https://example.test/docs"
    assert extract_magic_link("nothing") is None


def test_extract_magic_link_from_html_mime():
    html = '<a href="https://app.example.test/login/magic?t=xyz">Sign in</a>'
    msg = MIMEText(html, "html", "utf-8")
    assert extract_magic_link(msg.as_bytes()) == "https://app.example.test/login/magic?t=xyz"


def test_parse_message_combined():
    msg = MIMEText("Code 905531 or https://example.test/confirm?k=1", "plain", "utf-8")
    assert parse_message(msg.as_bytes()) == {
        "otp": "905531", "magic_link": "https://example.test/confirm?k=1"}
