"""SECRET detection: prefixed API keys, JWT-shaped tokens, URL credentials.

Two signals, neither needing surrounding context: vendor prefixes are designed
to be unmistakable, and a password inside a connection URL is marked by its
position. The hard negatives matter as much as the hits -- a placeholder in
the password slot is a reference to a secret, not a secret.
"""

from __future__ import annotations

import pytest

from piiguard.detectors import RegexDetector
from piiguard.detectors.regex_detectors import secret_valid
from piiguard.detectors.structured import StructuredDetector


def secrets(text: str) -> list:
    return [s for s in RegexDetector().detect(text) if s.label == "SECRET"]


# -- prefixed tokens ----------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "sk_live_4f9c2a7b1e",
        "sk_test_9x8y7z6w5v",
        "rk_live_0aa11bb22cc3",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "github_pat_11ABCDEFG0_abcdefghijklmnop",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP",
    ],
)
def test_prefixed_tokens_detected(token):
    found = secrets(f"config value is {token} today")
    assert [s.text for s in found] == [token]


def test_truncated_jwt_still_detected():
    # Logs print session tokens cut to two segments; the eyJ prefix (base64
    # for '{"') plus one dot-segment is already a credential fragment.
    found = secrets("session: token=eyJhbGciOiJIUzI1NiJ9.abc123 ttl=3600")
    assert [s.text for s in found] == ["eyJhbGciOiJIUzI1NiJ9.abc123"]


# -- URL credentials ----------------------------------------------------


def test_url_credential_span_is_password_only():
    text = "DATABASE_URL=postgres://svc_app:hunter2@10.0.4.17:5432/appdb"
    found = secrets(text)
    assert len(found) == 1
    span = found[0]
    assert span.text == "hunter2"
    # The span must not swallow the username or the host.
    assert text[span.start : span.end] == "hunter2"


def test_url_without_password_is_not_a_secret():
    # A Sentry-style DSN has a user slot but no password slot.
    assert secrets("SENTRY_DSN=https://abc123@o4507.ingest.errortrack.example/1") == []


def test_mailto_is_not_a_url_credential():
    assert secrets("write to mailto:ops@corp.example please") == []


# -- placeholders are not secrets ---------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "postgres://svc:${DB_PASSWORD}@db.internal/app",  # interpolation
        "mysql://root:password@db.internal/app",          # the literal word
        "mysql://root:********@db.internal/app",          # already masked
        "redis://svc:xxx@cache.internal",                 # too short
    ],
)
def test_placeholder_credentials_rejected(url):
    assert secrets(url) == []


def test_secret_valid_accepts_real_values():
    assert secret_valid("hunter2")
    assert secret_valid("sk_live_4f9c2a7b1e")


def test_transaction_reference_is_not_a_secret():
    # bank-notice-01's hard negative: "token" in prose near a number.
    assert secrets("Reference 4111 1111 1111 1112 is a rejected transaction token") == []


# -- structure: key/header names the secret -----------------------------


def test_json_api_key_value_redacted_whole():
    # Arbitrary-format secret: no prefix for the regex branch to see. The key
    # is the signal, exactly as a `name` column marks a person.
    text = '{\n  "service": "billing",\n  "api_key": "q7f9-mmx2-51ab-0042"\n}'
    spans = [s for s in StructuredDetector().detect(text) if s.label == "SECRET"]
    assert [s.text for s in spans] == ["q7f9-mmx2-51ab-0042"]


def test_csv_password_column_redacted_whole_cell():
    text = (
        "user,password,role\n"
        "svc_app,q7f9mmx251,writer\n"
        "svc_ro,zz81kk04pp,reader\n"
    )
    spans = [s for s in StructuredDetector().detect(text) if s.label == "SECRET"]
    assert sorted(s.text for s in spans) == ["q7f9mmx251", "zz81kk04pp"]
