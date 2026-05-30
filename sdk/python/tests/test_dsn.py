"""Tests for DSN parsing and DSN-aware clampd.init()."""

from __future__ import annotations

import pytest

import clampd
from clampd.dsn import DEFAULT_GATEWAY_URL, Dsn, parse_dsn


# ── Parser ──────────────────────────────────────────────────────────────
# (dsn, expected gateway_url, expected api_key). Mirror these vectors in the
# TypeScript SDK to keep cross-language parsing identical.
PARSE_VECTORS = [
    ("clampd://ag_live_abc123@gateway.clampd.dev",
     "https://gateway.clampd.dev", "ag_live_abc123"),
    ("clampd://ag_live_abc123@",
     DEFAULT_GATEWAY_URL, "ag_live_abc123"),
    ("clampd://ag_test_x@gateway.clampd.dev:8443",
     "https://gateway.clampd.dev:8443", "ag_test_x"),
    ("clampd+http://ag_test_x@localhost:8080",
     "http://localhost:8080", "ag_test_x"),
    ("https://ag_live_z@gw.example.com",
     "https://gw.example.com", "ag_live_z"),
]


@pytest.mark.parametrize("dsn,gateway_url,api_key", PARSE_VECTORS)
def test_parse_dsn_vectors(dsn, gateway_url, api_key):
    assert parse_dsn(dsn) == Dsn(gateway_url=gateway_url, api_key=api_key)


@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "clampd://gateway.clampd.dev",          # no org key
    "ftp://ag_live_x@gateway.clampd.dev",   # bad scheme
    "ag_live_x@gateway.clampd.dev",         # no scheme
])
def test_parse_dsn_rejects_invalid(bad):
    with pytest.raises(ValueError):
        parse_dsn(bad)


# ── init() integration ──────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "CLAMPD_DSN", "CLAMPD_GATEWAY_URL", "CLAMPD_API_KEY",
        "CLAMPD_AGENT_ID", "CLAMPD_AGENT_NAME", "CLAMPD_AGENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CLAMPD_AGENT_NAME", "test-agent")
    # init() enrolls; stub it out so unit tests don't hit the network.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import clampd.enroll as _enroll

    captured = {}

    def fake_enroll(host, org_key, name):
        captured["host"] = host
        captured["org_key"] = org_key
        captured["name"] = name
        return _enroll.Identity(
            private_key=Ed25519PrivateKey.generate(),
            agent_id="11111111-1111-1111-1111-111111111111",
        )

    monkeypatch.setattr(_enroll, "enroll", fake_enroll)
    clampd._captured_enroll = captured  # type: ignore[attr-defined]
    clampd._reset()
    yield
    clampd._reset()


def _config():
    return clampd._shared_config


def test_init_from_dsn_env(monkeypatch):
    monkeypatch.setenv("CLAMPD_DSN", "clampd://ag_live_fromenv@gateway.clampd.dev")
    clampd.init()
    assert _config()["gateway_url"] == "https://gateway.clampd.dev"
    assert _config()["api_key"] == "ag_live_fromenv"
    assert clampd._captured_enroll["org_key"] == "ag_live_fromenv"


def test_init_dsn_argument(monkeypatch):
    clampd.init("clampd+http://ag_test_arg@localhost:8080")
    assert _config()["gateway_url"] == "http://localhost:8080"
    assert _config()["api_key"] == "ag_test_arg"


def test_init_uses_name_for_enrollment(monkeypatch):
    clampd.init("clampd://ag_live_x@gateway.clampd.dev", name="billing")
    assert clampd._captured_enroll["name"] == "billing"
    assert clampd._default_client.agent_id == "11111111-1111-1111-1111-111111111111"


def test_missing_dsn_raises(monkeypatch):
    monkeypatch.delenv("CLAMPD_DSN", raising=False)
    with pytest.raises(ValueError):
        clampd.init()
