"""Tests for the Ed25519 identity + enrollment layer (Phase 2 slice 1)."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import clampd.enroll as enroll
from clampd.auth import make_agent_jwt_ed25519
from clampd._errors import ClampdEnrollError


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setattr(enroll, "_HOME", tmp_path)
    for var in ("CLAMPD_ENROLL_TOKEN", "CLAMPD_REBIND_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    yield


def test_keypair_persists_and_reloads():
    a = enroll.load_or_create("ag_live_x", "billing")
    b = enroll.load_or_create("ag_live_x", "billing")
    # Same private key bytes on reload (identity is stable across runs).
    raw_a = a.private_key.private_bytes_raw()
    raw_b = b.private_key.private_bytes_raw()
    assert raw_a == raw_b
    assert a.agent_id is None


def test_public_key_b64_is_32_bytes():
    ident = enroll.load_or_create("ag_live_x", "svc")
    raw = base64.urlsafe_b64decode(enroll.public_key_b64(ident.private_key) + "==")
    assert len(raw) == 32


def test_enroll_caches_agent_id(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 201
        text = ""

        def json(self):
            return {"agent_id": "11111111-1111-1111-1111-111111111111"}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["body"] = kwargs["json"]
        return FakeResp()

    monkeypatch.setattr(enroll.httpx, "post", fake_post)

    ident = enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")
    assert ident.agent_id == "11111111-1111-1111-1111-111111111111"
    assert captured["url"].endswith("/v1/enroll")
    assert captured["body"]["name"] == "svc"
    assert captured["body"]["attestation_type"] == "none"

    # Second call must NOT re-enroll: the agent_id is cached on disk.
    def boom(*a, **k):
        raise AssertionError("should not re-enroll once agent_id is cached")

    monkeypatch.setattr(enroll.httpx, "post", boom)
    again = enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")
    assert again.agent_id == "11111111-1111-1111-1111-111111111111"


def test_rebind_token_forces_rekey_with_fresh_key(monkeypatch):
    # 1. Enroll normally and cache an identity (agent_id + key on disk).
    class Resp201:
        status_code = 201
        text = ""

        def json(self):
            return {"agent_id": "33333333-3333-3333-3333-333333333333"}

    monkeypatch.setattr(enroll.httpx, "post", lambda url, **k: Resp201())
    first = enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")
    first_key = first.private_key.private_bytes_raw()
    assert first.agent_id == "33333333-3333-3333-3333-333333333333"

    # 2. With a rebind token set, re-key: must POST rekey_token attestation,
    #    generate a NEW key, and keep the SAME agent_id returned by the gateway.
    monkeypatch.setenv("CLAMPD_REBIND_TOKEN", "crt-abc")
    seen = {}

    class Resp200:
        status_code = 200
        text = ""

        def json(self):
            return {"agent_id": "33333333-3333-3333-3333-333333333333"}

    monkeypatch.setattr(
        enroll.httpx, "post", lambda url, **k: (seen.update(k["json"]), Resp200())[1]
    )
    rekeyed = enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")

    assert seen["attestation_type"] == "rekey_token"
    assert seen["attestation"] == "crt-abc"
    # Fresh keypair was generated (different from the original).
    assert rekeyed.private_key.private_bytes_raw() != first_key
    # Same agent identity preserved.
    assert rekeyed.agent_id == "33333333-3333-3333-3333-333333333333"
    # New key persisted to disk for subsequent runs.
    reloaded = enroll.load_or_create("ag_live_x", "svc")
    assert reloaded.private_key.private_bytes_raw() == rekeyed.private_key.private_bytes_raw()


def test_enroll_uses_enroll_token_attestation(monkeypatch):
    monkeypatch.setenv("CLAMPD_ENROLL_TOKEN", "tok-123")
    seen = {}

    class FakeResp:
        status_code = 200
        text = ""

        def json(self):
            return {"agent_id": "22222222-2222-2222-2222-222222222222"}

    monkeypatch.setattr(enroll.httpx, "post", lambda url, **k: (seen.update(k["json"]), FakeResp())[1])
    enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")
    assert seen["attestation_type"] == "enroll_token"
    assert seen["attestation"] == "tok-123"


def test_enroll_raises_on_rejection(monkeypatch):
    class FakeResp:
        status_code = 403
        text = "attestation_failed"

        def json(self):
            return {}

    monkeypatch.setattr(enroll.httpx, "post", lambda url, **k: FakeResp())
    with pytest.raises(ClampdEnrollError):
        enroll.enroll("https://gw.clampd.dev", "ag_live_x", "svc")


def test_ed25519_jwt_verifies_with_public_key():
    ident = enroll.load_or_create("ag_live_x", "svc")
    token = make_agent_jwt_ed25519("agent-uuid", ident.private_key)
    header_b64, payload_b64, sig_b64 = token.split(".")

    def _b64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    # Signature verifies over header.payload with the matching public key.
    ident.private_key.public_key().verify(
        _b64(sig_b64), f"{header_b64}.{payload_b64}".encode()
    )
    assert json.loads(_b64(header_b64))["alg"] == "EdDSA"
    assert json.loads(_b64(payload_b64))["sub"] == "agent-uuid"

    # A different key must NOT verify the signature.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(Exception):
        other.verify(_b64(sig_b64), f"{header_b64}.{payload_b64}".encode())
