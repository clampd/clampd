"""Tests for clampd.tool_verify — Ed25519 scope token verification."""

import base64
import hashlib
import json
import time

import pytest

from clampd.tool_verify import (
    ScopeTokenClaims,
    ScopeVerificationError,
    get_current_scope_token,
    require_scope,
    verify_scope_token,
)

# ── Ed25519 test keypair (deterministic from seed) ────────────────────

def _make_ed25519_keypair():
    """Generate an Ed25519 keypair for testing using the cryptography library."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _get_public_key_bytes(public_key) -> bytes:
    """Extract raw 32-byte public key from a cryptography Ed25519PublicKey."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw


def _sign_ed25519(private_key, message: bytes) -> bytes:
    """Sign a message with Ed25519."""
    return private_key.sign(message)


# Generate test keypair once
_test_private_key, _test_public_key = _make_ed25519_keypair()
TEST_PUBLIC_KEY_BYTES = _get_public_key_bytes(_test_public_key)


def _make_scope_token(
    payload: dict,
    private_key=None,
) -> str:
    """Build an Ed25519-signed scope token in the gateway format for testing."""
    if private_key is None:
        private_key = _test_private_key
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    sig = _sign_ed25519(private_key, payload_b64.encode())
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{payload_b64}.{sig_b64}"


def _valid_payload(**overrides) -> dict:
    """Return a valid scope token payload with sensible defaults."""
    now = int(time.time())
    base = {
        "sub": "agent-123",
        "scope": "data:pii:query exec:shell:run",
        "tool": "db.query",
        "binding": hashlib.sha256(b"db.query|{\"sql\":\"SELECT 1\"}").hexdigest(),
        "exp": now + 300,
        "rid": "req-abc-123",
    }
    base.update(overrides)
    return base


class TestScopeTokenClaims:
    def test_has_scope_true(self):
        claims = ScopeTokenClaims(
            sub="a", scope="data:pii:query exec:shell:run",
            tool="t", binding="b", exp=0, rid="r",
        )
        assert claims.has_scope("data:pii:query") is True
        assert claims.has_scope("exec:shell:run") is True

    def test_has_scope_false(self):
        claims = ScopeTokenClaims(
            sub="a", scope="data:pii:query",
            tool="t", binding="b", exp=0, rid="r",
        )
        assert claims.has_scope("exec:shell:run") is False

    def test_scopes_property(self):
        claims = ScopeTokenClaims(
            sub="a", scope="s1 s2 s3",
            tool="t", binding="b", exp=0, rid="r",
        )
        assert claims.scopes == ["s1", "s2", "s3"]

    def test_is_expired_true(self):
        claims = ScopeTokenClaims(
            sub="a", scope="s", tool="t", binding="b",
            exp=int(time.time()) - 100, rid="r",
        )
        assert claims.is_expired is True

    def test_is_expired_false(self):
        claims = ScopeTokenClaims(
            sub="a", scope="s", tool="t", binding="b",
            exp=int(time.time()) + 300, rid="r",
        )
        assert claims.is_expired is False

    def test_empty_scope(self):
        claims = ScopeTokenClaims(
            sub="a", scope="", tool="t", binding="b", exp=0, rid="r",
        )
        assert claims.scopes == []
        assert claims.has_scope("anything") is False


class TestVerifyScopeToken:
    def test_valid_token(self):
        payload = _valid_payload()
        token = _make_scope_token(payload)
        claims = verify_scope_token(token, public_key=TEST_PUBLIC_KEY_BYTES)

        assert claims.sub == "agent-123"
        assert claims.tool == "db.query"
        assert claims.rid == "req-abc-123"
        assert claims.has_scope("data:pii:query")

    def test_valid_token_explicit_key(self):
        payload = _valid_payload()
        token = _make_scope_token(payload)
        claims = verify_scope_token(token, public_key=TEST_PUBLIC_KEY_BYTES)
        assert claims.sub == "agent-123"

    def test_expired_token_rejected(self):
        payload = _valid_payload(exp=int(time.time()) - 60)
        token = _make_scope_token(payload)

        with pytest.raises(ScopeVerificationError, match="Token expired") as exc_info:
            verify_scope_token(token, public_key=TEST_PUBLIC_KEY_BYTES)

        # Expired tokens include claims for debugging
        assert exc_info.value.claims is not None
        assert exc_info.value.claims.sub == "agent-123"

    def test_invalid_signature_rejected(self):
        """Token signed with one key, verified with another."""
        other_private, other_public = _make_ed25519_keypair()
        payload = _valid_payload()
        token = _make_scope_token(payload, private_key=other_private)

        with pytest.raises(ScopeVerificationError, match="Invalid signature"):
            verify_scope_token(token, public_key=TEST_PUBLIC_KEY_BYTES)

    def test_empty_token_rejected(self):
        with pytest.raises(ScopeVerificationError, match="No scope token"):
            verify_scope_token("", public_key=TEST_PUBLIC_KEY_BYTES)

    def test_malformed_token_rejected(self):
        with pytest.raises(ScopeVerificationError, match="Malformed token"):
            verify_scope_token("not-a-valid-token", public_key=TEST_PUBLIC_KEY_BYTES)

    def test_three_part_token_rejected(self):
        with pytest.raises(ScopeVerificationError, match="Malformed token"):
            verify_scope_token("a.b.c", public_key=TEST_PUBLIC_KEY_BYTES)

    def test_missing_sub_claim(self):
        payload = _valid_payload()
        del payload["sub"]
        token = _make_scope_token(payload)

        with pytest.raises(ScopeVerificationError, match="Missing required claim"):
            verify_scope_token(token, public_key=TEST_PUBLIC_KEY_BYTES)


class TestGetCurrentScopeToken:
    def test_returns_empty_when_no_context(self):
        assert get_current_scope_token() == ""

    def test_returns_token_from_contextvar(self):
        from clampd import _scope_token_var
        token = _scope_token_var.set("test-token-value")
        try:
            assert get_current_scope_token() == "test-token-value"
        finally:
            _scope_token_var.reset(token)


class TestRequireScope:
    def test_success_with_matching_scope(self):
        payload = _valid_payload(scope="data:pii:query exec:shell:run")
        token = _make_scope_token(payload)

        claims = require_scope("data:pii:query", token=token, public_key=TEST_PUBLIC_KEY_BYTES)
        assert claims.sub == "agent-123"
        assert claims.has_scope("data:pii:query")

    def test_raises_on_missing_scope(self):
        payload = _valid_payload(scope="data:pii:query")
        token = _make_scope_token(payload)

        with pytest.raises(ScopeVerificationError, match="not granted") as exc_info:
            require_scope("exec:shell:run", token=token, public_key=TEST_PUBLIC_KEY_BYTES)

        # Claims are attached for debugging
        assert exc_info.value.claims is not None
        assert exc_info.value.claims.scope == "data:pii:query"

    def test_raises_on_no_token(self):
        with pytest.raises(ScopeVerificationError, match="No scope token available"):
            require_scope("data:pii:query", public_key=TEST_PUBLIC_KEY_BYTES)

    def test_reads_from_context_when_no_explicit_token(self):
        from clampd import _scope_token_var

        payload = _valid_payload(scope="data:pii:query")
        token_str = _make_scope_token(payload)
        cv_token = _scope_token_var.set(token_str)
        try:
            claims = require_scope("data:pii:query", public_key=TEST_PUBLIC_KEY_BYTES)
            assert claims.sub == "agent-123"
        finally:
            _scope_token_var.reset(cv_token)

    def test_expired_token_raises(self):
        payload = _valid_payload(exp=int(time.time()) - 60)
        token = _make_scope_token(payload)

        with pytest.raises(ScopeVerificationError, match="Token expired"):
            require_scope("data:pii:query", token=token, public_key=TEST_PUBLIC_KEY_BYTES)


class TestScopeVerificationError:
    def test_message_format(self):
        err = ScopeVerificationError("bad token")
        assert str(err) == "Scope verification failed: bad token"
        assert err.reason == "bad token"
        assert err.claims is None

    def test_with_claims(self):
        claims = ScopeTokenClaims(
            sub="a", scope="s", tool="t", binding="b", exp=0, rid="r",
        )
        err = ScopeVerificationError("expired", claims=claims)
        assert err.claims is not None
        assert err.claims.sub == "a"
