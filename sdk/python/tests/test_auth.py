"""Tests for clampd.auth - JWT generation."""

import base64
import hashlib
import hmac
import json
import os
from unittest.mock import patch

import pytest

from clampd.auth import make_agent_jwt


class TestUnsignedJWT:
    """Since C3 fix, unsigned JWTs are rejected - must raise ValueError."""

    def test_unsigned_jwt_raises_without_secret(self):
        saved = os.environ.pop("JWT_SECRET", None)
        try:
            with pytest.raises(ValueError, match="No signing secret available"):
                make_agent_jwt("agent-1")
        finally:
            if saved is not None:
                os.environ["JWT_SECRET"] = saved

    def test_unsigned_jwt_raises_without_env_var(self):
        saved = os.environ.pop("JWT_SECRET", None)
        try:
            with pytest.raises(ValueError):
                make_agent_jwt("agent-1")
        finally:
            if saved is not None:
                os.environ["JWT_SECRET"] = saved


class TestSignedJWT:
    def test_signed_jwt_has_three_parts(self):
        token = make_agent_jwt("agent-1", secret="test-secret")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != "nosig"

    def test_signed_jwt_header_is_hs256(self):
        token = make_agent_jwt("agent-1", secret="test-secret")
        header_b64 = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header["alg"] == "HS256"

    def test_signed_jwt_signature_validates(self):
        secret = "my-signing-key"
        token = make_agent_jwt("agent-1", secret=secret)
        header_b64, payload_b64, sig_b64 = token.split(".")

        expected_sig = base64.urlsafe_b64encode(
            hmac.new(
                secret.encode(),
                f"{header_b64}.{payload_b64}".encode(),
                hashlib.sha256,
            ).digest()
        ).rstrip(b"=").decode()

        assert sig_b64 == expected_sig

    def test_scopes_in_payload(self):
        token = make_agent_jwt("agent-1", secret="s", scopes=["db:read", "db:write"])
        payload_b64 = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert payload["scopes"] == ["db:read", "db:write"]

    def test_custom_ttl(self):
        token = make_agent_jwt("agent-1", secret="s", ttl_seconds=60)
        payload_b64 = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert payload["exp"] - payload["iat"] == 60

    def test_env_var_secret(self):
        with patch.dict(os.environ, {"JWT_SECRET": "env-secret"}):
            token = make_agent_jwt("agent-1")
            parts = token.split(".")
            assert parts[2] != "nosig"  # Signed, not unsigned

    def test_explicit_secret_overrides_env(self):
        with patch.dict(os.environ, {"JWT_SECRET": "env-secret"}):
            token1 = make_agent_jwt("agent-1", secret="explicit")
            token2 = make_agent_jwt("agent-1", secret="different")
            # Different secrets → different signatures
            assert token1.split(".")[2] != token2.split(".")[2]
