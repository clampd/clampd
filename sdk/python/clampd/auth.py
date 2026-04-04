"""JWT helper for Clampd agent authentication."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_agent_jwt(
    agent_id: str,
    *,
    secret: str | None = None,
    scopes: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> str:
    """Create a JWT with ``sub`` = *agent_id*.

    Uses HMAC-SHA256 when *secret* or ``JWT_SECRET`` env var is set.
    Raises ``ValueError`` if no signing secret is available — unsigned JWTs
    (alg: none) are NOT supported.
    """
    raw_secret = secret or os.environ.get("JWT_SECRET", "")
    now = int(time.time())

    payload_dict: dict[str, Any] = {
        "sub": agent_id,
        "iss": "clampd-sdk",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if scopes:
        payload_dict["scopes"] = scopes

    if raw_secret:
        # Derive the signing key.  If the secret looks like an agent secret
        # (ags_ prefix), hash it with SHA-256 so the HMAC key matches the
        # credential_hash stored server-side.  Otherwise use as-is (JWT_SECRET).
        if raw_secret.startswith("ags_"):
            signing_key = hashlib.sha256(raw_secret.encode()).hexdigest()
        else:
            signing_key = raw_secret

        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = _b64url(json.dumps(payload_dict, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode()
        signature = _b64url(
            hmac.new(signing_key.encode(), signing_input, hashlib.sha256).digest()
        )
        return f"{header}.{payload}.{signature}"

    raise ValueError(
        "[clampd] No signing secret available. "
        "Set JWT_SECRET env var or pass secret= to make_agent_jwt(). "
        "Unsigned JWTs (alg: none) are not supported."
    )
