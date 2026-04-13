"""Tool-side scope token verification (Ed25519).

Lets tool developers verify that a Clampd-approved scope token is present
before executing sensitive operations. The gateway mints these tokens on
approved proxy() calls; this module validates them on the tool side.

Scope tokens are signed with Ed25519 (asymmetric). The public key is fetched
from the gateway's JWKS endpoint (GET /.well-known/jwks.json) and cached
locally for 1 hour. No shared secret is needed.

Usage in a tool implementation:

    from clampd.tool_verify import require_scope, get_current_scope_token, verify_scope_token

    @clampd.guard("db.query")
    def run_query(sql: str) -> str:
        # Option A: Explicit verification
        claims = verify_scope_token(get_current_scope_token())
        if "data:pii:query" not in claims.scope:
            raise PermissionError("Insufficient scope")

        # Option B: Declarative (raises if scope missing)
        require_scope("data:pii:query")

        return db.execute(sql)
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Any

# ── Exception ─────────────────────────────────────────────────────────


class ScopeVerificationError(Exception):
    """Raised when scope token verification fails."""

    def __init__(self, reason: str, claims: ScopeTokenClaims | None = None):
        self.reason = reason
        self.claims = claims
        super().__init__(f"Scope verification failed: {reason}")


# ── Claims dataclass ──────────────────────────────────────────────────


@dataclass
class ScopeTokenClaims:
    """Decoded and verified scope token claims."""

    sub: str  # agent_id
    scope: str  # space-separated granted scopes
    tool: str  # tool name
    binding: str  # SHA-256(tool + params)
    exp: int  # expiry unix timestamp
    rid: str  # request_id

    def has_scope(self, required: str) -> bool:
        """Check if a specific scope is granted."""
        return required in self.scope.split()

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return time.time() > self.exp

    @property
    def scopes(self) -> list[str]:
        """Return list of granted scopes."""
        return self.scope.split()


# ── JWKS public key cache ────────────────────────────────────────────

_cached_jwks: dict[str, Any] | None = None
_jwks_fetched_at: float = 0.0
_JWKS_CACHE_TTL = 300  # 5 minutes


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _get_gateway_url() -> str:
    """Resolve the gateway URL from environment."""
    return (
        os.environ.get("CLAMPD_GATEWAY_URL")
        or os.environ.get("AG_GATEWAY_URL")
        or "http://localhost:8080"
    )


def fetch_jwks(gateway_url: str | None = None) -> dict[str, Any]:
    """Fetch JWKS from the gateway's /.well-known/jwks.json endpoint.

    Returns the parsed JWKS JSON. Results are cached for 1 hour.
    """
    global _cached_jwks, _jwks_fetched_at

    now = time.time()
    if _cached_jwks is not None and (now - _jwks_fetched_at) < _JWKS_CACHE_TTL:
        return _cached_jwks

    url = (gateway_url or _get_gateway_url()).rstrip("/")
    jwks_url = f"{url}/.well-known/jwks.json"

    import httpx

    resp = httpx.get(jwks_url, timeout=10.0)
    resp.raise_for_status()
    jwks: dict[str, Any] = resp.json()

    _cached_jwks = jwks
    _jwks_fetched_at = now
    return jwks


def _get_ed25519_public_key_bytes(gateway_url: str | None = None) -> bytes:
    """Extract the Ed25519 public key bytes from JWKS.

    Looks for the key with kid="scope-v1", crv="Ed25519".
    """
    jwks = fetch_jwks(gateway_url)
    for key in jwks.get("keys", []):
        if key.get("crv") == "Ed25519" and key.get("kid") == "scope-v1":
            x = key.get("x", "")
            return _b64url_decode(x)
    raise ScopeVerificationError("No Ed25519 scope key found in JWKS")


def invalidate_jwks_cache() -> None:
    """Force re-fetch of JWKS on next verification."""
    global _cached_jwks, _jwks_fetched_at
    _cached_jwks = None
    _jwks_fetched_at = 0.0


# ── Ed25519 verification ─────────────────────────────────────────────


def _verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature using the cryptography library or fallback."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature, message)
        return True
    except ImportError:
        pass

    # Fallback: use PyNaCl (nacl.signing)
    try:
        from nacl.signing import VerifyKey

        vk = VerifyKey(public_key_bytes)
        vk.verify(message, signature)
        return True
    except ImportError:
        pass

    raise ScopeVerificationError(
        "Ed25519 verification requires 'cryptography' or 'PyNaCl' package. "
        "Install with: pip install cryptography"
    )


# ── Token verification ────────────────────────────────────────────────


def verify_scope_token(
    token: str,
    public_key: bytes | None = None,
    gateway_url: str | None = None,
) -> ScopeTokenClaims:
    """Verify a Clampd scope token and return its claims.

    Args:
        token: The scope token string (format: base64url_payload.base64url_signature).
        public_key: Ed25519 public key bytes (32 bytes). If not provided,
            fetches from the gateway's JWKS endpoint.
        gateway_url: Gateway URL for JWKS fetch. Falls back to env vars.

    Returns:
        ScopeTokenClaims with the verified claims.

    Raises:
        ScopeVerificationError: If the token is missing, malformed, has an
            invalid signature, or is expired.
    """
    if not token:
        raise ScopeVerificationError("No scope token provided")

    # Split token: base64url_payload.base64url_signature
    parts = token.split(".")
    if len(parts) != 2:
        raise ScopeVerificationError(f"Malformed token: expected 2 parts, got {len(parts)}")

    payload_b64, sig_b64 = parts

    # Get public key
    pub_key_bytes = public_key
    if pub_key_bytes is None:
        try:
            pub_key_bytes = _get_ed25519_public_key_bytes(gateway_url)
        except Exception as e:
            if not isinstance(e, ScopeVerificationError):
                raise ScopeVerificationError(f"Failed to fetch JWKS: {e}") from e
            raise

    # Decode signature
    try:
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as e:
        raise ScopeVerificationError(f"Signature decode error: {e}") from e

    # Verify Ed25519 signature
    try:
        valid = _verify_ed25519(pub_key_bytes, payload_b64.encode(), sig_bytes)
        if not valid:
            raise ScopeVerificationError("Invalid signature")
    except ScopeVerificationError:
        raise
    except Exception:
        # On verification failure, invalidate cache and retry once
        invalidate_jwks_cache()
        raise ScopeVerificationError("Invalid signature")

    # Decode payload
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, Exception) as e:
        raise ScopeVerificationError(f"Invalid payload: {e}") from e

    # Extract claims
    try:
        claims = ScopeTokenClaims(
            sub=payload["sub"],
            scope=payload.get("scope", ""),
            tool=payload.get("tool", ""),
            binding=payload.get("binding", ""),
            exp=int(payload["exp"]),
            rid=payload.get("rid", ""),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ScopeVerificationError(f"Missing required claim: {e}") from e

    # Check expiry
    if claims.is_expired:
        raise ScopeVerificationError("Token expired", claims=claims)

    return claims


# ── Context helpers ───────────────────────────────────────────────────


def get_current_scope_token() -> str:
    """Read the current scope token from contextvars.

    Returns the token set by the @guard decorator during the current
    tool call, or empty string if no token is in context.
    """
    # Import here to avoid circular imports
    from clampd import _scope_token_var
    return _scope_token_var.get()


# ── Convenience function ──────────────────────────────────────────────


def require_scope(
    required_scope: str,
    token: str | None = None,
    public_key: bytes | None = None,
    gateway_url: str | None = None,
) -> ScopeTokenClaims:
    """Verify scope token and check that a specific scope is granted.

    Convenience function that combines get_current_scope_token(),
    verify_scope_token(), and has_scope().

    Args:
        required_scope: The scope string to check (e.g. "data:pii:query").
        token: Optional explicit token. If not provided, reads from context.
        public_key: Optional Ed25519 public key bytes. If not provided, fetches JWKS.
        gateway_url: Gateway URL for JWKS fetch.

    Returns:
        ScopeTokenClaims on success.

    Raises:
        ScopeVerificationError: If token is invalid or required scope is missing.
    """
    resolved_token = token or get_current_scope_token()
    if not resolved_token:
        raise ScopeVerificationError("No scope token available in context")

    claims = verify_scope_token(resolved_token, public_key=public_key, gateway_url=gateway_url)

    if not claims.has_scope(required_scope):
        raise ScopeVerificationError(
            f"Scope '{required_scope}' not granted (have: {claims.scope})",
            claims=claims,
        )

    return claims
