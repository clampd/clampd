"""JWT helper for Clampd agent authentication."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_agent_jwt_ed25519(
    agent_id: str,
    private_key: "Ed25519PrivateKey",
    *,
    scopes: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> str:
    """Create an EdDSA-signed JWT with ``sub`` = *agent_id*.

    Signed with the agent's Ed25519 private key; the gateway verifies against
    the public key registered at enrollment. No shared secret.
    """
    now = int(time.time())
    payload_dict: dict[str, Any] = {
        "sub": agent_id,
        "iss": "clampd-sdk",
        "aud": "ag-gateway",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if scopes:
        payload_dict["scopes"] = scopes

    header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(payload_dict, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64url(private_key.sign(signing_input.encode()))
    return f"{signing_input}.{signature}"


def _delegation_chain_hash(chain: list[str]) -> str:
    """SHA-256 of lowercased agent IDs joined by ','. Mirrors
    `ag-gateway::delegation::chain_hash`. Bound to a specific ancestry so
    a proof minted for [A, B, C] can't be replayed for [A, B, X]."""
    joined = ",".join(a.lower() for a in chain).encode()
    return hashlib.sha256(joined).hexdigest()


def make_delegation_proof_ed25519(
    leaf_agent_id: str,
    chain: list[str],
    private_key: "Ed25519PrivateKey",
    *,
    ttl_seconds: int = 30,
) -> str:
    """Mint an EdDSA-signed delegation proof for one cross-agent hop.

    The leaf agent (executor) signs a short-lived JWT binding (leaf, chain)
    with its Ed25519 private key. The gateway verifies against the agent's
    public key in `ag:agent:cred:{leaf}`. TTL defaults to 30s — a captured
    proof is useless after that.
    """
    now = int(time.time())
    payload_dict: dict[str, Any] = {
        "sub": leaf_agent_id,
        "iss": "clampd-sdk",
        "aud": "ag-gateway",
        "iat": now,
        "exp": now + ttl_seconds,
        "chain_hash": _delegation_chain_hash(chain),
    }
    header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(payload_dict, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64url(private_key.sign(signing_input.encode()))
    return f"{signing_input}.{signature}"
