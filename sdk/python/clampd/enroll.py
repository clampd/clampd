"""Per-agent Ed25519 identity and gateway enrollment.

The private key is generated on first run, persisted under ``CLAMPD_HOME``
(default ``~/.clampd``), and never leaves the process. The gateway stores only
the public key as the agent's credential and assigns the agent UUID, which is
cached alongside the key so later runs reuse the same identity.

Attestation anchors (highest assurance first): a one-time enrollment token,
a Kubernetes projected service-account token, GitHub Actions OIDC, or none
(dev / open enrollment).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clampd._errors import ClampdEnrollError

_HOME = pathlib.Path(os.environ.get("CLAMPD_HOME", "~/.clampd")).expanduser()


@dataclass
class Identity:
    private_key: Ed25519PrivateKey
    agent_id: str | None  # assigned by the gateway on enrollment


def _slot(org_key: str, name: str) -> pathlib.Path:
    org = hashlib.sha256(org_key.encode()).hexdigest()[:16]
    safe_name = name.replace("/", "_")
    return _HOME / "agents" / org / f"{safe_name}.json"


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate(org_key: str, name: str) -> Identity:
    """Generate a fresh keypair, persist it (agent_id unset), return the Identity."""
    key = Ed25519PrivateKey.generate()
    _save(_slot(org_key, name), key, None)
    return Identity(private_key=key, agent_id=None)


def load_or_create(org_key: str, name: str) -> Identity:
    slot = _slot(org_key, name)
    if slot.exists():
        data = json.loads(slot.read_text())
        key = serialization.load_pem_private_key(
            data["private_pem"].encode(), password=None
        )
        return Identity(private_key=key, agent_id=data.get("agent_id"))
    return _generate(org_key, name)


def _save(slot: pathlib.Path, key: Ed25519PrivateKey, agent_id: str | None) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    slot.parent.mkdir(parents=True, exist_ok=True)
    slot.write_text(json.dumps({"private_pem": pem, "agent_id": agent_id}))
    slot.chmod(0o600)


def gather_attestation() -> tuple[str, str]:
    # A re-key token takes precedence: it re-binds a new keypair to an existing
    # agent (used after losing the local key). Minted in the dashboard.
    if token := os.environ.get("CLAMPD_REBIND_TOKEN"):
        return ("rekey_token", token)
    # An explicit, admin-minted enroll token (org-wide) is the next choice.
    if token := os.environ.get("CLAMPD_ENROLL_TOKEN"):
        return ("enroll_token", token)
    # Workload OIDC attestation: a verified, STABLE per-workload identity
    # (k8s ServiceAccount / OIDC `sub`). The gateway verifies the projected
    # token against the org's trusted issuers and derives the agent's stable
    # attestation id from `sub` — enabling idempotent auto-recovery across pod
    # restarts and token rotation. Preferred when available.
    if token := _workload_token():
        return ("oidc", token)
    return ("none", "")


def _workload_token() -> str:
    """Locate a workload OIDC/k8s ServiceAccount token for attestation.

    Order: explicit raw token, explicit file, the recommended clampd-audience
    projected token, then the default k8s ServiceAccount token as a fallback.
    Returns "" when none is present (caller falls back to ``none``)."""
    if token := os.environ.get("CLAMPD_WORKLOAD_TOKEN"):
        return token.strip()
    candidates = []
    if path := os.environ.get("CLAMPD_WORKLOAD_TOKEN_FILE"):
        candidates.append(pathlib.Path(path))
    candidates.append(pathlib.Path("/var/run/secrets/clampd.io/token"))
    candidates.append(pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount/token"))
    for path in candidates:
        try:
            if path.exists():
                token = path.read_text().strip()
                if token:
                    return token
        except OSError:
            continue
    return ""


def enroll(host: str, org_key: str, name: str) -> Identity:
    """Return an enrolled :class:`Identity`, enrolling with the gateway if the
    local identity has no assigned agent UUID yet.

    When ``CLAMPD_REBIND_TOKEN`` is set, a re-key is forced even if a cached
    identity exists: a fresh keypair is generated and bound to the existing
    agent (same UUID), then persisted locally."""
    rebinding = bool(os.environ.get("CLAMPD_REBIND_TOKEN"))
    if rebinding:
        # Force a fresh keypair — the old private key is gone or being rotated.
        ident = _generate(org_key, name)
    else:
        ident = load_or_create(org_key, name)
        if ident.agent_id:
            return ident

    att_type, att = gather_attestation()
    try:
        resp = httpx.post(
            f"{host}/v1/enroll",
            headers={"X-AG-Key": org_key, "Content-Type": "application/json"},
            json={
                "public_key": public_key_b64(ident.private_key),
                "attestation_type": att_type,
                "attestation": att,
                "name": name,
            },
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        raise ClampdEnrollError(f"enrollment request failed: {e}") from e

    if resp.status_code not in (200, 201):
        raise ClampdEnrollError(f"enrollment rejected: {resp.status_code} {resp.text}")

    agent_id = resp.json().get("agent_id")
    if not agent_id:
        raise ClampdEnrollError("enrollment response missing agent_id")

    _save(_slot(org_key, name), ident.private_key, agent_id)
    ident.agent_id = agent_id
    return ident
