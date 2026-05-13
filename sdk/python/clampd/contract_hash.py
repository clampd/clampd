"""Canonical tool-contract hash — wire-identical to the TypeScript SDK.

Same formula as ``sdk/typescript/src/contract-hash.ts`` so a tool
registered from Python and invoked from TS (or vice versa) produces the
same ``descriptor_hash`` — rug-pull detection at the gateway can then
distinguish "admin approved this exact contract" from "someone changed
the contract".

Formula:
    sha256(json.dumps(
        {"name": ..., "description": ..., "parameters": ...},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ))

``sort_keys=True`` + ``separators=(",", ":")`` matches the TS SDK's
``sortedStringify`` output byte-for-byte, modulo unicode escaping
(``ensure_ascii=False`` keeps raw characters like the TS ``JSON.stringify``
default). Both ends emit the same canonicalisation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def contract_hash(name: str, description: str, parameters: Any) -> str:
    """Compute the canonical descriptor hash for a tool contract.

    Args:
        name: Tool name as it appears in proxy requests (e.g. ``"db.query"``).
        description: Human-readable description — participates in the hash,
            so a change here fires a rug-pull alert. Empty string is fine
            when the caller has no description to offer.
        parameters: JSON-Schema object describing the tool's parameters.
            Use ``{}`` when the caller has no schema. Must be
            JSON-serialisable.

    Returns:
        64-character lowercase hex string (SHA-256).
    """
    canonical = json.dumps(
        {
            "name": name,
            "description": description or "",
            "parameters": parameters if parameters is not None else {},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
