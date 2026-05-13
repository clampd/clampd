"""Cross-language parity vectors for clampd.contract_hash.contract_hash().

The same input set + expected hex strings live in:
  - services/crates/ag-common/src/contract_hash.rs (parity_vectors fn)
  - sdk/typescript/src/__tests__/contract-hash-parity.test.ts

**DO NOT** update a hex string here in isolation. If a hash changes for ONE
implementation, the canonicalisation has drifted — investigate, do not
paper over it. All three implementations must agree byte-for-byte.

When adding a vector: compute the hash in all three SDKs, verify they
match, then encode it in all three test files.
"""
from __future__ import annotations

import pytest

from clampd.contract_hash import contract_hash


# ── Cross-language vector set ──────────────────────────────────────────
#
# (label, name, description, parameters, expected_hex)
PARITY_VECTORS = [
    (
        "V1_simple_sql",
        "db.query",
        "Run a test query against the warehouse",
        {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
        "972f2f0a904ff55ccc836c4667554b0857203f3f95ab43c0a681c851b2c77514",
    ),
    (
        "V2_empty",
        "Bash",
        "",
        {},
        "9fbfcf9a33c1b0736670b423c4d829feba026b6da5b30fa43fb8e184fccebe4b",
    ),
    (
        "V3_nested_required",
        "fs.move",
        "Move a file to a new path",
        {
            "type": "object",
            "properties": {
                "src": {"type": "string"},
                "dst": {"type": "string"},
                "options": {
                    "type": "object",
                    "properties": {"overwrite": {"type": "boolean", "default": False}},
                },
            },
            "required": ["src", "dst"],
        },
        "8e60f85a924bde9f6a36792f594c78b30b9a4f230c6436ab1cd9d910811d1bf2",
    ),
    (
        "V4_unicode",
        "comms.email",
        "Send an email — supports é, ñ, 漢字, \U0001f680",
        {"type": "object", "properties": {"to": {"type": "string", "format": "email"}}},
        "8d45eb20f59a49910265bcfe3ed32aa0d337c48f17355f95d17a3c3e8b9bcc23",
    ),
    (
        "V5_special_chars",
        "fs.write",
        "Write content to a file",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {
                    "type": "string",
                    "description": "Body text. May contain \"quotes\" and \\ backslashes and \nnewlines.",
                },
            },
        },
        "9f02aa46ccc926a8e54feccc99b1c1059bce8aa5b5e4bfdb4e6c86e60cd885d1",
    ),
    (
        "V6_arrays",
        "search.batch",
        "Batch keyword search",
        {
            "type": "object",
            "properties": {
                "queries": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
        },
        "e83bf68c37bbac71b49d899470b4fef300c34f53c28bd4fbe4d7aad38a6fbc1f",
    ),
    (
        "V7_numbers",
        "math.compute",
        "Numeric computation",
        {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "minimum": 0, "maximum": 100},
                "y": {"type": "number"},
                "scale": {"type": "number", "default": 1.5},
            },
        },
        "aa3250631d691218a58ac2062241316391e6b26a803d4b81cd6e9242c607a721",
    ),
]


@pytest.mark.parametrize("label,name,description,parameters,expected", PARITY_VECTORS)
def test_cross_lang_parity_vectors(
    label: str, name: str, description: str, parameters: dict, expected: str
) -> None:
    actual = contract_hash(name=name, description=description, parameters=parameters)
    assert actual == expected, (
        f"vector {label} drifted (Python impl). Investigate before updating any "
        f"of the three test files (rust/python/typescript). expected={expected} "
        f"got={actual}"
    )


def test_key_order_independence() -> None:
    """Two structurally-equal schemas with different key insertion orders
    must produce the same hash."""
    p1 = {
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    p2 = {
        "properties": {"b": {"type": "integer"}, "a": {"type": "string"}},
        "type": "object",
    }
    assert contract_hash(name="t", description="d", parameters=p1) == contract_hash(
        name="t", description="d", parameters=p2
    )


def test_deterministic() -> None:
    h1 = contract_hash(name="Bash", description="", parameters={})
    h2 = contract_hash(name="Bash", description="", parameters={})
    assert h1 == h2
    assert len(h1) == 64
