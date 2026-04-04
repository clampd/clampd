"""
Mock Clampd Gateway — drop-in replacement for testing without a real gateway.

Usage:
    from mock_gateway import install_mock_gateway, remove_mock_gateway

    install_mock_gateway()
    # ... run your code ...
    remove_mock_gateway()

To switch to a real gateway, remove the install_mock_gateway() call and set:
    CLAMPD_GATEWAY_URL=https://your-gateway.clampd.dev
    CLAMPD_API_KEY=your-api-key
"""
from __future__ import annotations

import json
import re
import time
from unittest.mock import MagicMock, patch

BLOCKED_TOOLS = {"rm_rf", "exec_shell", "delete_database", "drop_table"}

BLOCKED_INPUT_PATTERNS = [
    re.compile(r"ignore\s+(previous|all)\s+instructions", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"rm\s+-rf", re.IGNORECASE),
]

_patches: list = []


def _make_mock_response(data: dict, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.text = json.dumps(data)
    resp.is_success = status < 400
    return resp


def _mock_post(url: str, **kwargs):
    body = json.loads(kwargs.get("content", "{}")) if "content" in kwargs else kwargs.get("json", {})

    if "/v1/proxy" in url:
        tool = body.get("tool", "")
        blocked = tool in BLOCKED_TOOLS
        return _make_mock_response({
            "request_id": f"mock-{int(time.time())}",
            "allowed": not blocked,
            "action": "block" if blocked else "pass",
            "risk_score": 0.95 if blocked else 0.05,
            "denial_reason": f"Tool '{tool}' is blocked by security policy" if blocked else None,
            "matched_rules": ["R001"] if blocked else [],
            "latency_ms": 3,
            "degraded_stages": [],
            "session_flags": [],
            "scope_token": None if blocked else "mock-scope-token",
        })

    if "/v1/verify" in url:
        return _make_mock_response({
            "request_id": f"mock-verify-{int(time.time())}",
            "allowed": True, "risk_score": 0.05, "latency_ms": 2,
            "degraded_stages": [], "session_flags": [],
        })

    if "/v1/inspect" in url:
        return _make_mock_response({
            "request_id": f"mock-inspect-{int(time.time())}",
            "allowed": True, "risk_score": 0.1, "latency_ms": 2,
            "degraded_stages": [], "session_flags": [],
        })

    if "/v1/scan-input" in url:
        text = body.get("text", "")
        blocked = any(p.search(text) for p in BLOCKED_INPUT_PATTERNS)
        return _make_mock_response({
            "allowed": not blocked,
            "risk_score": 0.92 if blocked else 0.03,
            "denial_reason": "Prompt injection detected" if blocked else None,
            "matched_rules": ["SCAN-001"] if blocked else [],
            "latency_ms": 2,
        })

    if "/v1/scan-output" in url:
        return _make_mock_response({
            "allowed": True, "risk_score": 0.02, "denial_reason": None,
            "matched_rules": [], "latency_ms": 2,
            "pii_found": [], "secrets_found": [],
        })

    return _make_mock_response({"error": "unknown endpoint"}, 404)


def install_mock_gateway():
    """Patch httpx.Client to use mock gateway responses."""
    p = patch("httpx.Client")
    mock_cls = p.start()
    instance = mock_cls.return_value
    instance.post.side_effect = _mock_post
    instance.__enter__ = MagicMock(return_value=instance)
    instance.__exit__ = MagicMock(return_value=False)
    _patches.append(p)


def remove_mock_gateway():
    """Remove all mock patches."""
    for p in _patches:
        p.stop()
    _patches.clear()
