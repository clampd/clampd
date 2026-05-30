"""Tests for v0.20 StructuredDenial / CorrectiveAction parsing + render."""

from __future__ import annotations

import pytest

from clampd._corrective import (
    CorrectiveAction,
    DownscopeTo,
    NoCorrection,
    RedactValue,
    RenameField,
    SplitRequest,
    StructuredDenial,
    SwitchEndpoint,
    SwitchTool,
    WaitAndRetry,
    render_corrective_for_llm,
    synthetic_denial,
)
from clampd.client import (
    ClampdBlockedError,
    ProxyResponse,
    ScanOutputResponse,
    ScanResponse,
)


# ── Wire-format parsing (one per variant) ────────────────────────────────


def _wire_corrective(action_key: str, action_value: dict) -> dict:
    """Build a corrective in the gateway's actual wire shape: flat
    ``kind`` + ``payload``. Matches ``ag_common::denial::CorrectiveActionJson``
    and the dashboard's ``CorrectiveAction`` TypeScript interface."""
    return {
        "kind": action_key,
        "payload": action_value,
        "human_explanation": "test hint",
        "confidence": "high",
        "source": "rule",
    }


def test_parse_switch_tool():
    c = CorrectiveAction.from_json(_wire_corrective("switch_tool", {"tool": "archive_table", "scope": "db:write:soft_delete"}))
    assert isinstance(c.action, SwitchTool)
    assert c.action.tool == "archive_table"
    assert c.action.scope == "db:write:soft_delete"


def test_parse_downscope_to():
    c = CorrectiveAction.from_json(_wire_corrective("downscope_to", {"scope": "db:read:select"}))
    assert isinstance(c.action, DownscopeTo)
    assert c.action.scope == "db:read:select"


def test_parse_rename_field_uses_keyword_safe_attr():
    c = CorrectiveAction.from_json(_wire_corrective("rename_field", {"from": "uid", "to": "user_id"}))
    assert isinstance(c.action, RenameField)
    assert c.action.from_ == "uid"
    assert c.action.to == "user_id"


def test_parse_redact_value():
    c = CorrectiveAction.from_json(_wire_corrective("redact_value", {"json_path": "$.body", "mask": "<REDACTED>"}))
    assert isinstance(c.action, RedactValue)
    assert c.action.json_path == "$.body"
    assert c.action.mask == "<REDACTED>"


def test_parse_split_request():
    c = CorrectiveAction.from_json(_wire_corrective("split_request", {"max_items_per_batch": 100, "current_items": 750}))
    assert isinstance(c.action, SplitRequest)
    assert c.action.max_items_per_batch == 100
    assert c.action.current_items == 750


def test_parse_wait_and_retry():
    c = CorrectiveAction.from_json(_wire_corrective("wait_and_retry", {"retry_after_seconds": 60, "window_label": "09:00-17:00 UTC"}))
    assert isinstance(c.action, WaitAndRetry)
    assert c.action.retry_after_seconds == 60
    assert c.action.window_label == "09:00-17:00 UTC"


def test_parse_switch_endpoint():
    c = CorrectiveAction.from_json(_wire_corrective("switch_endpoint", {"from_url": "https://x", "to_url": "https://approved/*"}))
    assert isinstance(c.action, SwitchEndpoint)
    assert c.action.from_url == "https://x"
    assert c.action.to_url == "https://approved/*"


def test_parse_no_correction():
    c = CorrectiveAction.from_json(_wire_corrective("no_correction", {}))
    assert isinstance(c.action, NoCorrection)


def test_parse_none_returns_none():
    assert CorrectiveAction.from_json(None) is None
    assert CorrectiveAction.from_json({}) is None


def test_parse_confidence_default_medium_when_invalid():
    c = CorrectiveAction.from_json({
        "kind": "no_correction",
        "payload": {},
        "confidence": "bogus",
        "human_explanation": "x",
    })
    assert c.confidence == "medium"


def test_parse_reads_rendered_block_when_present():
    """v0.23.1+ gateway pre-renders tool_result + short_label."""
    c = CorrectiveAction.from_json({
        "kind": "switch_tool",
        "payload": {"tool": "archive_table"},
        "human_explanation": "Use archive_table",
        "confidence": "high",
        "source": "rule",
        "rendered": {
            "tool_result": "Denied: Use archive_table\nTry the `archive_table` tool instead.",
            "short_label": "Switch tool",
        },
    })
    assert c.rendered is not None
    assert "archive_table" in c.rendered.tool_result
    assert c.rendered.short_label == "Switch tool"


def test_parse_leaves_rendered_none_for_pre_0_23_1_gateway():
    c = CorrectiveAction.from_json({
        "kind": "no_correction",
        "payload": {},
        "human_explanation": "no path",
        "confidence": "high",
        "source": "rule",
    })
    assert c.rendered is None


def test_render_corrective_for_llm_prefers_gateway_rendered_string():
    from clampd._corrective import render_corrective_for_llm
    c = CorrectiveAction.from_json({
        "kind": "switch_tool",
        "payload": {"tool": "archive_table"},
        "human_explanation": "ignored when rendered is present",
        "confidence": "high",
        "source": "rule",
        "rendered": {
            "tool_result": "TOOL_RESULT_FROM_GATEWAY",
            "short_label": "Switch tool",
        },
    })
    assert render_corrective_for_llm(c) == "TOOL_RESULT_FROM_GATEWAY"


# ── StructuredDenial parsing ─────────────────────────────────────────────


def test_structured_denial_round_trip():
    raw = {
        "rule_id": "R001",
        "violated_predicate": "params.query MATCHES /DROP/i",
        "offending_value": "DROP TABLE users",
        "corrective": _wire_corrective("switch_tool", {"tool": "archive_table"}),
        "reason_codes": ["HARD_DENY_MALICIOUS"],
        "boundary_violation": None,
        "boundary_matched_rule": None,
        "idempotency_key": "abc-123",
    }
    d = StructuredDenial.from_json(raw)
    assert d is not None
    assert d.rule_id == "R001"
    assert d.violated_predicate == "params.query MATCHES /DROP/i"
    assert d.offending_value == "DROP TABLE users"
    assert d.idempotency_key == "abc-123"
    assert d.reason_codes == ["HARD_DENY_MALICIOUS"]
    assert isinstance(d.corrective.action, SwitchTool)


def test_structured_denial_from_none_returns_none():
    assert StructuredDenial.from_json(None) is None
    assert StructuredDenial.from_json({}) is None


def test_structured_denial_handles_missing_optional_fields():
    raw = {"rule_id": "R001", "violated_predicate": "foo"}
    d = StructuredDenial.from_json(raw)
    assert d is not None
    assert d.corrective is None
    assert d.boundary_violation is None
    assert d.reason_codes == []


# ── Render templates (per variant) ───────────────────────────────────────


def _ca(variant, **kwargs):
    return CorrectiveAction(
        action=variant,
        human_explanation=kwargs.pop("explanation", "explanation here"),
        confidence=kwargs.pop("confidence", "high"),
        source=kwargs.pop("source", "rule"),
    )


def test_render_switch_tool():
    out = render_corrective_for_llm(_ca(SwitchTool(tool="archive_table")))
    assert "archive_table" in out
    assert "Try the" in out


def test_render_downscope_to():
    out = render_corrective_for_llm(_ca(DownscopeTo(scope="db:read:select")))
    assert "db:read:select" in out
    assert "Retry under scope" in out


def test_render_rename_field():
    out = render_corrective_for_llm(_ca(RenameField(from_="uid", to="user_id")))
    assert "uid" in out and "user_id" in out


def test_render_redact_value():
    out = render_corrective_for_llm(_ca(RedactValue(json_path="$.body", mask="<X>")))
    assert "$.body" in out


def test_render_split_request():
    out = render_corrective_for_llm(_ca(SplitRequest(max_items_per_batch=100, current_items=750)))
    assert "100" in out


def test_render_wait_and_retry_with_window():
    out = render_corrective_for_llm(_ca(WaitAndRetry(retry_after_seconds=60, window_label="09:00-17:00 UTC")))
    assert "60" in out
    assert "09:00-17:00 UTC" in out


def test_render_wait_and_retry_no_window():
    out = render_corrective_for_llm(_ca(WaitAndRetry(retry_after_seconds=30)))
    assert "30s" in out


def test_render_switch_endpoint():
    out = render_corrective_for_llm(_ca(SwitchEndpoint(from_url="https://x", to_url="https://approved")))
    assert "https://approved" in out
    assert "https://x" in out


def test_render_no_correction_carries_explanation_only():
    out = render_corrective_for_llm(_ca(NoCorrection(), explanation="No path forward"))
    assert "No path forward" in out


def test_render_low_confidence_suppressed():
    """Low-confidence correctives are dashboard-only; never surfaced to LLM."""
    out = render_corrective_for_llm(_ca(SwitchTool(tool="x"), confidence="low"))
    assert out == ""


def test_render_none_returns_empty():
    assert render_corrective_for_llm(None) == ""


# ── ClampdBlockedError integration ───────────────────────────────────────


def test_blocked_error_accepts_structured_denial():
    d = StructuredDenial(
        rule_id="R001",
        violated_predicate="DROP detected",
        corrective=CorrectiveAction(
            action=SwitchTool(tool="archive_table"),
            human_explanation="Use archive_table",
            confidence="high",
            source="rule",
        ),
    )
    err = ClampdBlockedError(d, risk_score=0.95)
    assert err.denial is d
    assert err.risk_score == 0.95
    assert "Use archive_table" in err.reason
    assert "archive_table" in err.to_tool_result()


def test_blocked_error_accepts_plain_string_for_sdk_synthetic():
    """SDK-internal call sites (e.g. delegation depth) still pass a string;
    the error wraps it in a synthetic denial so .denial is always typed."""
    err = ClampdBlockedError("delegation too deep", risk_score=1.0)
    assert err.denial is not None
    assert err.denial.rule_id == "SDK/synthetic"
    assert err.denial.violated_predicate == "delegation too deep"


def test_blocked_error_to_tool_result_with_no_corrective():
    """When the denial has no corrective, to_tool_result still produces a
    human-readable message (falls back to violated_predicate)."""
    d = StructuredDenial(rule_id="R001", violated_predicate="reason text")
    err = ClampdBlockedError(d)
    assert "reason text" in err.to_tool_result()


def test_blocked_error_low_confidence_corrective_renders_fallback():
    """A LOW-confidence corrective is suppressed from to_tool_result, but
    the error still produces a fallback string with .reason for logging."""
    d = StructuredDenial(
        rule_id="R001",
        violated_predicate="silent",
        corrective=CorrectiveAction(
            action=SwitchTool(tool="x"),
            human_explanation="quiet",
            confidence="low",
            source="rule",
        ),
    )
    err = ClampdBlockedError(d)
    assert err.to_tool_result()  # non-empty fallback
    assert "x" not in err.to_tool_result()  # low-confidence tool is NOT surfaced


# ── Response model integration (denial field populated from JSON) ────────


def test_proxy_response_parses_denial_from_dict():
    """The gateway JSON has `denial` as a nested dict; ProxyResponse should
    coerce it into a typed StructuredDenial on construction."""
    resp = ProxyResponse(
        allowed=False,
        risk_score=0.95,
        denial={
            "rule_id": "R001",
            "violated_predicate": "params.query MATCHES /DROP/i",
            "corrective": _wire_corrective("downscope_to", {"scope": "db:read:select"}),
            "reason_codes": [],
        },
    )
    assert resp.denial is not None
    assert resp.denial.rule_id == "R001"
    assert isinstance(resp.denial.corrective.action, DownscopeTo)


def test_proxy_response_no_denial_when_allowed():
    resp = ProxyResponse(allowed=True, risk_score=0.0)
    assert resp.denial is None


def test_scan_output_response_parses_denial():
    resp = ScanOutputResponse(
        allowed=False,
        risk_score=0.85,
        denial={"rule_id": "R039", "violated_predicate": "PII leak"},
    )
    assert resp.denial is not None
    assert resp.denial.rule_id == "R039"


# ── synthetic_denial helper ──────────────────────────────────────────────


def test_synthetic_denial_basic():
    d = synthetic_denial("SDK/timeout", "gateway_timeout")
    assert d.rule_id == "SDK/timeout"
    assert d.violated_predicate == "gateway_timeout"
    assert d.corrective is None


# ── Loop detection (idempotency_key) ─────────────────────────────────────


def test_loop_detection_first_seen_is_ok():
    """First denial with an idempotency_key is fine — recorded in the ring."""
    from clampd.client import ClampdClient

    c = ClampdClient(agent_id="a")
    d = StructuredDenial(rule_id="R001", violated_predicate="x", idempotency_key="abc123")
    # First call: not a loop, recorded.
    assert c._record_and_check_loop(d) is False


def test_loop_detection_second_same_key_is_loop():
    """Same key seen twice → flagged as a loop."""
    from clampd.client import ClampdClient

    c = ClampdClient(agent_id="a")
    d = StructuredDenial(rule_id="R001", violated_predicate="x", idempotency_key="abc123")
    c._record_and_check_loop(d)
    # Second call with the same key: loop detected.
    assert c._record_and_check_loop(d) is True


def test_loop_detection_different_keys_not_a_loop():
    """Different idempotency keys (different params/tool) don't trip detection."""
    from clampd.client import ClampdClient

    c = ClampdClient(agent_id="a")
    d1 = StructuredDenial(rule_id="R001", violated_predicate="x", idempotency_key="key1")
    d2 = StructuredDenial(rule_id="R001", violated_predicate="x", idempotency_key="key2")
    assert c._record_and_check_loop(d1) is False
    assert c._record_and_check_loop(d2) is False


def test_loop_detection_no_key_is_noop():
    """Synthetic denials (no idempotency_key) never trigger loop detection."""
    from clampd.client import ClampdClient

    c = ClampdClient(agent_id="a")
    d = StructuredDenial(rule_id="SDK/timeout", violated_predicate="x")  # no key
    assert c._record_and_check_loop(d) is False
    assert c._record_and_check_loop(d) is False  # still false


def test_loop_error_subclasses_blocked_error():
    """ClampdLoopError must be a SUBCLASS of ClampdBlockedError so existing
    `except ClampdBlockedError: raise` chains propagate it correctly."""
    from clampd.client import ClampdBlockedError, ClampdLoopError

    assert issubclass(ClampdLoopError, ClampdBlockedError)


def test_loop_error_carries_typed_denial():
    """ClampdLoopError exposes the same `.denial` field as the base."""
    from clampd.client import ClampdLoopError

    d = StructuredDenial(rule_id="R001", violated_predicate="x", idempotency_key="abc")
    err = ClampdLoopError(d)
    assert err.denial is d
    assert "abc" in str(err)
    assert "loop" in str(err).lower()
