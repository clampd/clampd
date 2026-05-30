"""Structured denial + corrective-action types for the Clampd SDK.

Mirrors the v0.20 gateway JSON wire shape (`denial: StructuredDenial`).
The gateway emits this on every Deny/Downscope response; the SDK parses it
into typed objects so callers can pattern-match on the corrective variant
instead of parsing a free-text string.

LLM-facing rendering lives in `render_corrective_for_llm` — same template
set as the TypeScript SDK so error messages are identical across languages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Union

Confidence = Literal["high", "medium", "low"]
Source = Literal[
    "rule",
    "rule_dynamic",
    "scope",
    "boundary",
    "cedar",
    "sdk_override",
    "bundle",
    "gateway",
]


# ── Corrective action variants (one per oneof case) ──────────────────────


@dataclass(frozen=True)
class SwitchTool:
    tool: str
    scope: str | None = None


@dataclass(frozen=True)
class DownscopeTo:
    scope: str


@dataclass(frozen=True)
class RenameField:
    # `from` is a Python keyword — use trailing underscore. The JSON wire
    # key is still "from"; the parser maps both directions.
    from_: str
    to: str


@dataclass(frozen=True)
class RedactValue:
    json_path: str
    mask: str


@dataclass(frozen=True)
class SplitRequest:
    max_items_per_batch: int
    current_items: int


@dataclass(frozen=True)
class WaitAndRetry:
    retry_after_seconds: int
    window_label: str | None = None


@dataclass(frozen=True)
class SwitchEndpoint:
    from_url: str
    to_url: str


@dataclass(frozen=True)
class NoCorrection:
    pass


CorrectiveActionVariant = Union[
    SwitchTool,
    DownscopeTo,
    RenameField,
    RedactValue,
    SplitRequest,
    WaitAndRetry,
    SwitchEndpoint,
    NoCorrection,
]


@dataclass(frozen=True)
class RenderedCorrective:
    """v0.23.1+: gateway-pre-rendered strings. Lets every consumer
    (SDKs, clampd-guard, dashboard, MCP, CI action) read identical text
    without each maintaining its own template library."""

    tool_result: str = ""
    short_label: str = ""


@dataclass
class CorrectiveAction:
    """Typed corrective with a single `action` variant + LLM-facing metadata."""

    action: CorrectiveActionVariant
    human_explanation: str = ""
    confidence: Confidence = "medium"
    source: Source = "rule"
    # v0.23.1: pre-rendered strings, populated when the gateway is
    # 0.23.1+. None when talking to an older gateway — callers should
    # fall back to `render_corrective_for_llm()` which mirrors the
    # server templates.
    rendered: RenderedCorrective | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any] | None) -> "CorrectiveAction | None":
        """Parse the gateway's wire shape:

            {
              "kind": "switch_tool",
              "payload": {"tool": "archive_table", "scope": "db:query:read"},
              "human_explanation": "Use archive_table for soft-delete.",
              "confidence": "high",
              "source": "rule",
              "rendered": {                 # v0.23.1+, optional
                "tool_result": "Denied: ...\\nTry the `archive_table` tool instead.",
                "short_label": "Switch tool"
              }
            }

        The wire shape is flat — variant kind at the top level, variant
        fields inside `payload`. Matches `ag_common::denial::CorrectiveActionJson`
        in the Rust gateway and the dashboard's `CorrectiveAction` TS type."""
        if not d:
            return None
        kind = d.get("kind")
        payload = d.get("payload") or {}
        if not isinstance(kind, str) or not isinstance(payload, dict):
            return None
        variant = _parse_variant(kind, payload)
        if variant is None:
            return None
        confidence = d.get("confidence") or "medium"
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"
        source = d.get("source") or "rule"
        rendered_raw = d.get("rendered")
        rendered = None
        if isinstance(rendered_raw, dict):
            rendered = RenderedCorrective(
                tool_result=str(rendered_raw.get("tool_result") or ""),
                short_label=str(rendered_raw.get("short_label") or ""),
            )
        return cls(
            action=variant,
            human_explanation=d.get("human_explanation") or "",
            confidence=confidence,  # type: ignore[arg-type]
            source=source,  # type: ignore[arg-type]
            rendered=rendered,
        )


def _parse_variant(
    kind: str, payload: dict[str, Any]
) -> CorrectiveActionVariant | None:
    """Build the variant dataclass for a `(kind, payload)` from the gateway.

    `kind` is the discriminator string ("switch_tool", "downscope_to", …);
    `payload` is the variant-specific fields. Unknown kinds return None so
    the corrective is dropped on the SDK side rather than synthesising a
    fake variant — same posture as the Rust resolver."""
    if kind == "switch_tool":
        return SwitchTool(
            tool=payload.get("tool") or "",
            scope=payload.get("scope"),
        )
    if kind == "downscope_to":
        return DownscopeTo(scope=payload.get("scope") or "")
    if kind == "rename_field":
        return RenameField(
            from_=payload.get("from") or "",
            to=payload.get("to") or "",
        )
    if kind == "redact_value":
        return RedactValue(
            json_path=payload.get("json_path") or "",
            mask=payload.get("mask") or "",
        )
    if kind == "split_request":
        return SplitRequest(
            max_items_per_batch=int(payload.get("max_items_per_batch") or 0),
            current_items=int(payload.get("current_items") or 0),
        )
    if kind == "wait_and_retry":
        return WaitAndRetry(
            retry_after_seconds=int(payload.get("retry_after_seconds") or 0),
            window_label=payload.get("window_label"),
        )
    if kind == "switch_endpoint":
        return SwitchEndpoint(
            from_url=payload.get("from_url") or "",
            to_url=payload.get("to_url") or "",
        )
    if kind == "no_correction":
        return NoCorrection()
    return None


# ── StructuredDenial ─────────────────────────────────────────────────────


@dataclass
class StructuredDenial:
    """Carries the rule/policy that fired + a typed corrective for the LLM.

    Emitted by the gateway on every Deny/Downscope. Absent on Allow.
    """

    rule_id: str = ""
    violated_predicate: str = ""
    offending_value: str = ""
    corrective: CorrectiveAction | None = None
    reason_codes: list[str] = field(default_factory=list)
    boundary_violation: str | None = None
    boundary_matched_rule: str | None = None
    idempotency_key: str | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any] | None) -> "StructuredDenial | None":
        if not d:
            return None
        return cls(
            rule_id=d.get("rule_id") or "",
            violated_predicate=d.get("violated_predicate") or "",
            offending_value=d.get("offending_value") or "",
            corrective=CorrectiveAction.from_json(d.get("corrective")),
            reason_codes=list(d.get("reason_codes") or []),
            boundary_violation=d.get("boundary_violation"),
            boundary_matched_rule=d.get("boundary_matched_rule"),
            idempotency_key=d.get("idempotency_key"),
        )


def synthetic_denial(
    rule_id: str,
    violated_predicate: str,
    *,
    corrective: CorrectiveAction | None = None,
) -> StructuredDenial:
    """Build a denial for SDK-side error conditions (gateway timeout, circuit
    breaker, network failure) where no gateway StructuredDenial was returned.
    Uses synthetic `SDK/...` rule IDs so observability can distinguish these
    from real rule denials."""
    return StructuredDenial(
        rule_id=rule_id,
        violated_predicate=violated_predicate,
        corrective=corrective,
    )


# ── LLM-facing render templates ──────────────────────────────────────────


def render_corrective_for_llm(c: CorrectiveAction | None) -> str:
    """Render a corrective into a tool_result-suitable string.

    Returns "" for low-confidence correctives (dashboard-only). LLM tool
    loops use this string as the `tool_result.content` so the model can
    pattern-match on the suggested action.

    As of v0.23.1 the gateway pre-renders this string in
    `corrective.rendered.tool_result` so all consumers read identical
    text. This function prefers that pre-rendered value when the gateway
    is 0.23.1+, and falls back to inlined templates (identical to the
    server's `ag_common::denial::render`) when talking to older gateways.
    """
    if c is None:
        return ""
    # Prefer the server-rendered string. The gateway already applies the
    # "low confidence = empty tool_result" rule, so we don't duplicate it.
    if c.rendered is not None:
        return c.rendered.tool_result

    # Fallback for pre-v0.23.1 gateways. Same templates as the server's
    # `ag_common::denial::render` — keep in lockstep until we drop
    # support for pre-0.23.1.
    if c.confidence == "low":
        return ""

    explanation = c.human_explanation or "denied"
    action = c.action

    if isinstance(action, SwitchTool):
        return f"Denied: {explanation}\nTry the `{action.tool}` tool instead."
    if isinstance(action, DownscopeTo):
        return f"Denied: {explanation}\nRetry under scope `{action.scope}`."
    if isinstance(action, RenameField):
        return (
            f"Denied: {explanation}\nRename `{action.from_}` → "
            f"`{action.to}` and retry."
        )
    if isinstance(action, RedactValue):
        return (
            f"Denied: {explanation}\nRemove the value at "
            f"`{action.json_path}` before retry."
        )
    if isinstance(action, SplitRequest):
        return (
            f"Denied: {explanation}\nSplit into batches of "
            f"≤ {action.max_items_per_batch}."
        )
    if isinstance(action, WaitAndRetry):
        suffix = f" ({action.window_label})" if action.window_label else ""
        return (
            f"Denied: {explanation}\nRetry after "
            f"{action.retry_after_seconds}s{suffix}."
        )
    if isinstance(action, SwitchEndpoint):
        return (
            f"Denied: {explanation}\nUse `{action.to_url}` instead of "
            f"`{action.from_url}`."
        )
    if isinstance(action, NoCorrection):
        return f"Denied: {explanation}"
    return f"Denied: {explanation}"


__all__ = [
    "CorrectiveAction",
    "CorrectiveActionVariant",
    "Confidence",
    "DownscopeTo",
    "NoCorrection",
    "RedactValue",
    "RenameField",
    "Source",
    "SplitRequest",
    "StructuredDenial",
    "SwitchEndpoint",
    "SwitchTool",
    "WaitAndRetry",
    "render_corrective_for_llm",
    "synthetic_denial",
]
