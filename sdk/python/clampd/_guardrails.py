"""Shared guardrail helpers for the Clampd Python SDK.

Extracted from __init__.py to reduce duplication across openai/anthropic/guard wrappers.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
from typing import Any

from clampd.client import (
    ClampdBlockedError,
    ClampdClient,
    ProxyResponse,
    SchemaInjectionWarning,
    scan_for_schema_injection,
)
from clampd.delegation import (
    DelegationContext,
    MAX_DELEGATION_DEPTH,
    enter_delegation,
    exit_delegation,
)
from clampd._errors import (
    ClampdDescriptorMismatchError,
    ClampdUnregisteredToolError,
)

logger = logging.getLogger("clampd")

# Import the SINGLE scope token context var from __init__ to avoid duplicate instances.
# Lazy import to avoid circular dependency — resolved at call time.
def _get_scope_token_var() -> contextvars.ContextVar[str]:
    import clampd
    return clampd._scope_token_var


def schema_injection_prescan(messages: list[dict[str, Any]]) -> None:
    """Check messages for schema injection attempts; raise if risk >= 0.85.

    Logs a warning for lower-risk detections.
    """
    warnings = scan_for_schema_injection(messages)
    if not warnings:
        return
    top = warnings[0]
    if top.risk_score >= 0.85:
        raise ClampdBlockedError(
            f"Schema injection detected: {top.alert_type} (pattern: {top.matched_pattern})",
            risk_score=top.risk_score,
        )
    else:
        logger.warning("Schema injection warning: %s", top)


def extract_prompt_text_openai(kwargs: dict[str, Any]) -> str:
    """Concatenate the user/tool/function messages from an OpenAI-format
    request into a single prompt-context string. Returns "" when nothing
    scannable is present.

    Used by both ``scan_input_openai`` (sent to /v1/scan-input) and the
    ``clampd.openai()`` wrapper (sent as ``prompt_context`` on each
    proxy call so the gateway's ``llm:input:prompt`` rules — R013/R014
    /R015/R031/R032/R038 — fire on tool-call traffic, not just on
    standalone scan_input calls).
    """
    messages = kwargs.get("messages") or []
    scannable = [m for m in messages if m.get("role") in ("user", "tool", "function")]
    return "\n".join(
        m.get("content", "") for m in scannable if isinstance(m.get("content"), str)
    )


def extract_prompt_text_anthropic(kwargs: dict[str, Any]) -> str:
    """Concatenate user/tool/function content blocks from an
    Anthropic-format request into a single prompt-context string.
    Handles both string content and list-of-content-blocks.
    """
    messages = kwargs.get("messages") or []
    scannable = [m for m in messages if m.get("role") in ("user", "tool", "function")]
    parts: list[str] = []
    for m in scannable:
        content = m.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            parts.append(json.dumps(content) if content else "")
    return "\n".join(filter(None, parts))


def scan_input_openai(
    client: ClampdClient,
    kwargs: dict[str, Any],
    fail_open: bool = False,
) -> None:
    """Run schema injection pre-scan + input scan on OpenAI-format messages."""
    messages = kwargs.get("messages") or []
    schema_injection_prescan(messages)
    text = extract_prompt_text_openai(kwargs)
    if not text.strip():
        return
    try:
        result = client.scan_input(text, message_count=len(messages))
        if not result.allowed:
            raise ClampdBlockedError(
                result.denial or "Input blocked by guardrail",
                risk_score=result.risk_score,
                response=result,
            )
    except ClampdBlockedError:
        raise
    except Exception as e:
        if not fail_open:
            raise
        logger.warning("Input scan failed (fail-open): %s", e)


def scan_input_anthropic(
    client: ClampdClient,
    kwargs: dict[str, Any],
    fail_open: bool = False,
) -> None:
    """Run schema injection pre-scan + input scan on Anthropic-format messages."""
    messages = kwargs.get("messages") or []
    schema_injection_prescan(messages)
    text = extract_prompt_text_anthropic(kwargs)
    if not text.strip():
        return
    try:
        result = client.scan_input(text, message_count=len(messages))
        if not result.allowed:
            raise ClampdBlockedError(
                result.denial or "Input blocked by guardrail",
                risk_score=result.risk_score,
                response=result,
            )
    except ClampdBlockedError:
        raise
    except Exception as e:
        if not fail_open:
            raise
        logger.warning("Input scan failed (fail-open): %s", e)


def scan_output_content(
    client: ClampdClient,
    content: str,
    fail_open: bool = False,
) -> None:
    """Scan output text for PII/secrets; raise ClampdBlockedError if blocked."""
    if not content:
        return
    try:
        result = client.scan_output(content)
        if not result.allowed:
            raise ClampdBlockedError(
                result.denial or "Output blocked by guardrail",
                risk_score=result.risk_score,
                response=result,
            )
    except ClampdBlockedError:
        raise
    except Exception as e:
        if not fail_open:
            raise
        logger.warning("Output scan failed (fail-open): %s", e)


def inspect_response(
    client: ClampdClient,
    tool_name: str,
    response_data: Any,
    request_id: str = "",
    fail_open: bool = False,
    scope_token: str = "",
) -> None:
    """Send a tool response through inspect + scan_output endpoints."""
    try:
        try:
            serializable = json.loads(json.dumps(response_data, default=str))
        except (TypeError, ValueError):
            serializable = str(response_data)
        resp = client.inspect(
            tool=tool_name,
            response_data=serializable,
            request_id=request_id,
            scope_token=scope_token,
        )
    except Exception as e:
        if fail_open:
            logger.warning("Clampd inspect error (fail-open): %s", e)
            return
        raise ClampdBlockedError(f"Response inspection failed: {e}") from e

    if not resp.allowed:
        raise ClampdBlockedError(
            resp.denial or "Response blocked",
            risk_score=resp.risk_score,
            response=resp,
        )

    try:
        text = (
            json.dumps(response_data, default=str)
            if not isinstance(response_data, str)
            else response_data
        )
        scan_resp = client.scan_output(text, request_id=request_id)
    except Exception as e:
        if fail_open:
            logger.warning("Clampd scan_output error (fail-open): %s", e)
            return
        raise ClampdBlockedError(f"Response scan failed: {e}") from e

    if not scan_resp.allowed:
        raise ClampdBlockedError(
            scan_resp.denial or "Response contains sensitive data",
            risk_score=scan_resp.risk_score,
            response=scan_resp,
        )


def extract_openai_tool_names(kwargs: dict[str, Any]) -> list[str] | None:
    """Extract tool names from OpenAI tools parameter for X-AG-Authorized-Tools."""
    tools = kwargs.get("tools")
    if not tools:
        return None
    names = []
    for t in tools:
        fn = t.get("function", {}) if isinstance(t, dict) else {}
        name = fn.get("name", "")
        if name:
            names.append(name)
    return names if names else None


def extract_anthropic_tool_names(kwargs: dict[str, Any]) -> list[str] | None:
    """Extract tool names from Anthropic tools parameter for X-AG-Authorized-Tools."""
    tools = kwargs.get("tools")
    if not tools:
        return None
    names = []
    for t in tools:
        name = t.get("name", "") if isinstance(t, dict) else ""
        if name:
            names.append(name)
    return names if names else None


# ── Callback-oriented helpers ────────────────────────────────────
#
# ADK, LangChain, and CrewAI integrations use a callback pattern that
# returns {error: ...} | None instead of raising ClampdBlockedError.
# These helpers provide the standard delegation + proxy + scope token +
# inspect + scanOutput pattern for that contract.
#

# Gateway error denial reasons that indicate a transient failure (not a policy denial)
_GATEWAY_ERROR_REASONS = frozenset({
    "gateway_timeout", "gateway_unreachable", "gateway_error",
    # NOTE: "circuit_breaker_open" intentionally excluded — sustained outage
    # should not allow failOpen bypass indefinitely.
})


_DESCRIPTOR_HASH_RE = re.compile(r"with hash ([0-9a-fA-F]+)")


def _raise_for_descriptor_errors(
    tool_name: str, resp: ProxyResponse | None
) -> None:
    """Translate gateway descriptor-related denials into typed exceptions.

    Three prefixes are recognised on ``ProxyResponse.denial_reason``:

      - ``tool_not_registered:`` / ``tool_not_classified:`` →
        :class:`ClampdUnregisteredToolError` (the descriptor is missing
        or unclassified — fix is to call ``register_tool``)
      - ``descriptor_hash_mismatch:`` →
        :class:`ClampdDescriptorMismatchError` (the descriptor exists,
        but the hash sent by this call doesn't match any approved
        version — fix is to approve the new hash in the dashboard)

    Any other denial reason is left to the caller (which should raise
    :class:`ClampdBlockedError`).
    """
    if not (resp and not resp.allowed and resp.denial_reason):
        return

    reason = resp.denial_reason
    if reason.startswith(("tool_not_registered:", "tool_not_classified:")):
        raise ClampdUnregisteredToolError(tool_name)

    if reason.startswith("descriptor_hash_mismatch:"):
        match = _DESCRIPTOR_HASH_RE.search(reason)
        attempted = match.group(1) if match else None
        raise ClampdDescriptorMismatchError(
            tool_name, attempted_hash=attempted,
        )


def _raise_if_unregistered(tool_name: str, resp: ProxyResponse | None) -> None:
    """Backward-compat alias for :func:`_raise_for_descriptor_errors`.

    Originally this only handled ``tool_not_registered`` /
    ``tool_not_classified`` prefixes. It now also raises
    :class:`ClampdDescriptorMismatchError` on
    ``descriptor_hash_mismatch:`` — kept under the old name so existing
    call sites keep working without touching every wrapper.
    """
    _raise_for_descriptor_errors(tool_name, resp)


def guard_tool_callback(
    client: ClampdClient,
    tool_name: str,
    args: dict[str, Any],
    *,
    target_url: str = "",
    fail_open: bool = False,
    tool_descriptor_hash: str | None = None,
    prompt_context: str | None = None,
) -> tuple[dict[str, Any] | None, str, ProxyResponse | None]:
    """Guard a tool call in callback context (ADK/CrewAI/LangChain).

    Enters delegation, calls proxy, stores scope token.

    When ``tool_descriptor_hash`` is provided, it is forwarded to
    ``client.proxy()`` so the gateway can verify the contract matches a
    previously-registered descriptor (rug-pull detection).

    Returns (error_dict | None, scope_token, proxy_response | None).
    - ``error_dict`` is ``None`` when allowed — proceed with execution.
    - ``error_dict`` populated means blocked — return to framework.
    - ``proxy_response`` is the raw gateway response (when one was
      received), so callers can pass it through to ``ClampdBlockedError``
      for richer telemetry. ``None`` on transient failure paths.

    Raises :class:`ClampdUnregisteredToolError` when the gateway reports
    that the tool descriptor is missing or unclassified — distinct from
    a policy block.
    """
    ctx, delegation_token = enter_delegation(client.agent_id)
    try:
        if ctx.depth > MAX_DELEGATION_DEPTH:
            return (
                {"error": f"Delegation chain too deep ({ctx.depth} > {MAX_DELEGATION_DEPTH})"},
                "",
                None,
            )
        if ctx.has_cycle():
            return (
                {"error": f"Delegation cycle detected: {' -> '.join(ctx.chain)}"},
                "",
                None,
            )

        try:
            result = client.proxy(
                tool=tool_name,
                params=args,
                target_url=target_url,
                prompt_context=prompt_context,
                tool_descriptor_hash=tool_descriptor_hash,
            )
        except Exception as e:
            if fail_open:
                logger.warning("Clampd gateway error (fail-open): %s", e)
                return None, "", None
            return (
                {"error": f"Security gateway error: {type(e).__name__}"},
                "",
                None,
            )

        # Translate gateway "you forgot to register this tool" into a
        # typed exception before building the generic error envelope.
        _raise_if_unregistered(tool_name, result)

        scope_token = result.scope_token or ""
        if result.allowed:
            _get_scope_token_var().set(scope_token)
            return None, scope_token, result

        # Not allowed — check if this is a gateway error with fail_open
        if fail_open and result.denial_reason in _GATEWAY_ERROR_REASONS:
            logger.warning("Clampd gateway error (fail-open): %s", result.denial_reason)
            return None, "", result

        return (
            {
                "error": f"Blocked by Clampd: {result.denial_reason}",
                "risk_score": result.risk_score,
            },
            "",
            result,
        )
    finally:
        exit_delegation(delegation_token)


def inspect_response_callback(
    client: ClampdClient,
    tool_name: str,
    response_data: Any,
    *,
    fail_open: bool = False,
    scope_token: str = "",
) -> dict[str, Any] | None:
    """Inspect a tool response in callback context (ADK/CrewAI/LangChain).

    Calls inspect() for anomaly detection, scope validation, and PII detection.
    PII/secrets scanning is handled server-side by the gateway's /v1/inspect
    endpoint — no separate scan_output() call needed here.

    Returns error_dict or None. When blocked, the error dict carries a
    ``"_response"`` key with the raw :class:`ProxyResponse` so callers can
    forward it to :class:`ClampdBlockedError` for richer telemetry
    (matched_rules, session_flags). The ``"_response"`` key is private —
    callers MUST treat it as opaque (it may be ``None`` on transient
    failure) and MUST NOT surface it to end users / framework return
    values.
    """
    try:
        serializable = (
            response_data
            if isinstance(response_data, (str, int, float, bool, type(None), dict, list))
            else str(response_data)
        )
        result = client.inspect(
            tool=tool_name, response_data=serializable, scope_token=scope_token,
        )
    except Exception as e:
        if fail_open:
            logger.warning("Clampd inspect error (fail-open): %s", e)
            return None
        return {
            "error": f"Response inspection error: {type(e).__name__}",
            "_response": None,
        }

    if not result.allowed:
        return {
            "error": f"Response blocked by Clampd: {result.denial_reason}",
            "risk_score": result.risk_score,
            "_response": result,
        }

    return None
