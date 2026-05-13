"""Tests for full ProxyResponse preservation through ClampdBlockedError.

Pre-change, the langchain/crewai callback paths would raise
``ClampdBlockedError(reason)`` and lose the rich gateway response (matched
rules, request id, session flags). They now forward the raw
``ProxyResponse`` via the ``response=`` kwarg so callers can introspect
the full picture.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd.client import ClampdBlockedError, ClampdClient, ProxyResponse
from clampd.crewai_callback import ClampdCrewAIGuard
from clampd.langchain_callback import ClampdCallbackHandler


def _rich_blocked_response() -> ProxyResponse:
    """A blocked ProxyResponse with all the telemetry fields populated."""
    return ProxyResponse(
        request_id="req_1",
        allowed=False,
        risk_score=0.93,
        denial_reason="Sensitive data exfiltration attempt",
        matched_rules=["R002"],
        session_flags=["sticky_taint"],
        latency_ms=12,
    )


def _make_client() -> ClampdClient:
    with patch("clampd.client.httpx.Client"):
        return ClampdClient(
            agent_id="test-agent", gateway_url="http://test:8080"
        )


@pytest.fixture(autouse=True)
def _isolate():
    clampd._reset()
    yield
    clampd._reset()


# ── Langchain callback ────────────────────────────────────────────────


class TestLangchainCallbackResponse:
    def test_langchain_callback_attaches_response(self):
        """on_tool_start must raise ClampdBlockedError with the full
        ProxyResponse attached — not just the reason string."""
        client = _make_client()
        rich = _rich_blocked_response()
        client.proxy = MagicMock(return_value=rich)
        handler = ClampdCallbackHandler(client)

        with pytest.raises(ClampdBlockedError) as excinfo:
            handler.on_tool_start(
                {"name": "exfil_tool", "description": "uh oh"},
                input_str='{"data": "creditcard"}',
            )

        err = excinfo.value
        # Same object — no copying / reconstruction.
        assert err.response is rich
        # Convenience accessors that ClampdBlockedError populates from the
        # response in __init__.
        assert err.matched_rules == ["R002"]
        assert err.session_flags == ["sticky_taint"]
        # The response carries the request id for log correlation.
        assert err.response is not None
        assert err.response.request_id == "req_1"
        # And the human-readable message includes rules + session info
        # (build_message format).
        msg = str(err)
        assert "R002" in msg
        assert "sticky_taint" in msg


# ── CrewAI callback ───────────────────────────────────────────────────


class TestCrewAICallbackResponse:
    """CrewAI's step_callback funnels through ``_guard_and_raise``, which
    must also forward the full ProxyResponse onto ClampdBlockedError."""

    def test_crewai_callback_attaches_response(self):
        client = _make_client()
        rich = _rich_blocked_response()
        client.proxy = MagicMock(return_value=rich)
        guard = ClampdCrewAIGuard(client)

        step = MagicMock()
        step.tool = "exfil_tool"
        step.tool_input = {"data": "creditcard"}
        step.tool_description = "uh oh"

        with pytest.raises(ClampdBlockedError) as excinfo:
            guard.step_callback(step)

        err = excinfo.value
        assert err.response is rich
        assert err.matched_rules == ["R002"]
        assert err.session_flags == ["sticky_taint"]
        assert err.response is not None
        assert err.response.request_id == "req_1"

    def test_crewai_guard_and_raise_direct(self):
        """Smoke test the inner helper directly — same contract."""
        client = _make_client()
        rich = _rich_blocked_response()
        client.proxy = MagicMock(return_value=rich)
        guard = ClampdCrewAIGuard(client)

        with pytest.raises(ClampdBlockedError) as excinfo:
            guard._guard_and_raise("exfil_tool", {"data": "x"})
        assert excinfo.value.response is rich


# ── Pre-existing @clampd.guard regression ─────────────────────────────


class TestGuardDecoratorResponse:
    """``@clampd.guard`` already attached the full response pre-change.
    Quick regression so a refactor doesn't accidentally drop the kwarg.
    """

    def test_guard_decorator_unchanged(self, monkeypatch):
        # Avoid CLAMPD_AGENT_ID requirement
        monkeypatch.setenv("CLAMPD_AGENT_ID", "dec-agent")

        client = _make_client()
        rich = _rich_blocked_response()
        client.proxy = MagicMock(return_value=rich)

        # Patch _get_client so the decorator picks up our mocked client.
        with patch("clampd._get_client", return_value=client):

            @clampd.guard("exfil_tool")
            def do_thing(arg: str) -> str:
                return f"processed {arg}"

            with pytest.raises(ClampdBlockedError) as excinfo:
                do_thing("payload")

        err = excinfo.value
        assert err.response is rich
        assert err.matched_rules == ["R002"]
        assert err.session_flags == ["sticky_taint"]


# ── Sanity: ClampdBlockedError fields when no response provided ───────


class TestBlockedErrorWithoutResponse:
    """If a caller still raises ClampdBlockedError without a ``response``
    kwarg, the convenience attributes degrade to safe empty defaults — no
    AttributeError at log time."""

    def test_no_response_defaults(self):
        err = ClampdBlockedError("denied", risk_score=0.5)
        assert err.response is None
        assert err.matched_rules == []
        assert err.session_flags == []
        # Message still well-formed.
        assert "denied" in str(err)
