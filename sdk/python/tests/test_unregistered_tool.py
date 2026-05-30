"""Tests for ClampdUnregisteredToolError — typed exception raised when the
gateway reports a tool descriptor is missing or unclassified.

Distinct from ``ClampdBlockedError`` (which is for policy denials): callers
that catch ``ClampdBlockedError`` MUST NOT swallow this — it indicates a
configuration bug, not a runtime block.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd import ClampdUnregisteredToolError
from clampd._guardrails import _raise_if_unregistered, guard_tool_callback
from clampd._corrective import synthetic_denial
from clampd.client import ClampdBlockedError, ClampdClient, ProxyResponse


def _proxy_response(
    *,
    allowed: bool = False,
    denial_reason: str | None = None,
    risk_score: float = 1.0,
) -> ProxyResponse:
    denial = (
        synthetic_denial("TEST/unregistered", denial_reason)
        if denial_reason
        else None
    )
    return ProxyResponse(
        request_id="req-unreg-1",
        allowed=allowed,
        risk_score=risk_score,
        denial=denial,
        latency_ms=1,
    )


@pytest.fixture(autouse=True)
def _isolate():
    clampd._reset()
    yield
    clampd._reset()


# ── _raise_if_unregistered direct tests ────────────────────────────────


class TestRaiseIfUnregistered:
    def test_raised_on_tool_not_registered_prefix(self):
        resp = _proxy_response(
            denial_reason="tool_not_registered: no descriptor for foo"
        )
        with pytest.raises(ClampdUnregisteredToolError) as excinfo:
            _raise_if_unregistered("foo", resp)
        assert excinfo.value.tool_name == "foo"

    def test_raised_on_tool_not_classified_prefix(self):
        resp = _proxy_response(
            denial_reason="tool_not_classified: no taxonomy mapping"
        )
        with pytest.raises(ClampdUnregisteredToolError) as excinfo:
            _raise_if_unregistered("bar", resp)
        assert excinfo.value.tool_name == "bar"

    def test_not_raised_for_other_denial_reasons(self):
        resp = _proxy_response(denial_reason="Policy denied: PII detected")
        # Should NOT raise
        _raise_if_unregistered("baz", resp)

    def test_not_raised_when_allowed(self):
        resp = _proxy_response(allowed=True, denial_reason=None)
        _raise_if_unregistered("baz", resp)

    def test_not_raised_when_response_is_none(self):
        # Defensive: transient gateway failure path may pass None
        _raise_if_unregistered("baz", None)

    def test_not_raised_when_allowed_with_reason(self):
        # Edge: allowed=True but somehow has a denial_reason (exempt path).
        # The helper looks at `not resp.allowed` first, so this should NOT raise.
        resp = _proxy_response(
            allowed=True,
            denial_reason="tool_not_registered: stale",
        )
        _raise_if_unregistered("baz", resp)

    def test_does_not_subclass_blocked_error(self):
        """Critical: catching ``ClampdBlockedError`` must NOT swallow this.

        Treating an unregistered-tool error as a generic block is a config bug
        that gets silently retried until the developer notices.
        """
        assert not issubclass(ClampdUnregisteredToolError, ClampdBlockedError)

        # And the converse — ensure a try/except for ClampdBlockedError lets
        # ClampdUnregisteredToolError propagate.
        resp = _proxy_response(denial_reason="tool_not_registered: foo")
        with pytest.raises(ClampdUnregisteredToolError):
            try:
                _raise_if_unregistered("foo", resp)
            except ClampdBlockedError:
                pytest.fail(
                    "ClampdUnregisteredToolError was swallowed by "
                    "`except ClampdBlockedError`"
                )

    def test_default_hint_message(self):
        """The default hint must point the developer at register_tool()."""
        err = ClampdUnregisteredToolError("my.tool")
        assert err.tool_name == "my.tool"
        assert "register_tool" in err.hint
        assert "my.tool" in err.hint
        # The Exception message embeds the hint too.
        assert "my.tool" in str(err)
        assert "not registered" in str(err)

    def test_custom_hint_message(self):
        err = ClampdUnregisteredToolError("x", hint="See docs/onboarding.md")
        assert err.hint == "See docs/onboarding.md"
        assert "See docs/onboarding.md" in str(err)


# ── guard_tool_callback integration ───────────────────────────────────


class TestGuardToolCallbackIntegration:
    """``guard_tool_callback`` is the shared helper that ADK / LangChain /
    CrewAI run through. ``ClampdUnregisteredToolError`` MUST propagate out
    of it (rather than being wrapped in a generic ``error`` envelope) so
    framework wrappers can re-raise as a typed exception.
    """

    def _make_client(self) -> ClampdClient:
        with patch("clampd.client.httpx.Client"):
            return ClampdClient(
                agent_id="test-agent", gateway_url="http://test:8080"
            )

    def test_propagates_from_guard_tool_callback(self):
        client = self._make_client()
        client.proxy = MagicMock(
            return_value=_proxy_response(
                denial_reason="tool_not_registered: search"
            )
        )

        with pytest.raises(ClampdUnregisteredToolError) as excinfo:
            guard_tool_callback(client, "search", {"q": "x"})
        assert excinfo.value.tool_name == "search"

    def test_propagates_through_langchain_callback(self):
        """The LangChain ``on_tool_start`` path must surface the typed
        error and NOT re-wrap it as ``ClampdBlockedError``."""
        from clampd.langchain_callback import ClampdCallbackHandler

        client = self._make_client()
        client.proxy = MagicMock(
            return_value=_proxy_response(
                denial_reason="tool_not_classified: web_search has no scope"
            )
        )
        handler = ClampdCallbackHandler(client)

        with pytest.raises(ClampdUnregisteredToolError) as excinfo:
            handler.on_tool_start(
                {"name": "web_search", "description": "Search"},
                input_str='{"q": "hello"}',
            )
        assert excinfo.value.tool_name == "web_search"

    def test_other_blocks_do_not_become_unregistered_error(self):
        """A normal policy block must remain a ClampdBlockedError, not
        accidentally trigger the new typed exception."""
        from clampd.langchain_callback import ClampdCallbackHandler

        client = self._make_client()
        client.proxy = MagicMock(
            return_value=_proxy_response(
                denial_reason="Policy denied: rate limit exceeded"
            )
        )
        handler = ClampdCallbackHandler(client)

        with pytest.raises(ClampdBlockedError):
            handler.on_tool_start(
                {"name": "web_search", "description": "Search"},
                input_str="{}",
            )
        # Belt-and-braces: confirm it's NOT the typed flavour.
        try:
            handler.on_tool_start(
                {"name": "web_search", "description": "Search"},
                input_str="{}",
            )
        except ClampdUnregisteredToolError:
            pytest.fail(
                "Policy denial accidentally surfaced as "
                "ClampdUnregisteredToolError"
            )
        except ClampdBlockedError:
            pass
