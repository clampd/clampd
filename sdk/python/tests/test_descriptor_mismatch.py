"""Tests for ClampdDescriptorMismatchError — typed exception raised when
the gateway reports the tool's ``descriptor_hash`` doesn't match any
approved version for that tool name.

Distinct from:
  - ``ClampdBlockedError`` — policy/risk denial against a known tool.
  - ``ClampdUnregisteredToolError`` — tool entirely unknown to the gateway.

A mismatch means the tool exists, but its current contract (name +
description + parameter schema) hashes to a value the dashboard hasn't
approved — typically a rug-pull-detection signal that needs a human
to approve the new descriptor.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd import ClampdDescriptorMismatchError, ClampdUnregisteredToolError
from clampd._guardrails import (
    _raise_for_descriptor_errors,
    _raise_if_unregistered,
    guard_tool_callback,
)
from clampd.client import ClampdBlockedError, ClampdClient, ProxyResponse


def _proxy_response(
    *,
    allowed: bool = False,
    denial_reason: str | None = None,
    risk_score: float = 1.0,
) -> ProxyResponse:
    return ProxyResponse(
        request_id="req-mismatch-1",
        allowed=allowed,
        risk_score=risk_score,
        denial_reason=denial_reason,
        latency_ms=1,
    )


@pytest.fixture(autouse=True)
def _isolate():
    clampd._reset()
    yield
    clampd._reset()


# ── _raise_for_descriptor_errors direct tests ─────────────────────────


class TestRaiseForDescriptorErrors:
    def test_raised_on_descriptor_hash_mismatch_prefix(self):
        resp = _proxy_response(
            denial_reason=(
                "descriptor_hash_mismatch: tool 'mcp_postgres_query' was "
                "called with hash 5587c5abcd1234ef but only a different "
                "hash is approved; approve 5587c5abcd1234ef in dashboard"
            )
        )
        with pytest.raises(ClampdDescriptorMismatchError) as excinfo:
            _raise_for_descriptor_errors("mcp_postgres_query", resp)
        assert excinfo.value.tool_name == "mcp_postgres_query"

    def test_attempted_hash_extracted_from_reason(self):
        """The 'with hash <X>' fragment must be parsed into ``attempted_hash``."""
        resp = _proxy_response(
            denial_reason=(
                "descriptor_hash_mismatch: tool 'foo' was called with hash "
                "deadbeefcafef00d1234 but only a different hash is approved"
            )
        )
        with pytest.raises(ClampdDescriptorMismatchError) as excinfo:
            _raise_for_descriptor_errors("foo", resp)
        assert excinfo.value.attempted_hash == "deadbeefcafef00d1234"

    def test_attempted_hash_is_none_when_reason_lacks_hash(self):
        """Absent the parseable fragment, ``attempted_hash`` falls back to None."""
        resp = _proxy_response(
            denial_reason="descriptor_hash_mismatch: hash mismatch (details elided)"
        )
        with pytest.raises(ClampdDescriptorMismatchError) as excinfo:
            _raise_for_descriptor_errors("foo", resp)
        assert excinfo.value.attempted_hash is None

    def test_not_raised_on_other_denial_reasons(self):
        resp = _proxy_response(denial_reason="Policy denied: PII detected")
        # Should NOT raise either typed error
        _raise_for_descriptor_errors("baz", resp)

    def test_not_raised_when_allowed(self):
        resp = _proxy_response(allowed=True, denial_reason=None)
        _raise_for_descriptor_errors("baz", resp)

    def test_not_raised_when_response_is_none(self):
        # Defensive: transient gateway failure path may pass None
        _raise_for_descriptor_errors("baz", None)

    def test_not_raised_when_allowed_with_reason(self):
        # Edge: allowed=True but somehow has a denial_reason — helper
        # checks ``not resp.allowed`` first.
        resp = _proxy_response(
            allowed=True,
            denial_reason="descriptor_hash_mismatch: stale",
        )
        _raise_for_descriptor_errors("baz", resp)

    def test_unregistered_prefix_still_raises_unregistered(self):
        """The same helper must keep handling the legacy unregistered case."""
        resp = _proxy_response(
            denial_reason="tool_not_registered: no descriptor for foo"
        )
        with pytest.raises(ClampdUnregisteredToolError):
            _raise_for_descriptor_errors("foo", resp)

    def test_legacy_alias_still_raises_descriptor_mismatch(self):
        """The old _raise_if_unregistered name now also handles mismatches."""
        resp = _proxy_response(
            denial_reason=(
                "descriptor_hash_mismatch: tool 'foo' was called with hash "
                "abcd1234 but only a different hash is approved"
            )
        )
        with pytest.raises(ClampdDescriptorMismatchError):
            _raise_if_unregistered("foo", resp)


# ── ClampdDescriptorMismatchError class shape ────────────────────────


class TestErrorClassShape:
    def test_does_not_subclass_blocked_error(self):
        """Critical: catching ``ClampdBlockedError`` must NOT swallow this.

        A descriptor-hash mismatch is a contract-drift signal that needs a
        human to act in the dashboard — surfacing it as a generic policy
        block buries the actionable hint.
        """
        assert not issubclass(
            ClampdDescriptorMismatchError, ClampdBlockedError
        )

        # And the converse — confirm a try/except for ClampdBlockedError
        # lets the typed mismatch error propagate.
        resp = _proxy_response(
            denial_reason=(
                "descriptor_hash_mismatch: tool 'foo' was called with hash "
                "5587c5 but only a different hash is approved"
            )
        )
        with pytest.raises(ClampdDescriptorMismatchError):
            try:
                _raise_for_descriptor_errors("foo", resp)
            except ClampdBlockedError:
                pytest.fail(
                    "ClampdDescriptorMismatchError was swallowed by "
                    "`except ClampdBlockedError`"
                )

    def test_does_not_subclass_unregistered_error(self):
        """The two typed errors are siblings — neither inherits from the
        other. Callers may want to handle ``unregistered`` and ``mismatch``
        with different remediation logic."""
        assert not issubclass(
            ClampdDescriptorMismatchError, ClampdUnregisteredToolError
        )
        assert not issubclass(
            ClampdUnregisteredToolError, ClampdDescriptorMismatchError
        )

    def test_default_hint_contains_dashboard_action(self):
        """The default hint must point the developer at the dashboard."""
        err = ClampdDescriptorMismatchError(
            "my.tool", attempted_hash="5587c5abcd1234ef0011223344556677",
        )
        assert err.tool_name == "my.tool"
        assert err.attempted_hash == "5587c5abcd1234ef0011223344556677"
        assert "dashboard" in err.hint.lower()
        assert "my.tool" in err.hint
        # First 16 chars of the hash should be embedded for quick scanning
        assert "5587c5abcd1234ef" in err.hint
        # The Exception message embeds the hint too.
        assert "my.tool" in str(err)
        assert "does not match" in str(err)

    def test_default_hint_without_hash(self):
        """When no hash is available, the hint still mentions the dashboard."""
        err = ClampdDescriptorMismatchError("my.tool")
        assert err.attempted_hash is None
        assert "dashboard" in err.hint.lower()
        assert "my.tool" in err.hint

    def test_custom_hint_message(self):
        err = ClampdDescriptorMismatchError(
            "x", attempted_hash="abc", hint="See docs/rotate-hash.md",
        )
        assert err.hint == "See docs/rotate-hash.md"
        assert "See docs/rotate-hash.md" in str(err)


# ── guard_tool_callback integration ──────────────────────────────────


class TestGuardToolCallbackIntegration:
    """``guard_tool_callback`` is the shared helper that ADK / LangChain /
    CrewAI run through. ``ClampdDescriptorMismatchError`` MUST propagate
    out of it (rather than being wrapped in a generic ``error`` envelope)
    so framework wrappers can re-raise as a typed exception.
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
                denial_reason=(
                    "descriptor_hash_mismatch: tool 'search' was called "
                    "with hash 5587c5abcd1234ef but only a different hash "
                    "is approved"
                )
            )
        )

        with pytest.raises(ClampdDescriptorMismatchError) as excinfo:
            guard_tool_callback(client, "search", {"q": "x"})
        assert excinfo.value.tool_name == "search"
        assert excinfo.value.attempted_hash == "5587c5abcd1234ef"

    def test_propagates_through_langchain_callback(self):
        """The LangChain ``on_tool_start`` path must surface the typed
        error and NOT re-wrap it as ``ClampdBlockedError``."""
        from clampd.langchain_callback import ClampdCallbackHandler

        client = self._make_client()
        client.proxy = MagicMock(
            return_value=_proxy_response(
                denial_reason=(
                    "descriptor_hash_mismatch: tool 'web_search' was called "
                    "with hash deadbeef1234 but only a different hash is approved"
                )
            )
        )
        handler = ClampdCallbackHandler(client)

        with pytest.raises(ClampdDescriptorMismatchError) as excinfo:
            handler.on_tool_start(
                {"name": "web_search", "description": "Search"},
                input_str='{"q": "hello"}',
            )
        assert excinfo.value.tool_name == "web_search"
        assert excinfo.value.attempted_hash == "deadbeef1234"

    def test_other_blocks_do_not_become_descriptor_mismatch_error(self):
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
        except ClampdDescriptorMismatchError:
            pytest.fail(
                "Policy denial accidentally surfaced as "
                "ClampdDescriptorMismatchError"
            )
        except ClampdBlockedError:
            pass
