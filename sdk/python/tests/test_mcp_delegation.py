"""Tests for MCP proxy delegation context propagation."""

from unittest.mock import MagicMock, patch

import pytest

from clampd.client import ClampdClient, ProxyResponse
from clampd.delegation import get_delegation
from clampd.mcp_server import ClampdMCPProxy


def _make_proxy_response(allowed=True, risk_score=0.1, denial_reason=None):
    return ProxyResponse(
        request_id="req-test",
        allowed=allowed,
        risk_score=risk_score,
        denial_reason=denial_reason,
        latency_ms=5,
    )


def _make_mock_client():
    """Create a ClampdClient with mocked internals."""
    with patch.object(ClampdClient, "__init__", lambda self, **kw: None):
        client = ClampdClient.__new__(ClampdClient)
        client.gateway_url = "http://test:8080"
        client.agent_id = "agent-b-uuid"
        client.api_key = "test-key"
        client._jwt = "fake"
        client._http = MagicMock()
    return client


class TestMCPDelegationPropagation:
    """Test that ClampdMCPProxy correctly enters/exits delegation context."""

    def _make_proxy(self, parent_agent_id=None):
        return ClampdMCPProxy(
            gateway_url="http://test:8080",
            agent_id="agent-b-uuid",
            api_key="test-key",
            downstream_command="echo hello",
            parent_agent_id=parent_agent_id,
        )

    def test_check_with_clampd_sets_delegation_without_parent(self):
        """Without parent_agent_id, delegation chain has just this agent."""
        proxy = self._make_proxy()

        captured_ctx = None

        def mock_proxy(tool, params, target_url, prompt_context=None):
            nonlocal captured_ctx
            captured_ctx = get_delegation()
            return _make_proxy_response()

        client = _make_mock_client()
        client.proxy = mock_proxy

        result = proxy._check_with_clampd(client, "read_file", {"path": "/tmp"})

        assert result.allowed is True
        assert captured_ctx is not None
        assert captured_ctx.chain == ["agent-b-uuid"]
        assert captured_ctx.caller_agent_id is None

        # Delegation context should be cleaned up after the call
        assert get_delegation() is None

    def test_check_with_clampd_sets_delegation_with_parent(self):
        """With parent_agent_id, delegation chain includes parent -> agent."""
        proxy = self._make_proxy(parent_agent_id="agent-a-uuid")

        captured_ctx = None

        def mock_proxy(tool, params, target_url, prompt_context=None):
            nonlocal captured_ctx
            captured_ctx = get_delegation()
            return _make_proxy_response()

        client = _make_mock_client()
        client.proxy = mock_proxy

        result = proxy._check_with_clampd(client, "read_file", {"path": "/tmp"})

        assert result.allowed is True
        assert captured_ctx is not None
        assert captured_ctx.chain == ["agent-a-uuid", "agent-b-uuid"]
        assert captured_ctx.caller_agent_id == "agent-a-uuid"
        assert captured_ctx.trace_id  # should have a trace ID

        # Delegation context cleaned up
        assert get_delegation() is None

    def test_delegation_context_cleaned_on_error(self):
        """Delegation context is cleaned up even when gateway call raises."""
        proxy = self._make_proxy(parent_agent_id="agent-a-uuid")

        def mock_proxy(tool, params, target_url, prompt_context=None):
            raise Exception("Gateway down")

        client = _make_mock_client()
        client.proxy = mock_proxy

        with pytest.raises(Exception, match="Gateway down"):
            proxy._check_with_clampd(client, "read_file", {"path": "/tmp"})

        # Context must still be cleaned up
        assert get_delegation() is None

    def test_dry_run_mode_sets_delegation(self):
        """Dry-run mode also sets delegation context for verify calls."""
        proxy = self._make_proxy(parent_agent_id="agent-a-uuid")
        proxy.dry_run = True

        captured_ctx = None

        def mock_verify(tool, params, target_url):
            nonlocal captured_ctx
            captured_ctx = get_delegation()
            return _make_proxy_response()

        client = _make_mock_client()
        client.verify = mock_verify

        result = proxy._check_with_clampd(client, "read_file", {"path": "/tmp"})

        assert result.allowed is True
        assert captured_ctx is not None
        assert captured_ctx.chain == ["agent-a-uuid", "agent-b-uuid"]

    def test_delegation_trace_ids_differ_per_call(self):
        """Each MCP tool call gets a fresh delegation trace ID."""
        proxy = self._make_proxy(parent_agent_id="agent-a-uuid")

        trace_ids = []

        def mock_proxy(tool, params, target_url, prompt_context=None):
            ctx = get_delegation()
            if ctx:
                trace_ids.append(ctx.trace_id)
            return _make_proxy_response()

        client = _make_mock_client()
        client.proxy = mock_proxy

        proxy._check_with_clampd(client, "tool1", {})
        proxy._check_with_clampd(client, "tool2", {})

        assert len(trace_ids) == 2
        # Each call starts a fresh delegation, so trace IDs should differ
        assert trace_ids[0] != trace_ids[1]

    def test_constructor_stores_parent_agent_id(self):
        proxy = self._make_proxy(parent_agent_id="parent-123")
        assert proxy.parent_agent_id == "parent-123"

    def test_constructor_without_parent_agent_id(self):
        proxy = self._make_proxy()
        assert proxy.parent_agent_id is None
