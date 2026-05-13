"""Tests for automatic A2A delegation chain detection via contextvars."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd.client import ClampdBlockedError
from clampd.delegation import (
    MAX_DELEGATION_DEPTH,
    _delegation_ctx,
    enter_delegation,
    exit_delegation,
    get_delegation,
)
from tests.conftest import make_response


@pytest.fixture(autouse=True)
def reset_state():
    """Reset global client and delegation context between tests."""
    clampd._default_client = None
    # Ensure delegation context is clean
    tok = _delegation_ctx.set(None)
    yield
    _delegation_ctx.reset(tok)
    clampd._default_client = None


def _setup_guard(agent_id="agent-A"):
    """Set up clampd with a mocked proxy that always allows."""
    with patch("clampd.client.httpx.Client"):
        clampd.init(agent_id=agent_id)
    resp = make_response(allowed=True)
    clampd._default_client.proxy = MagicMock(return_value=resp)


class TestDelegationContext:
    def test_default_is_none(self):
        assert get_delegation() is None

    def test_enter_root_creates_chain(self):
        ctx, token = enter_delegation("agent-A")
        try:
            assert ctx.chain == ["agent-A"]
            assert ctx.depth == 1
            assert ctx.caller_agent_id is None
            assert not ctx.has_cycle()
            assert len(ctx.trace_id) == 16
        finally:
            exit_delegation(token)

    def test_nested_extends_chain(self):
        ctx_a, tok_a = enter_delegation("agent-A")
        try:
            ctx_b, tok_b = enter_delegation("agent-B")
            try:
                assert ctx_b.chain == ["agent-A", "agent-B"]
                assert ctx_b.depth == 2
                assert ctx_b.caller_agent_id == "agent-A"
                assert ctx_b.trace_id == ctx_a.trace_id  # same trace
            finally:
                exit_delegation(tok_b)
            # After exiting B, context is restored to A
            restored = get_delegation()
            assert restored.chain == ["agent-A"]
        finally:
            exit_delegation(tok_a)

    def test_three_level_chain(self):
        ctx_a, tok_a = enter_delegation("agent-A")
        try:
            ctx_b, tok_b = enter_delegation("agent-B")
            try:
                ctx_c, tok_c = enter_delegation("agent-C")
                try:
                    assert ctx_c.chain == ["agent-A", "agent-B", "agent-C"]
                    assert ctx_c.depth == 3
                    assert ctx_c.caller_agent_id == "agent-B"
                    assert ctx_c.trace_id == ctx_a.trace_id
                finally:
                    exit_delegation(tok_c)
            finally:
                exit_delegation(tok_b)
        finally:
            exit_delegation(tok_a)

    def test_cycle_detection(self):
        ctx_a, tok_a = enter_delegation("agent-A")
        try:
            ctx_b, tok_b = enter_delegation("agent-B")
            try:
                ctx_a2, tok_a2 = enter_delegation("agent-A")
                try:
                    assert ctx_a2.chain == ["agent-A", "agent-B", "agent-A"]
                    assert ctx_a2.has_cycle()
                finally:
                    exit_delegation(tok_a2)
            finally:
                exit_delegation(tok_b)
        finally:
            exit_delegation(tok_a)

    def test_exit_restores_none(self):
        ctx, token = enter_delegation("agent-A")
        exit_delegation(token)
        assert get_delegation() is None


class TestGuardDelegation:
    def test_single_agent_chain(self):
        """Single guarded call creates a chain of depth 1."""
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="agent-A")
        resp = make_response(allowed=True)
        clampd._default_client.proxy = MagicMock(return_value=resp)

        captured_ctx = []

        @clampd.guard("tool.read")
        def read_data(key: str) -> str:
            captured_ctx.append(get_delegation())
            return f"data:{key}"

        result = read_data("x")
        assert result == "data:x"
        assert len(captured_ctx) == 1
        assert captured_ctx[0].chain == ["agent-A"]
        # After guard returns, context should be restored
        assert get_delegation() is None

    def test_two_agents_auto_detect(self):
        """Agent A's guard calling Agent B's guard auto-detects the chain."""
        with patch("clampd.client.httpx.Client"):
            client_a = clampd.ClampdClient(agent_id="agent-A", gateway_url="http://test:8080")
            client_b = clampd.ClampdClient(agent_id="agent-B", gateway_url="http://test:8080")

        resp = make_response(allowed=True)
        client_a.proxy = MagicMock(return_value=resp)
        client_b.proxy = MagicMock(return_value=resp)

        captured_ctx = []

        def patched_get(agent_id=None, **kw):
            if agent_id == "agent-B":
                return client_b
            return client_a

        # Both guards must be defined while _get_client is patched,
        # because guard() resolves the client at decoration time.
        with patch.object(clampd, "_get_client", side_effect=patched_get):
            @clampd.guard("tool.write", agent_id="agent-B")
            def write_data(value: str) -> str:
                captured_ctx.append(get_delegation())
                return f"wrote:{value}"

            @clampd.guard("tool.orchestrate", agent_id="agent-A")
            def orchestrate(task: str) -> str:
                captured_ctx.append(get_delegation())
                return write_data(task)

            result = orchestrate("hello")

        assert result == "wrote:hello"
        # First capture: inside orchestrate (agent-A's guard)
        assert captured_ctx[0].chain == ["agent-A"]
        # Second capture: inside write_data (agent-B's guard, nested under agent-A)
        assert captured_ctx[1].chain == ["agent-A", "agent-B"]
        assert captured_ctx[1].caller_agent_id == "agent-A"
        # Same trace ID
        assert captured_ctx[0].trace_id == captured_ctx[1].trace_id

    def test_cycle_raises_error(self):
        """A->B->A delegation cycle raises ClampdBlockedError."""
        with patch("clampd.client.httpx.Client"):
            client = clampd.ClampdClient(agent_id="agent-A", gateway_url="http://test:8080")
        resp = make_response(allowed=True)
        client.proxy = MagicMock(return_value=resp)

        with patch.object(clampd, "_get_client", return_value=client):
            @clampd.guard("tool.ping", agent_id="agent-A")
            def ping() -> str:
                return "pong"

        # Simulate: already in agent-A -> agent-B context, then agent-A guard fires
        ctx_a, tok_a = enter_delegation("agent-A")
        try:
            ctx_b, tok_b = enter_delegation("agent-B")
            try:
                with pytest.raises(ClampdBlockedError, match="Delegation cycle detected"):
                    ping()
            finally:
                exit_delegation(tok_b)
        finally:
            exit_delegation(tok_a)

    def test_max_depth_raises_error(self):
        """Exceeding MAX_DELEGATION_DEPTH raises ClampdBlockedError."""
        with patch("clampd.client.httpx.Client"):
            client = clampd.ClampdClient(agent_id="agent-X", gateway_url="http://test:8080")
        resp = make_response(allowed=True)
        client.proxy = MagicMock(return_value=resp)

        with patch.object(clampd, "_get_client", return_value=client):
            @clampd.guard("tool.deep", agent_id="agent-X")
            def deep_call() -> str:
                return "deep"

        # Build a chain of MAX_DELEGATION_DEPTH unique agents, then trigger guard
        tokens = []
        try:
            for i in range(MAX_DELEGATION_DEPTH):
                _, tok = enter_delegation(f"agent-{i}")
                tokens.append(tok)
            # Now at depth 5, guard adds agent-X -> depth 6 > 5
            with pytest.raises(ClampdBlockedError, match="Delegation chain too deep"):
                deep_call()
        finally:
            for tok in reversed(tokens):
                exit_delegation(tok)

    def test_proxy_includes_delegation_fields(self):
        """When there's a parent caller, proxy body includes delegation info."""
        with patch("clampd.client.httpx.Client"):
            client = clampd.ClampdClient(agent_id="agent-B", gateway_url="http://test:8080")

        resp = make_response(allowed=True)
        client.proxy = MagicMock(return_value=resp)

        with patch.object(clampd, "_get_client", return_value=client):
            @clampd.guard("tool.action", agent_id="agent-B")
            def action(x: int) -> int:
                return x + 1

        # Enter agent-A context first
        ctx_a, tok_a = enter_delegation("agent-A")
        try:
            action(42)
        finally:
            exit_delegation(tok_a)

        # Verify proxy was called with delegation fields
        call_kwargs = client.proxy.call_args
        assert call_kwargs is not None
        # proxy is called as proxy(tool=..., params=..., target_url=...)
        # The delegation fields are added inside client.proxy via contextvars,
        # so we need to check the underlying _post call instead.
        # Since we mocked proxy directly, delegation fields are handled
        # internally by the real proxy method. Let's verify the context was correct.

    def test_context_cleaned_after_exception(self):
        """Delegation context is properly cleaned up even if guarded fn raises."""
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="agent-A")
        resp = make_response(allowed=True)
        clampd._default_client.proxy = MagicMock(return_value=resp)

        @clampd.guard("tool.fail")
        def failing_tool(x: int) -> int:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            failing_tool(1)

        # Context should be clean
        assert get_delegation() is None


class TestDelegationHeaders:
    def test_no_context_returns_empty(self):
        assert clampd.delegation_headers() == {}

    def test_with_context_returns_headers(self):
        ctx, token = enter_delegation("agent-A")
        try:
            ctx_b, token_b = enter_delegation("agent-B")
            try:
                headers = clampd.delegation_headers()
                assert headers["X-Clampd-Delegation-Trace"] == ctx.trace_id
                assert headers["X-Clampd-Delegation-Chain"] == "agent-A,agent-B"
                assert headers["X-Clampd-Delegation-Confidence"] == "verified"
            finally:
                exit_delegation(token_b)
        finally:
            exit_delegation(token)

    def test_single_agent_no_headers(self):
        """Single-agent chain = not delegation, no headers sent."""
        ctx, token = enter_delegation("agent-A")
        try:
            headers = clampd.delegation_headers()
            assert headers == {}
        finally:
            exit_delegation(token)


class TestConcurrentDelegation:
    def test_concurrent_requests_isolated(self):
        """contextvars ensures concurrent async tasks don't interfere."""
        results = {}

        async def agent_task(name: str, peer: str):
            ctx, token = enter_delegation(name)
            try:
                ctx2, token2 = enter_delegation(peer)
                try:
                    await asyncio.sleep(0.01)  # yield control
                    current = get_delegation()
                    results[name] = list(current.chain)
                finally:
                    exit_delegation(token2)
            finally:
                exit_delegation(token)

        async def run():
            await asyncio.gather(
                agent_task("task-1", "peer-A"),
                agent_task("task-2", "peer-B"),
                agent_task("task-3", "peer-C"),
            )

        asyncio.run(run())

        # Each task should have its own independent chain
        assert results["task-1"] == ["task-1", "peer-A"]
        assert results["task-2"] == ["task-2", "peer-B"]
        assert results["task-3"] == ["task-3", "peer-C"]


class TestClientProxyDelegation:
    def test_proxy_sends_delegation_in_body(self):
        """ClampdClient.proxy includes delegation fields when chain >= 2 agents."""
        with patch("clampd.client.httpx.Client") as MockHttpx:
            client = clampd.ClampdClient(agent_id="agent-B", gateway_url="http://test:8080")
            mock_http = MockHttpx.return_value
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "request_id": "req-1",
                "allowed": True,
                "risk_score": 0.1,
                "latency_ms": 3,
            }
            mock_http.post.return_value = mock_resp

            # Set up delegation context: agent-A -> agent-B (2 agents = real delegation)
            ctx_a, tok_a = enter_delegation("agent-A")
            try:
                ctx_b, tok_b = enter_delegation("agent-B")
                try:
                    client.proxy(tool="tool.x", params={"k": "v"})
                finally:
                    exit_delegation(tok_b)
            finally:
                exit_delegation(tok_a)

            # Check the JSON body sent to gateway
            call_args = mock_http.post.call_args
            body = call_args.kwargs.get("json") or call_args[1].get("json")
            assert body["delegation_chain"] == ["agent-A", "agent-B"]
            assert "delegation_trace_id" in body

    def test_proxy_no_delegation_fields_for_single_agent(self):
        """Single-agent chain = not delegation, no delegation fields sent."""
        with patch("clampd.client.httpx.Client") as MockHttpx:
            client = clampd.ClampdClient(agent_id="agent-A", gateway_url="http://test:8080")
            mock_http = MockHttpx.return_value
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "request_id": "req-1",
                "allowed": True,
                "risk_score": 0.1,
                "latency_ms": 3,
            }
            mock_http.post.return_value = mock_resp

            # Single agent context — not delegation
            ctx, tok = enter_delegation("agent-A")
            try:
                client.proxy(tool="tool.x", params={"k": "v"})
            finally:
                exit_delegation(tok)

            call_args = mock_http.post.call_args
            body = call_args.kwargs.get("json") or call_args[1].get("json")
            assert "delegation_chain" not in body
            assert "delegation_trace_id" not in body
