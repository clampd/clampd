"""Tests for B1-B4 critical bug fixes: streaming, async, token race, resource leak."""

import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import clampd
from clampd import _scope_token_var
from clampd.client import AsyncClampdClient, ClampdBlockedError
from tests.conftest import make_response


@pytest.fixture(autouse=True)
def reset_global():
    """Reset global client between tests."""
    clampd._default_client = None
    yield
    clampd._default_client = None


def _mock_proxy(allowed=True, risk_score=0.1, denial_reason=None, scope_token=None):
    resp = make_response(allowed=allowed, risk_score=risk_score, denial_reason=denial_reason)
    if scope_token is not None:
        resp.scope_token = scope_token
    mock = MagicMock(return_value=resp)
    return mock, resp


# ── B1: Streaming passthrough ──────────────────────────────────────────


class TestStreamingPassthrough:
    def _make_openai_mock(self, tool_calls=None):
        oai = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "tool_calls" if tool_calls else "stop"
        choice.message.tool_calls = tool_calls or []
        choice.message.content = "Hello"

        response = MagicMock()
        response.choices = [choice]
        oai.chat.completions.create.return_value = response
        return oai, response

    def test_streaming_passthrough_openai(self):
        """B1: stream=True bypasses tool call interception, returns original_create."""
        oai, _ = self._make_openai_mock()
        stream_sentinel = MagicMock(name="stream_iterator")
        oai.chat.completions.create.return_value = stream_sentinel

        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)

            result = wrapped.chat.completions.create(
                model="gpt-4o", messages=[], stream=True
            )

            assert result is stream_sentinel
            proxy_mock.assert_not_called()

    def test_streaming_passthrough_anthropic(self):
        """B1: stream=True bypasses tool call interception for Anthropic."""
        anth = MagicMock()
        stream_sentinel = MagicMock(name="stream_iterator")
        anth.messages.create.return_value = stream_sentinel

        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.anthropic(anth, agent_id="test", scan_input=False, scan_output=False)

            result = wrapped.messages.create(
                model="claude-sonnet-4-6",
                messages=[],
                max_tokens=100,
                stream=True,
            )

            assert result is stream_sentinel
            proxy_mock.assert_not_called()

    def test_streaming_still_scans_input(self):
        """B1: Even with stream=True, scan_input is still checked."""
        oai, _ = self._make_openai_mock()
        oai.chat.completions.create.return_value = MagicMock()

        scan_mock = MagicMock(
            return_value=make_response(
                allowed=False, risk_score=0.9, denial_reason="injection"
            )
        )

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.scan_input = scan_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=True)

            with pytest.raises(ClampdBlockedError, match="injection"):
                wrapped.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": "DROP TABLE"}],
                    stream=True,
                )


# ── B2: Async guard support ───────────────────────────────────────────


class TestAsyncGuard:
    async def test_guard_async_function(self):
        """B2: @guard on async def correctly awaits the function."""
        proxy_mock, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            async def run_query(sql: str) -> str:
                return f"async result: {sql}"

            result = await run_query("SELECT 1")
            assert result == "async result: SELECT 1"
            proxy_mock.assert_called_once()

    async def test_guard_async_denied(self):
        """B2: @guard on async def raises ClampdBlockedError when denied."""
        proxy_mock, _ = _mock_proxy(
            allowed=False, denial_reason="SQL injection", risk_score=0.95
        )
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            async def run_query(sql: str) -> str:
                return f"result: {sql}"

            with pytest.raises(ClampdBlockedError, match="SQL injection"):
                await run_query("DROP TABLE users")

    async def test_guard_async_check_response(self):
        """B2: @guard with check_response=True works on async functions."""
        from clampd.client import ScanOutputResponse
        proxy_mock, _ = _mock_proxy(allowed=True)
        inspect_mock, _ = _mock_proxy(allowed=True)
        scan_output_mock = MagicMock(return_value=ScanOutputResponse(
            allowed=True, risk_score=0.0,
        ))
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock
            clampd._default_client.scan_output = scan_output_mock

            @clampd.guard("database.query", check_response=True)
            async def run_query(sql: str) -> str:
                return f"result: {sql}"

            result = await run_query("SELECT 1")
            assert result == "result: SELECT 1"
            proxy_mock.assert_called_once()
            inspect_mock.assert_called_once()
            scan_output_mock.assert_called_once()

    async def test_guard_sync_still_works(self):
        """B2: Sync functions still work after adding async support."""
        proxy_mock, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return f"sync result: {sql}"

            result = run_query("SELECT 1")
            assert result == "sync result: SELECT 1"


# ── B3: Token race condition ──────────────────────────────────────────


class TestScopeTokenRace:
    def test_scope_token_no_race(self):
        """B3: Concurrent calls use contextvars, not client attribute."""
        tokens_seen = []
        errors = []

        def worker(token_val: str, idx: int):
            try:
                _scope_token_var.set(token_val)
                # Simulate some work
                import time
                time.sleep(0.01)
                actual = _scope_token_var.get()
                tokens_seen.append((idx, token_val, actual))
                if actual != token_val:
                    errors.append(
                        f"Thread {idx}: expected {token_val}, got {actual}"
                    )
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(f"token_{i}", i))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Each thread should see its own token value
        assert len(errors) == 0, f"Race conditions detected: {errors}"
        assert len(tokens_seen) == 10

    def test_openai_wrapper_uses_contextvars(self):
        """B3: OpenAI wrapper stores token in contextvars, not client attr."""
        tc = MagicMock()
        tc.function.name = "get_weather"
        tc.function.arguments = '{"city": "NYC"}'

        oai = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "tool_calls"
        choice.message.tool_calls = [tc]
        choice.message.content = "Hello"
        response = MagicMock()
        response.choices = [choice]
        oai.chat.completions.create.return_value = response

        proxy_mock, _ = _mock_proxy(
            allowed=True, scope_token="vtoken_abc"
        )

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(
                oai, agent_id="test", check_response=True,
                scan_input=False, scan_output=False,
            )

            wrapped.chat.completions.create(
                model="gpt-4o", messages=[]
            )

            # Verify token is in contextvars
            assert _scope_token_var.get() == "vtoken_abc"
            # MagicMock auto-creates attributes on access, so instead check
            # that _clampd_last_scope_token was never explicitly set
            assert "_clampd_last_scope_token" not in oai.__dict__


# ── B4: AsyncClampdClient resource management ─────────────────────────


class TestAsyncClampdClient:
    @pytest.mark.asyncio
    async def test_async_client_context_manager(self):
        """B4: AsyncClampdClient supports async context manager."""
        with patch("clampd.client.httpx.AsyncClient") as MockAsync:
            mock_instance = AsyncMock()
            MockAsync.return_value = mock_instance
            async with AsyncClampdClient(
                agent_id="test-agent",
                gateway_url="http://test:8080",
            ) as client:
                assert client.agent_id == "test-agent"
                assert client.gateway_url == "http://test:8080"

            # aclose should have been called
            MockAsync.return_value.aclose.assert_called_once()

    async def test_async_client_jwt_before_http(self):
        """B4: JWT is created before httpx.AsyncClient (no leak on JWT failure)."""
        with patch(
            "clampd.client.make_agent_jwt", side_effect=ValueError("no secret")
        ):
            with patch("clampd.client.httpx.AsyncClient") as MockAsync:
                with pytest.raises(ValueError, match="no secret"):
                    AsyncClampdClient(
                        agent_id="test-agent",
                        gateway_url="http://test:8080",
                    )
                # httpx.AsyncClient should NOT have been created
                MockAsync.assert_not_called()

    def test_sync_client_jwt_before_http(self):
        """B4: ClampdClient also creates JWT before httpx.Client (no leak)."""
        with patch(
            "clampd.client.make_agent_jwt", side_effect=ValueError("no secret")
        ):
            with patch("clampd.client.httpx.Client") as MockSync:
                with pytest.raises(ValueError, match="no secret"):
                    from clampd.client import ClampdClient

                    ClampdClient(
                        agent_id="test-agent",
                        gateway_url="http://test:8080",
                    )
                MockSync.assert_not_called()
