"""Tests for the 1-line SDK API — clampd.openai(), clampd.anthropic(), clampd.guard()."""

from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd.client import ClampdBlockedError
from tests.conftest import make_response


@pytest.fixture(autouse=True)
def reset_global():
    """Reset global client between tests."""
    clampd._default_client = None
    yield
    clampd._default_client = None


def _mock_proxy(allowed=True, risk_score=0.1, denial_reason=None):
    """Create a patched ClampdClient.proxy that returns a fixed response."""
    resp = make_response(allowed=allowed, risk_score=risk_score, denial_reason=denial_reason)
    mock = MagicMock(return_value=resp)
    return mock, resp


class TestInit:
    def test_init_sets_global_client(self):
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test-agent")
            assert clampd._default_client is not None
            assert clampd._default_client.agent_id == "test-agent"


class TestGuardDecorator:
    def test_allowed_call_executes(self):
        proxy_mock, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return f"result: {sql}"

            result = run_query("SELECT 1")
            assert result == "result: SELECT 1"
            proxy_mock.assert_called_once()

    def test_denied_call_raises(self):
        proxy_mock, _ = _mock_proxy(allowed=False, denial_reason="SQL injection detected", risk_score=0.95)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return f"result: {sql}"

            with pytest.raises(ClampdBlockedError, match="SQL injection"):
                run_query("DROP TABLE users")

    def test_params_extracted_from_signature(self):
        proxy_mock, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("db.query")
            def query(sql: str, limit: int = 10) -> str:
                return "ok"

            query("SELECT 1", limit=5)

            call_args = proxy_mock.call_args
            params = call_args[1]["params"] if "params" in call_args[1] else call_args[0][1]
            assert params["sql"] == "SELECT 1"
            assert params["limit"] == 5

    def test_fail_open_allows_on_error(self):
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = MagicMock(side_effect=Exception("network error"))

            @clampd.guard("db.query", fail_open=True)
            def query(sql: str) -> str:
                return "executed"

            result = query("SELECT 1")
            assert result == "executed"


class TestOpenAIWrapper:
    def _make_openai_mock(self, tool_calls=None):
        """Create a mock OpenAI client."""
        oai = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "tool_calls" if tool_calls else "stop"
        choice.message.tool_calls = tool_calls or []
        choice.message.content = "Hello"

        response = MagicMock()
        response.choices = [choice]
        oai.chat.completions.create.return_value = response
        return oai, response

    def test_no_tool_calls_passthrough(self):
        oai, response = self._make_openai_mock(tool_calls=None)
        with patch("clampd.client.httpx.Client"):
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.chat.completions.create(model="gpt-4o", messages=[])
            assert result is response

    def test_allowed_tool_call_passes(self):
        tc = MagicMock()
        tc.function.name = "get_weather"
        tc.function.arguments = '{"city": "NYC"}'

        oai, response = self._make_openai_mock(tool_calls=[tc])
        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.chat.completions.create(model="gpt-4o", messages=[])
            assert result is response
            proxy_mock.assert_called_once()

    def test_denied_tool_call_raises(self):
        tc = MagicMock()
        tc.function.name = "delete_all"
        tc.function.arguments = '{}'

        oai, _ = self._make_openai_mock(tool_calls=[tc])
        proxy_mock, _ = _mock_proxy(allowed=False, denial_reason="dangerous tool")

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)

            with pytest.raises(ClampdBlockedError, match="dangerous tool"):
                wrapped.chat.completions.create(model="gpt-4o", messages=[])


class TestResponseChecking:
    def test_guard_check_response_allowed(self):
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
            def run_query(sql: str) -> str:
                return f"result: {sql}"

            result = run_query("SELECT 1")
            assert result == "result: SELECT 1"
            proxy_mock.assert_called_once()
            inspect_mock.assert_called_once()
            scan_output_mock.assert_called_once()

    def test_guard_check_response_blocked(self):
        from clampd.client import ScanOutputResponse
        proxy_mock, _ = _mock_proxy(allowed=True)
        inspect_mock, _ = _mock_proxy(allowed=False, denial_reason="PII detected in response")
        scan_output_mock = MagicMock(return_value=ScanOutputResponse(
            allowed=True, risk_score=0.0,
        ))
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock
            clampd._default_client.scan_output = scan_output_mock

            @clampd.guard("database.query", check_response=True)
            def run_query(sql: str) -> str:
                return "SSN: 123-45-6789"

            with pytest.raises(ClampdBlockedError, match="PII detected"):
                run_query("SELECT ssn FROM users")

    def test_guard_no_check_response_by_default(self):
        proxy_mock, _ = _mock_proxy(allowed=True)
        inspect_mock = MagicMock()
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return "ok"

            run_query("SELECT 1")
            inspect_mock.assert_not_called()


class TestAnthropicWrapper:
    def _make_anthropic_mock(self, tool_use_blocks=None):
        """Create a mock Anthropic client."""
        anth = MagicMock()
        response = MagicMock()
        response.stop_reason = "tool_use" if tool_use_blocks else "end_turn"
        response.content = tool_use_blocks or []
        anth.messages.create.return_value = response
        return anth, response

    def test_no_tool_use_passthrough(self):
        anth, response = self._make_anthropic_mock()
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            wrapped = clampd.anthropic(anth, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.messages.create(model="claude-sonnet-4-6", messages=[], max_tokens=100)
            assert result is response

    def test_allowed_tool_use_passes(self):
        block = MagicMock()
        block.type = "tool_use"
        block.name = "search"
        block.input = {"query": "test"}

        anth, response = self._make_anthropic_mock(tool_use_blocks=[block])
        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.anthropic(anth, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.messages.create(model="claude-sonnet-4-6", messages=[], max_tokens=100)
            assert result is response
            proxy_mock.assert_called_once()

    def test_denied_tool_use_raises(self):
        block = MagicMock()
        block.type = "tool_use"
        block.name = "rm_rf"
        block.input = {"path": "/"}

        anth, _ = self._make_anthropic_mock(tool_use_blocks=[block])
        proxy_mock, _ = _mock_proxy(allowed=False, denial_reason="destructive operation")

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.anthropic(anth, agent_id="test", scan_input=False, scan_output=False)

            with pytest.raises(ClampdBlockedError, match="destructive"):
                wrapped.messages.create(model="claude-sonnet-4-6", messages=[], max_tokens=100)


class TestToolDescriptorHash:
    def test_guard_sends_descriptor_hash(self):
        """guard() computes and sends a tool_descriptor_hash to proxy()."""
        proxy_mock, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return f"result: {sql}"

            run_query("SELECT 1")

            call_kwargs = proxy_mock.call_args[1] if proxy_mock.call_args[1] else {}
            call_args = proxy_mock.call_args[0] if proxy_mock.call_args[0] else ()
            # tool_descriptor_hash should be passed as a keyword argument
            assert "tool_descriptor_hash" in call_kwargs
            assert isinstance(call_kwargs["tool_descriptor_hash"], str)
            assert len(call_kwargs["tool_descriptor_hash"]) == 64  # SHA-256 hex length

    def test_same_function_produces_same_hash(self):
        """The same function decorated twice with the same tool name yields the same hash."""
        proxy_mock_1, _ = _mock_proxy(allowed=True)
        proxy_mock_2, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")

            clampd._default_client.proxy = proxy_mock_1

            @clampd.guard("database.query")
            def run_query_a(sql: str) -> str:
                return f"result: {sql}"

            run_query_a("SELECT 1")
            hash_1 = proxy_mock_1.call_args[1]["tool_descriptor_hash"]

            clampd._default_client.proxy = proxy_mock_2

            @clampd.guard("database.query")
            def run_query_b(sql: str) -> str:
                return f"result: {sql}"

            run_query_b("SELECT 1")
            hash_2 = proxy_mock_2.call_args[1]["tool_descriptor_hash"]

            assert hash_1 == hash_2

    def test_different_function_produces_different_hash(self):
        """Functions with different signatures or docstrings yield different hashes."""
        proxy_mock_1, _ = _mock_proxy(allowed=True)
        proxy_mock_2, _ = _mock_proxy(allowed=True)
        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")

            clampd._default_client.proxy = proxy_mock_1

            @clampd.guard("database.query")
            def run_query(sql: str) -> str:
                return f"result: {sql}"

            run_query("SELECT 1")
            hash_1 = proxy_mock_1.call_args[1]["tool_descriptor_hash"]

            clampd._default_client.proxy = proxy_mock_2

            @clampd.guard("database.query")
            def run_query_v2(sql: str, limit: int = 10) -> str:
                """Query with limit."""
                return f"result: {sql}"

            run_query_v2("SELECT 1")
            hash_2 = proxy_mock_2.call_args[1]["tool_descriptor_hash"]

            assert hash_1 != hash_2


class TestJsonParseFallback:
    """B5: Malformed tool arguments should not crash the openai wrapper."""

    def test_malformed_json_arguments(self):
        """Tool calls with invalid JSON arguments fall back to _raw dict."""
        tc = MagicMock()
        tc.function.name = "broken_tool"
        tc.function.arguments = "not valid json {{{{"

        oai = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "tool_calls"
        choice.message.tool_calls = [tc]
        choice.message.content = None
        response = MagicMock()
        response.choices = [choice]
        oai.chat.completions.create.return_value = response

        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.chat.completions.create(model="gpt-4o", messages=[])
            assert result is response
            # The proxy should have been called with a fallback dict
            call_kwargs = proxy_mock.call_args[1]
            assert call_kwargs["params"] == {"_raw": "not valid json {{{{"}

    def test_none_arguments(self):
        """Tool calls with None arguments fall back gracefully."""
        tc = MagicMock()
        tc.function.name = "null_args_tool"
        tc.function.arguments = None

        oai = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "tool_calls"
        choice.message.tool_calls = [tc]
        choice.message.content = None
        response = MagicMock()
        response.choices = [choice]
        oai.chat.completions.create.return_value = response

        proxy_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            wrapped = clampd.openai(oai, agent_id="test", scan_input=False, scan_output=False)
            result = wrapped.chat.completions.create(model="gpt-4o", messages=[])
            assert result is response
            # None is not a string, so it should be returned directly
            call_kwargs = proxy_mock.call_args[1]
            assert call_kwargs["params"] is None


class TestLangchainOnToolEnd:
    """B8: Test that on_tool_end calls inspect when check_response=True."""

    def test_on_tool_end_calls_inspect(self):
        proxy_mock, proxy_resp = _mock_proxy(allowed=True)
        inspect_mock, _ = _mock_proxy(allowed=True)

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock

            handler = clampd.langchain(agent_id="test", check_response=True)

            # Simulate on_tool_start
            handler.on_tool_start({"name": "db.query"}, '{"sql": "SELECT 1"}')

            # Simulate on_tool_end
            handler.on_tool_end("result: 42")

            inspect_mock.assert_called_once()
            call_kwargs = inspect_mock.call_args[1]
            assert call_kwargs["tool"] == "db.query"
            assert call_kwargs["response_data"] == "result: 42"

    def test_on_tool_end_skipped_without_check_response(self):
        proxy_mock, _ = _mock_proxy(allowed=True)
        inspect_mock = MagicMock()

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock

            handler = clampd.langchain(agent_id="test")

            handler.on_tool_start({"name": "db.query"}, '{"sql": "SELECT 1"}')
            handler.on_tool_end("result: 42")

            inspect_mock.assert_not_called()

    def test_on_tool_end_raises_on_blocked(self):
        proxy_mock, _ = _mock_proxy(allowed=True)
        inspect_mock, _ = _mock_proxy(allowed=False, denial_reason="PII in response")

        with patch("clampd.client.httpx.Client"):
            clampd.init(agent_id="test")
            clampd._default_client.proxy = proxy_mock
            clampd._default_client.inspect = inspect_mock

            handler = clampd.langchain(agent_id="test", check_response=True)

            handler.on_tool_start({"name": "db.query"}, '{"sql": "SELECT 1"}')

            with pytest.raises(ClampdBlockedError, match="PII in response"):
                handler.on_tool_end("SSN: 123-45-6789")
