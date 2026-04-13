"""Tests for clampd.crewai_callback — CrewAI guard."""

from unittest.mock import MagicMock, patch

import pytest

from clampd.client import ClampdBlockedError, ClampdClient
from clampd.crewai_callback import ClampdCrewAIGuard
from tests.conftest import make_response


class TestCrewAIGuard:
    def _make_client(self):
        with patch("clampd.client.httpx.Client"):
            client = ClampdClient(agent_id="test-agent", gateway_url="http://test:8080")
            return client

    def test_step_callback_allows_tool_call(self):
        client = self._make_client()
        client.proxy = MagicMock(return_value=make_response(allowed=True))
        guard = ClampdCrewAIGuard(client)

        step = MagicMock()
        step.tool = "search"
        step.tool_input = {"query": "hello"}

        result = guard.step_callback(step)

        assert result is step
        client.proxy.assert_called_once_with(
            tool="search",
            params={"query": "hello"},
            target_url="",
        )

    def test_step_callback_blocks_dangerous_tool(self):
        client = self._make_client()
        client.proxy = MagicMock(
            return_value=make_response(allowed=False, risk_score=0.95, denial_reason="dangerous tool")
        )
        guard = ClampdCrewAIGuard(client)

        step = MagicMock()
        step.tool = "shell_exec"
        step.tool_input = {"cmd": "rm -rf /"}

        with pytest.raises(ClampdBlockedError, match="dangerous tool"):
            guard.step_callback(step)

    def test_step_callback_skips_non_tool_steps(self):
        client = self._make_client()
        client.proxy = MagicMock()
        guard = ClampdCrewAIGuard(client)

        step = MagicMock(spec=[])  # no attributes at all

        result = guard.step_callback(step)

        assert result is step
        client.proxy.assert_not_called()

    def test_step_callback_handles_string_tool_input(self):
        client = self._make_client()
        client.proxy = MagicMock(return_value=make_response(allowed=True))
        guard = ClampdCrewAIGuard(client)

        step = MagicMock()
        step.tool = "search"
        step.tool_input = '{"query": "test"}'

        result = guard.step_callback(step)

        assert result is step
        client.proxy.assert_called_once_with(
            tool="search",
            params={"query": "test"},
            target_url="",
        )

    def test_wrap_tool_guards_run(self):
        client = self._make_client()
        client.proxy = MagicMock(return_value=make_response(allowed=True))
        guard = ClampdCrewAIGuard(client)

        tool = MagicMock()
        tool.name = "calculator"
        tool._run = MagicMock(return_value="42")

        wrapped = guard.wrap_tool(tool)
        result = wrapped._run(expression="2+2")

        client.proxy.assert_called_once_with(
            tool="calculator",
            params={"expression": "2+2"},
            target_url="",
        )
        assert result == "42"

    def test_wrap_tool_blocks_when_denied(self):
        client = self._make_client()
        client.proxy = MagicMock(
            return_value=make_response(allowed=False, risk_score=0.9, denial_reason="policy violation")
        )
        guard = ClampdCrewAIGuard(client)

        tool = MagicMock()
        tool.name = "file_write"
        original_run = MagicMock()
        tool._run = original_run

        wrapped = guard.wrap_tool(tool)

        with pytest.raises(ClampdBlockedError, match="policy violation"):
            wrapped._run(path="/etc/passwd", content="hacked")

        original_run.assert_not_called()

    def test_fail_open_allows_on_error(self):
        client = self._make_client()
        client.proxy = MagicMock(side_effect=ConnectionError("gateway down"))
        guard = ClampdCrewAIGuard(client, fail_open=True)

        step = MagicMock()
        step.tool = "search"
        step.tool_input = {"query": "hello"}

        result = guard.step_callback(step)

        assert result is step

    def test_fail_open_false_raises_on_error(self):
        client = self._make_client()
        client.proxy = MagicMock(side_effect=ConnectionError("gateway down"))
        guard = ClampdCrewAIGuard(client, fail_open=False)

        step = MagicMock()
        step.tool = "search"
        step.tool_input = {"query": "hello"}

        with pytest.raises(ClampdBlockedError, match="Security gateway error"):
            guard.step_callback(step)
