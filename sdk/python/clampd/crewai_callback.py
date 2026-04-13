"""Clampd guard for CrewAI agents — intercepts tool calls via step callback."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient
from clampd._guardrails import guard_tool_callback, inspect_response_callback

logger = logging.getLogger("clampd.crewai")


class ClampdCrewAIGuard:
    """Guard that intercepts CrewAI tool calls through the Clampd security pipeline.

    Usage:
        guard = ClampdCrewAIGuard(client, agent_id="my-agent")

        # Use as step_callback for CrewAI Agent
        agent = Agent(
            role="researcher",
            step_callback=guard.step_callback,
            tools=[search_tool, write_tool],
        )

        # Or wrap individual tools
        safe_tool = guard.wrap_tool(my_tool)
    """

    def __init__(
        self,
        client: ClampdClient,
        *,
        target_url: str = "",
        fail_open: bool = False,
        check_response: bool = False,
    ):
        self._client = client
        self._target_url = target_url
        self._fail_open = fail_open
        self._check_response = check_response
        self._last_scope_token: str = ""

    def _guard_and_raise(self, tool_name: str, params: dict[str, Any]) -> None:
        """Shared guard logic: delegation + proxy + scope token + failOpen.

        Raises ClampdBlockedError if blocked.
        """
        error, scope_token = guard_tool_callback(
            self._client, tool_name, params,
            target_url=self._target_url, fail_open=self._fail_open,
        )
        self._last_scope_token = scope_token
        if error:
            raise ClampdBlockedError(
                error.get("error", "Tool call blocked"),
                risk_score=error.get("risk_score", 1.0),
            )

    def _inspect_and_raise(self, tool_name: str, response_data: Any) -> None:
        """Shared response inspection: inspect + failOpen.

        Raises ClampdBlockedError if blocked.
        """
        error = inspect_response_callback(
            self._client, tool_name, response_data,
            fail_open=self._fail_open, scope_token=self._last_scope_token,
        )
        if error:
            raise ClampdBlockedError(
                error.get("error", "Response blocked"),
                risk_score=error.get("risk_score", 1.0),
            )

    def step_callback(self, step_output: Any) -> Any:
        """CrewAI step callback that guards tool calls.

        Inspect the step output for tool usage and guard it through Clampd.
        """
        tool_name = getattr(step_output, "tool", None)
        if not tool_name:
            return step_output

        tool_input = getattr(step_output, "tool_input", {})
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                tool_input = {"raw": tool_input}

        self._guard_and_raise(
            tool_name,
            tool_input if isinstance(tool_input, dict) else {"input": tool_input},
        )

        # Inspect step output if check_response enabled
        tool_output = getattr(step_output, "tool_output", None)
        if self._check_response and tool_output is not None:
            self._inspect_and_raise(tool_name, tool_output)

        return step_output

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a CrewAI tool's _run method with Clampd guard.

        Returns a shallow copy — the original tool is not modified.
        """
        original_run = tool._run
        guard = self

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", type(tool).__name__)
            params = kwargs if kwargs else {"args": args}

            guard._guard_and_raise(tool_name, params)
            result = original_run(*args, **kwargs)

            if guard._check_response:
                guard._inspect_and_raise(tool_name, result)

            return result

        wrapped = copy.copy(tool)
        wrapped._run = guarded_run
        return wrapped
