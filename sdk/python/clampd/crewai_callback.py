"""Clampd guard for CrewAI agents — intercepts tool calls via step callback."""

from __future__ import annotations

import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient
from clampd.delegation import enter_delegation, exit_delegation

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

    def step_callback(self, step_output: Any) -> Any:
        """CrewAI step callback that guards tool calls.

        Inspect the step output for tool usage and guard it through Clampd.
        """
        # CrewAI step_output has .tool (name) and .tool_input (args) when a tool is used
        tool_name = getattr(step_output, "tool", None)
        if not tool_name:
            return step_output

        tool_input = getattr(step_output, "tool_input", {})
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                tool_input = {"raw": tool_input}

        ctx, token = enter_delegation(self._client.agent_id)
        try:
            result = self._client.proxy(
                tool=tool_name,
                params=tool_input if isinstance(tool_input, dict) else {"input": tool_input},
                target_url=self._target_url,
            )
            self._last_scope_token = result.scope_token or ""
            if not result.allowed:
                raise ClampdBlockedError(
                    result.denial_reason or "Tool call blocked",
                    risk_score=result.risk_score,
                    response=result,
                )
        except ClampdBlockedError:
            raise
        except Exception as exc:
            if not self._fail_open:
                raise ClampdBlockedError(str(exc))
        finally:
            exit_delegation(token)

        return step_output

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a CrewAI tool's _run method with Clampd guard."""
        original_run = tool._run
        guard = self

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", type(tool).__name__)
            params = kwargs if kwargs else {"args": args}

            ctx, token = enter_delegation(guard._client.agent_id)
            try:
                result = guard._client.proxy(
                    tool=tool_name,
                    params=params,
                    target_url=guard._target_url,
                )
                guard._last_scope_token = result.scope_token or ""
                if not result.allowed:
                    raise ClampdBlockedError(
                        result.denial_reason or "Tool call blocked",
                        risk_score=result.risk_score,
                        response=result,
                    )
            except ClampdBlockedError:
                raise
            except Exception as exc:
                if not guard._fail_open:
                    raise ClampdBlockedError(str(exc))
            finally:
                exit_delegation(token)

            return original_run(*args, **kwargs)

        tool._run = guarded_run
        return tool
