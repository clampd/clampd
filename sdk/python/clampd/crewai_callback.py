"""Clampd guard for CrewAI agents — intercepts tool calls via step callback."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient
from clampd._guardrails import guard_tool_callback, inspect_response_callback
from clampd.contract_hash import contract_hash
# Re-export for backward compat (tests / callers patching
# ``clampd.crewai_callback._schema_to_dict``).
from clampd._framework_adapters import _schema_to_dict

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

    def _guard_and_raise(
        self,
        tool_name: str,
        params: dict[str, Any],
        *,
        tool_descriptor_hash: str | None = None,
    ) -> None:
        """Shared guard logic: delegation + proxy + scope token + failOpen.

        Raises ClampdBlockedError if blocked.
        """
        error, scope_token, resp = guard_tool_callback(
            self._client, tool_name, params,
            target_url=self._target_url, fail_open=self._fail_open,
            tool_descriptor_hash=tool_descriptor_hash,
        )
        self._last_scope_token = scope_token
        if error:
            raise ClampdBlockedError(
                error.get("error", "Tool call blocked"),
                risk_score=error.get("risk_score", 1.0),
                response=resp,
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
                response=error.get("_response"),
            )

    def step_callback(self, step_output: Any) -> Any:
        """CrewAI step callback that guards tool calls.

        Inspect the step output for tool usage and guard it through Clampd.
        """
        # Local import to avoid circular dependency at package init time.
        from clampd import _registered_descriptors

        tool_name = getattr(step_output, "tool", None)
        if not tool_name:
            return step_output

        tool_input = getattr(step_output, "tool_input", {})
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                tool_input = {"raw": tool_input}

        # Prefer the hash recorded at register_tool() time — it covers
        # the full contract (name + description + param_schema). Falling
        # back to the (name, description) hash keeps the legacy behaviour
        # for tools that were never registered explicitly. Coerce
        # description to str defensively — some frameworks pass back
        # proxy-like objects.
        raw_description = getattr(step_output, "tool_description", "")
        description = raw_description if isinstance(raw_description, str) else ""
        descriptor_hash = _registered_descriptors.get(tool_name) or contract_hash(
            tool_name, description, {},
        )

        self._guard_and_raise(
            tool_name,
            tool_input if isinstance(tool_input, dict) else {"input": tool_input},
            tool_descriptor_hash=descriptor_hash,
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
        # Local import to avoid circular dependency at package init time.
        from clampd import _registered_descriptors

        original_run = tool._run
        guard = self

        # Compute the descriptor hash once at wrap time — the full
        # BaseTool is in scope here, so we can include the pydantic
        # args_schema. Cached on the closure so every invocation sends
        # the same hash (the gateway uses it to spot a contract change).
        tool_name_at_wrap = getattr(tool, "name", type(tool).__name__)
        raw_description = getattr(tool, "description", "")
        tool_description = raw_description if isinstance(raw_description, str) else ""
        raw_schema = getattr(tool, "args_schema", None)
        schema_dict = _schema_to_dict(raw_schema)
        try:
            computed_hash = contract_hash(
                tool_name_at_wrap, tool_description, schema_dict,
            )
        except TypeError:
            # Fall back to empty-parameters hash if the schema isn't
            # JSON-serialisable (e.g. when the caller hands us a mock).
            computed_hash = contract_hash(
                tool_name_at_wrap, tool_description, {},
            )
        # Prefer the explicitly-registered hash if one exists for this
        # tool name (matches what register_tool() POSTed to the backend).
        descriptor_hash = (
            _registered_descriptors.get(tool_name_at_wrap) or computed_hash
        )

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", type(tool).__name__)
            params = kwargs if kwargs else {"args": args}

            guard._guard_and_raise(
                tool_name, params, tool_descriptor_hash=descriptor_hash,
            )
            result = original_run(*args, **kwargs)

            if guard._check_response:
                guard._inspect_and_raise(tool_name, result)

            return result

        wrapped = copy.copy(tool)
        wrapped._run = guarded_run
        return wrapped
