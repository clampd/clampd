"""LangChain CallbackHandler - guards ALL tools in any chain/agent.

Used internally by ``clampd.langchain()``. You don't need to import this directly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient
from clampd._guardrails import guard_tool_callback, inspect_response_callback

logger = logging.getLogger("clampd.langchain")

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError(
        "langchain-core required. Install: pip install langchain-core"
    )


class ClampdCallbackHandler(BaseCallbackHandler):
    """LangChain callback that intercepts tool calls via Clampd."""

    raise_error = True
    run_inline = True

    def __init__(self, client: ClampdClient, target_url: str = "", fail_open: bool = False, check_response: bool = False) -> None:
        super().__init__()
        self.client = client
        self.target_url = target_url
        self.fail_open = fail_open
        self.check_response = check_response
        self._last_tool_name = ""
        self._last_scope_token = ""

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = serialized.get("name", "unknown_tool")
        self._last_tool_name = tool_name

        inputs = kwargs.get("inputs")
        if inputs and isinstance(inputs, dict):
            params = inputs
        else:
            try:
                params = json.loads(input_str) if input_str else {}
            except (json.JSONDecodeError, TypeError):
                params = {"input": input_str}

        error, scope_token = guard_tool_callback(
            self.client, tool_name, params,
            target_url=self.target_url, fail_open=self.fail_open,
        )
        self._last_scope_token = scope_token

        if error:
            raise ClampdBlockedError(
                error.get("error", "denied"),
                risk_score=error.get("risk_score", 1.0),
            )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if not self.check_response:
            return
        error = inspect_response_callback(
            self.client, self._last_tool_name, output,
            fail_open=self.fail_open, scope_token=self._last_scope_token,
        )
        if error:
            raise ClampdBlockedError(
                error.get("error", "Response blocked"),
                risk_score=error.get("risk_score", 1.0),
            )
