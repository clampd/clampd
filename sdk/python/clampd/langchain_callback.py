"""LangChain CallbackHandler — guards ALL tools in any chain/agent.

Used internally by ``clampd.langchain()``. You don't need to import this directly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient

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

        try:
            result = self.client.proxy(tool=tool_name, params=params, target_url=self.target_url)
        except Exception as e:
            if self.fail_open:
                logger.warning("Gateway error (fail-open): %s", e)
                return
            raise ClampdBlockedError(str(e)) from e

        if not result.allowed:
            raise ClampdBlockedError(
                result.denial_reason or "denied",
                risk_score=result.risk_score,
                response=result,
            )

        self._last_scope_token = result.scope_token or ""

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        if not self.check_response:
            return
        try:
            resp = self.client.inspect(
                tool=self._last_tool_name,
                response_data=output,
                scope_token=self._last_scope_token,
            )
            if not resp.allowed:
                raise ClampdBlockedError(
                    resp.denial_reason or "Response blocked",
                    risk_score=resp.risk_score,
                    response=resp,
                )
        except ClampdBlockedError:
            raise
        except Exception as e:
            if self.fail_open:
                logger.warning("Clampd inspect error (fail-open): %s", e)
                return
            raise ClampdBlockedError(f"Response inspection failed: {e}") from e
