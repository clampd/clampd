"""LangChain CallbackHandler — guards ALL tools in any chain/agent.

Used internally by ``clampd.langchain()``. You don't need to import this directly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient
from clampd._guardrails import guard_tool_callback, inspect_response_callback
from clampd.contract_hash import contract_hash
# Re-export for backward compat (tests / callers patching
# ``clampd.langchain_callback._schema_to_dict``).
from clampd._framework_adapters import _schema_to_dict

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
        # Captured at on_chat_model_start, forwarded to every subsequent
        # on_tool_start within the same chain so the gateway's prompt-
        # scoped rules (R013/R014/R015/R031/R032/R038) fire on the
        # tool calls the LLM produces from this prompt.
        self._last_prompt_context: str | None = None

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[Any],
        **kwargs: Any,
    ) -> None:
        """LangChain calls this with the messages list right before the LLM
        invocation. Capture the prompt text so on_tool_start can forward
        it as prompt_context — gives the gateway the LLM's input alongside
        every tool call it triggers.
        """
        # ``messages`` is List[List[BaseMessage]] (per-prompt batch). Flatten
        # then pull .content from each message. Defensive: BaseMessage's
        # .content can be str OR list-of-content-blocks.
        try:
            parts: list[str] = []
            for batch in messages:
                msgs_iter = batch if isinstance(batch, list) else [batch]
                for m in msgs_iter:
                    content = getattr(m, "content", None)
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for blk in content:
                            text = blk.get("text") if isinstance(blk, dict) else None
                            if isinstance(text, str):
                                parts.append(text)
            joined = "\n".join(p for p in parts if p)
            self._last_prompt_context = joined.strip() or None
        except Exception:
            # Never let prompt extraction break the agent loop.
            self._last_prompt_context = None

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Same as on_chat_model_start but for legacy text-completion LLMs.
        ``prompts`` is List[str], one per parallel batch.
        """
        try:
            joined = "\n".join(p for p in (prompts or []) if isinstance(p, str))
            self._last_prompt_context = joined.strip() or None
        except Exception:
            self._last_prompt_context = None

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        # Local import to avoid a circular dependency at module load
        # (``clampd/__init__.py`` imports this module during package init).
        from clampd import _registered_descriptors

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

        # Prefer the hash recorded at ``register_tool`` time — it is
        # computed from the FULL contract (including ``param_schema``)
        # which LangChain's serialized payload doesn't expose. Falling
        # back to the (name, description) hash keeps the legacy
        # behaviour for tools that were never registered explicitly.
        descriptor_hash = _registered_descriptors.get(tool_name) or contract_hash(
            tool_name,
            serialized.get("description", "") or "",
            _schema_to_dict(serialized.get("args_schema")),
        )

        error, scope_token, resp = guard_tool_callback(
            self.client, tool_name, params,
            target_url=self.target_url, fail_open=self.fail_open,
            tool_descriptor_hash=descriptor_hash,
            prompt_context=self._last_prompt_context,
        )
        self._last_scope_token = scope_token

        if error:
            raise ClampdBlockedError(
                error.get("error", "denied"),
                risk_score=error.get("risk_score", 1.0),
                response=resp,
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
                response=error.get("_response"),
            )
