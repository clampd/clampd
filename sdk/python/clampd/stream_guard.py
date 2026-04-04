"""Streaming tool call interception for OpenAI and Anthropic."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

from clampd.client import ClampdBlockedError, ClampdClient

logger = logging.getLogger("clampd")


class _StreamProxy:
    """Wraps a stream iterator and proxies attributes from the original object."""

    def __init__(self, original: Any, generator: Iterator[Any]) -> None:
        self._original = original
        self._generator = generator

    def __iter__(self) -> Iterator[Any]:
        return self._generator

    def __next__(self) -> Any:
        return next(self._generator)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)

    def __enter__(self) -> _StreamProxy:
        if hasattr(self._original, "__enter__"):
            self._original.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if hasattr(self._original, "__exit__"):
            self._original.__exit__(*exc)


def guard_openai_stream(
    stream: Any,
    client: ClampdClient,
    *,
    agent_id: str = "",
    target_url: str = "",
    fail_open: bool = False,
    authorized_tools: list[str] | None = None,
) -> Any:
    """Wraps an OpenAI streaming response to intercept tool calls.

    Text chunks pass through immediately. Tool call chunks are buffered
    until the stream signals finish_reason="tool_calls", at which point
    each tool call is sent through client.proxy() for policy evaluation.
    If blocked, raises ClampdBlockedError. If allowed, yields the
    buffered tool call chunks.

    Uses a SHARED buffer (not per-tool-call) for two reasons:

    1. OpenAI sends a single chunk with deltas for multiple tool calls.
       Per-tool-call buffers would either lose chunks (only store in one)
       or duplicate them (store in all, yield the same chunk N times).

    2. Parallel tool calls in the same LLM response are atomic — if the
       model says "call weather AND calendar", both must be approved before
       either executes. If one is denied, the entire response is blocked.
       Partial release of one tool call's chunks would give the consumer
       an incomplete response that can't be acted on.
    """

    def _generate() -> Iterator[Any]:
        # Accumulate tool call data per index; shared buffer holds all chunks.
        tool_calls: dict[int, dict[str, Any]] = {}
        buffered_chunks: list[Any] = []  # shared — see docstring for why

        for chunk in stream:
            choice = chunk.choices[0] if chunk.choices else None
            if choice is None:
                yield chunk
                continue

            delta = choice.delta if hasattr(choice, "delta") else None
            if delta is None:
                yield chunk
                continue

            # Check if this chunk has tool call deltas
            tc_deltas = getattr(delta, "tool_calls", None)
            if tc_deltas:
                buffered_chunks.append(chunk)
                for tc in tc_deltas:
                    idx = tc.index
                    if idx not in tool_calls:
                        tool_calls[idx] = {"name": "", "arguments": ""}
                    fn = getattr(tc, "function", None)
                    if fn:
                        if getattr(fn, "name", None):
                            tool_calls[idx]["name"] = fn.name
                        if getattr(fn, "arguments", None):
                            tool_calls[idx]["arguments"] += fn.arguments

                # Check if stream is done with tool calls
                if getattr(choice, "finish_reason", None) == "tool_calls":
                    # Guard each accumulated tool call
                    for idx in sorted(tool_calls):
                        tc_data = tool_calls[idx]
                        tool_name = tc_data["name"]
                        try:
                            tool_args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
                        except (json.JSONDecodeError, TypeError):
                            tool_args = {"_raw": tc_data["arguments"]}

                        try:
                            result = client.proxy(
                                tool=tool_name,
                                params=tool_args,
                                target_url=target_url,
                                authorized_tools=authorized_tools,
                            )
                        except ClampdBlockedError:
                            raise
                        except Exception as e:
                            if fail_open:
                                logger.warning("Clampd gateway error (fail-open): %s", e)
                                continue
                            raise ClampdBlockedError(str(e)) from e

                        if not result.allowed:
                            raise ClampdBlockedError(
                                result.denial_reason or "denied",
                                risk_score=result.risk_score,
                                response=result,
                            )

                    # All tool calls allowed — yield buffered chunks
                    yield from buffered_chunks
                    buffered_chunks.clear()
                    tool_calls.clear()
            else:
                # Text or non-tool chunk — pass through immediately
                yield chunk

    return _StreamProxy(stream, _generate())


def guard_anthropic_stream(
    stream: Any,
    client: ClampdClient,
    *,
    agent_id: str = "",
    target_url: str = "",
    fail_open: bool = False,
    authorized_tools: list[str] | None = None,
) -> Any:
    """Wraps an Anthropic streaming response to intercept tool_use blocks.

    Text events pass through immediately. Tool use events are buffered
    until content_block_stop, at which point the tool call is sent through
    client.proxy() for policy evaluation. If blocked, raises ClampdBlockedError.
    If allowed, yields the buffered events.
    """

    def _generate() -> Iterator[Any]:
        # Current tool block being accumulated
        current_tool_name: str = ""
        current_tool_json: str = ""
        buffered_events: list[Any] = []
        in_tool_block: bool = False

        for event in stream:
            event_type = getattr(event, "type", None)

            if event_type == "content_block_start":
                block = getattr(event, "content_block", None)
                if block and getattr(block, "type", None) == "tool_use":
                    # Start buffering a tool_use block
                    in_tool_block = True
                    current_tool_name = getattr(block, "name", "")
                    current_tool_json = ""
                    buffered_events = [event]
                    continue

            if in_tool_block:
                buffered_events.append(event)

                if event_type == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    if delta and getattr(delta, "type", None) == "input_json_delta":
                        current_tool_json += getattr(delta, "partial_json", "")

                elif event_type == "content_block_stop":
                    # Tool block complete — guard it
                    try:
                        tool_args = json.loads(current_tool_json) if current_tool_json else {}
                    except (json.JSONDecodeError, TypeError):
                        tool_args = {"_raw": current_tool_json}

                    try:
                        result = client.proxy(
                            tool=current_tool_name,
                            params=tool_args,
                            target_url=target_url,
                            authorized_tools=authorized_tools,
                        )
                    except ClampdBlockedError:
                        raise
                    except Exception as e:
                        if fail_open:
                            logger.warning("Clampd gateway error (fail-open): %s", e)
                            in_tool_block = False
                            continue
                        raise ClampdBlockedError(str(e)) from e

                    if not result.allowed:
                        raise ClampdBlockedError(
                            result.denial_reason or "denied",
                            risk_score=result.risk_score,
                            response=result,
                        )

                    # Allowed — yield buffered events
                    yield from buffered_events
                    in_tool_block = False
                    buffered_events = []
                    current_tool_name = ""
                    current_tool_json = ""

                continue

            # Non-tool event — pass through immediately
            yield event

    return _StreamProxy(stream, _generate())
