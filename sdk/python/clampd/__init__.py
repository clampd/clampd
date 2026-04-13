"""Clampd Python SDK — Guard AI agent tool calls in 1 line.

Usage:
    import clampd

    # Guard OpenAI tool calls
    client = clampd.openai(OpenAI(), agent_id="my-agent")

    # Guard Anthropic/Claude tool calls
    client = clampd.anthropic(Anthropic(), agent_id="my-agent")

    # Guard any function
    @clampd.guard("database.query", agent_id="my-agent")
    def run_query(sql: str) -> str: ...

    # Guard LangChain agents (attach as callback)
    agent.invoke(input, config={"callbacks": [clampd.langchain(agent_id="my-agent")]})

    # Guard Google ADK agents
    agent = Agent(tools=[...], before_tool_callback=clampd.adk(agent_id="my-agent"))
"""

from __future__ import annotations

import contextvars
import copy
import functools
import hashlib
import inspect
import json
import logging
import os
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from clampd.crewai_callback import ClampdCrewAIGuard

from clampd.auth import make_agent_jwt
from clampd.client import (
    AsyncClampdClient,
    ClampdBlockedError,
    ClampdClient,
    ProxyResponse,
    SchemaInjectionWarning,
    scan_for_schema_injection,
)
from clampd.delegation import (
    MAX_DELEGATION_DEPTH,
    DelegationContext,
    enter_delegation,
    exit_delegation,
    get_delegation,
)
from clampd._guardrails import (
    inspect_response as _inspect_response,
    scan_input_openai as _scan_input_openai,
    scan_input_anthropic as _scan_input_anthropic,
    scan_output_content as _scan_output_content,
    extract_openai_tool_names as _extract_openai_tool_names,
    extract_anthropic_tool_names as _extract_anthropic_tool_names,
)
from clampd.stream_guard import guard_anthropic_stream, guard_openai_stream
from clampd.tool_verify import (
    ScopeTokenClaims,
    ScopeVerificationError,
    fetch_jwks,
    get_current_scope_token,
    invalidate_jwks_cache,
    require_scope,
    verify_scope_token,
)

__all__ = [
    # Core API
    "init",
    "guard",
    "openai",
    "anthropic",
    "langchain",
    "adk",
    "crewai",
    "agent",
    "delegation_headers",
    # Error types
    "ClampdBlockedError",
    "ScopeVerificationError",
    # Scope verification (tool-side)
    "verify_scope_token",
    "require_scope",
    "get_current_scope_token",
    "ScopeTokenClaims",
    # Security scanning
    "scan_for_schema_injection",
    "SchemaInjectionWarning",
    # Advanced / escape-hatch (custom gateway setups)
    "ClampdClient",
    "AsyncClampdClient",
    "make_agent_jwt",
]

F = TypeVar("F", bound=Callable[..., Any])

logger = logging.getLogger("clampd")

# B3: Thread/async-safe scope token storage
_scope_token_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    '_clampd_scope_token', default='')

# ── Global config ─────────────────────────────────────────────────────

_default_client: ClampdClient | None = None
_agent_clients: dict[str, ClampdClient] = {}
_agent_secrets: dict[str, str] = {}
_shared_config: dict[str, str] = {}


def _reset() -> None:
    """Reset all global SDK state. Intended for test isolation."""
    global _default_client
    _default_client = None
    _agent_clients.clear()
    _agent_secrets.clear()
    _shared_config.clear()


def init(
    *,
    agent_id: str,
    gateway_url: str = "http://localhost:8080",
    api_key: str = "clmpd_demo_key",
    secret: str | None = None,
    agents: dict[str, str | None] | None = None,
) -> ClampdClient:
    """Initialize the global Clampd client. Call once at startup.

    After calling ``init()``, other functions like ``guard()``,
    ``openai()``, etc. will use this client automatically.

    For multi-agent setups, pass per-agent secrets via ``agents``.
    Each agent gets its own JWT signed with its own ags_ secret.
    Kill/rate-limit/EMA operate independently per agent.

        clampd.init(
            agent_id="orchestrator",
            agents={
                "orchestrator": os.environ["ORCHESTRATOR_SECRET"],
                "research-agent": os.environ["RESEARCHER_SECRET"],
            },
        )
    """
    global _default_client
    _shared_config["gateway_url"] = gateway_url
    _shared_config["api_key"] = api_key

    # Register per-agent secrets
    if agents:
        for aid, sec in agents.items():
            if sec:
                _agent_secrets[aid] = sec

    _default_client = ClampdClient(
        gateway_url=gateway_url,
        agent_id=agent_id,
        api_key=api_key,
        secret=_agent_secrets.get(agent_id) or secret,
    )
    _agent_clients[agent_id] = _default_client
    return _default_client


def _get_client(
    agent_id: str | None = None,
    gateway_url: str | None = None,
    api_key: str | None = None,
    secret: str | None = None,
) -> ClampdClient:
    """Get or create a ClampdClient.

    Per-agent identity: if the agent_id has a registered secret (via
    init(agents={...}) or env var CLAMPD_SECRET_{agent_id}), a dedicated
    client is created with its own JWT. Kill/rate-limit/EMA then operate
    on THIS agent independently.
    """
    # Check per-agent client pool
    if agent_id and agent_id in _agent_clients:
        return _agent_clients[agent_id]

    # Check for per-agent secret → create dedicated client
    if agent_id:
        env_key = f"CLAMPD_SECRET_{agent_id.replace('-', '_').replace('.', '_')}"
        agent_secret = _agent_secrets.get(agent_id) or os.environ.get(env_key)
        if agent_secret:
            client = ClampdClient(
                gateway_url=gateway_url
                or _shared_config.get("gateway_url")
                or os.environ.get("CLAMPD_GATEWAY_URL", "http://localhost:8080"),
                agent_id=agent_id,
                api_key=api_key
                or _shared_config.get("api_key")
                or os.environ.get("CLAMPD_API_KEY", "clmpd_demo_key"),
                secret=agent_secret,
            )
            _agent_clients[agent_id] = client
            return client

    # Fallback to default client
    if _default_client is not None:
        return _default_client

    if not agent_id:
        agent_id = os.environ.get("CLAMPD_AGENT_ID", "")
        if not agent_id:
            raise ValueError(
                "No agent_id provided. Either call clampd.init(agent_id=...) "
                "first, or pass agent_id= to each function, or set CLAMPD_AGENT_ID env var."
            )

    return ClampdClient(
        gateway_url=gateway_url
        or os.environ.get("CLAMPD_GATEWAY_URL", "http://localhost:8080"),
        agent_id=agent_id,
        api_key=api_key or os.environ.get("CLAMPD_API_KEY", "clmpd_demo_key"),
        secret=secret,
    )


# ── @clampd.guard() decorator ────────────────────────────────────────


def guard(
    tool_name: str,
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    secret: str | None = None,
) -> Callable[[F], F]:
    """Decorator that guards any function through the Clampd pipeline.

        @clampd.guard("database.query")
        def run_query(sql: str) -> str:
            return db.execute(sql)

    Set ``check_response=True`` to also inspect the return value for PII,
    data anomalies, or policy violations.
    """
    client = _get_client(agent_id=agent_id, secret=secret)

    def decorator(fn: F) -> F:
        sig = inspect.signature(fn)

        # Compute tool descriptor hash for rug-pull detection
        sig_str = str(sig)
        doc = fn.__doc__ or ""
        hash_input = f"{tool_name}:{doc}:{sig_str}"
        descriptor_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        # B2: Auto-detect async functions
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)

                ctx, token = enter_delegation(client.agent_id)
                try:
                    if ctx.depth > MAX_DELEGATION_DEPTH:
                        raise ClampdBlockedError(
                            f"Delegation chain too deep "
                            f"({ctx.depth} > {MAX_DELEGATION_DEPTH})",
                            risk_score=1.0,
                        )
                    if ctx.has_cycle():
                        raise ClampdBlockedError(
                            f"Delegation cycle detected: "
                            f"{' -> '.join(ctx.chain)}",
                            risk_score=1.0,
                        )

                    try:
                        resp = client.proxy(
                            tool=tool_name,
                            params=params,
                            target_url=target_url,
                            tool_descriptor_hash=descriptor_hash,
                        )
                    except ClampdBlockedError:
                        raise
                    except Exception as e:
                        if fail_open:
                            logger.warning(
                                "Clampd gateway error (fail-open): %s", e
                            )
                            return await fn(*args, **kwargs)
                        raise ClampdBlockedError(str(e)) from e

                    if not resp.allowed:
                        raise ClampdBlockedError(
                            resp.denial_reason or "denied",
                            risk_score=resp.risk_score,
                            response=resp,
                        )

                    # Store scope token in context for tool-side access
                    _scope_token_var.set(resp.scope_token or "")
                    if resp.scope_granted:
                        logger.debug(
                            "Tool %s approved with scope: %s",
                            tool_name,
                            resp.scope_granted,
                        )

                    # Snapshot kwargs to prevent mutation between guard and execution (TOCTOU)
                    frozen_kwargs = copy.deepcopy(kwargs)
                    result = await fn(*args, **frozen_kwargs)

                    if check_response:
                        _inspect_response(
                            client,
                            tool_name,
                            result,
                            resp.request_id,
                            fail_open,
                            resp.scope_token or "",
                        )

                    return result
                finally:
                    exit_delegation(token)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)

                ctx, token = enter_delegation(client.agent_id)
                try:
                    if ctx.depth > MAX_DELEGATION_DEPTH:
                        raise ClampdBlockedError(
                            f"Delegation chain too deep "
                            f"({ctx.depth} > {MAX_DELEGATION_DEPTH})",
                            risk_score=1.0,
                        )
                    if ctx.has_cycle():
                        raise ClampdBlockedError(
                            f"Delegation cycle detected: "
                            f"{' -> '.join(ctx.chain)}",
                            risk_score=1.0,
                        )

                    try:
                        resp = client.proxy(
                            tool=tool_name,
                            params=params,
                            target_url=target_url,
                            tool_descriptor_hash=descriptor_hash,
                        )
                    except ClampdBlockedError:
                        raise
                    except Exception as e:
                        if fail_open:
                            logger.warning(
                                "Clampd gateway error (fail-open): %s", e
                            )
                            return fn(*args, **kwargs)
                        raise ClampdBlockedError(str(e)) from e

                    if not resp.allowed:
                        raise ClampdBlockedError(
                            resp.denial_reason or "denied",
                            risk_score=resp.risk_score,
                            response=resp,
                        )

                    # Store scope token in context for tool-side access
                    _scope_token_var.set(resp.scope_token or "")
                    if resp.scope_granted:
                        logger.debug(
                            "Tool %s approved with scope: %s",
                            tool_name,
                            resp.scope_granted,
                        )

                    # Snapshot kwargs to prevent mutation between guard and execution (TOCTOU)
                    frozen_kwargs = copy.deepcopy(kwargs)
                    result = fn(*args, **frozen_kwargs)

                    if check_response:
                        _inspect_response(
                            client,
                            tool_name,
                            result,
                            resp.request_id,
                            fail_open,
                            resp.scope_token or "",
                        )

                    return result
                finally:
                    exit_delegation(token)

            return wrapper  # type: ignore[return-value]

    return decorator


# ── clampd.openai() — wrap OpenAI client ──────────────────────────────


def openai(
    client: Any,
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    scan_input: bool = True,
    scan_output: bool = True,
    guard_stream: bool = True,
    schema_registry: dict[str, str] | None = None,
    secret: str | None = None,
) -> Any:
    """Wrap an OpenAI client so all tool calls go through Clampd.

        import openai, clampd
        client = clampd.openai(openai.OpenAI(), agent_id="my-agent")
        # Use client.chat.completions.create() as normal — tool calls are guarded

    Set ``check_response=True`` to also inspect tool responses for PII or anomalies.
    Returns a drop-in replacement that intercepts tool execution.
    """
    clampd_client = _get_client(agent_id=agent_id, secret=secret)
    original_create = client.chat.completions.create

    def guarded_create(*args: Any, **kwargs: Any) -> Any:
        _authorized_tools = _extract_openai_tool_names(kwargs)

        # Streaming requests — intercept tool calls only when guard_stream=True
        if kwargs.get("stream"):
            if scan_input:
                _scan_input_openai(clampd_client, kwargs, fail_open)
            raw_stream = original_create(*args, **kwargs)
            if _authorized_tools:
                if guard_stream:
                    return guard_openai_stream(
                        raw_stream, clampd_client,
                        agent_id=clampd_client.agent_id,
                        target_url=target_url,
                        fail_open=fail_open,
                        authorized_tools=_authorized_tools,
                    )
                else:
                    logger.warning(
                        "guard_stream explicitly disabled — streaming tool calls are not guarded."
                    )
            return raw_stream

        # ── INPUT GUARDRAIL ──
        if scan_input:
            _scan_input_openai(clampd_client, kwargs, fail_open)

        response = original_create(*args, **kwargs)
        choice = response.choices[0]

        # ── OUTPUT GUARDRAIL ──
        if scan_output and choice.message.content:
            _scan_output_content(clampd_client, choice.message.content, fail_open)

        if (
            choice.finish_reason != "tool_calls"
            or not choice.message.tool_calls
        ):
            return response

        for tc in choice.message.tool_calls:
            try:
                tool_args = (
                    json.loads(tc.function.arguments)
                    if isinstance(tc.function.arguments, str)
                    else tc.function.arguments
                )
            except (json.JSONDecodeError, TypeError):
                tool_args = {"_raw": tc.function.arguments}
                logger.warning(
                    "Failed to parse tool arguments as JSON for tool %s",
                    tc.function.name,
                )
            # Schema registry hash verification
            if schema_registry and tc.function.name in schema_registry:
                import hashlib as _hashlib
                tool_def = next((t for t in (kwargs.get("tools") or []) if t.get("function", {}).get("name") == tc.function.name), None)
                if tool_def:
                    fn_def = tool_def.get("function", {})
                    hash_input = f"{fn_def.get('name', '')}|{fn_def.get('description', '')}|{json.dumps(fn_def.get('parameters', {}), sort_keys=True)}"
                    current_hash = _hashlib.sha256(hash_input.encode()).hexdigest()
                    expected = schema_registry[tc.function.name]
                    if not expected.startswith("sha256:"):
                        expected = f"sha256:{expected}"
                    if f"sha256:{current_hash}" != expected:
                        raise ClampdBlockedError(
                            f"Tool descriptor hash mismatch for {tc.function.name}: "
                            f"expected {expected}, got sha256:{current_hash}",
                            risk_score=0.95,
                        )

            ctx, token = enter_delegation(clampd_client.agent_id)
            try:
                if ctx.depth > MAX_DELEGATION_DEPTH:
                    raise ClampdBlockedError(
                        f"Delegation chain too deep "
                        f"({ctx.depth} > {MAX_DELEGATION_DEPTH})",
                        risk_score=1.0,
                    )
                if ctx.has_cycle():
                    raise ClampdBlockedError(
                        f"Delegation cycle detected: "
                        f"{' -> '.join(ctx.chain)}",
                        risk_score=1.0,
                    )
                try:
                    result = clampd_client.proxy(
                        tool=tc.function.name,
                        params=tool_args,
                        target_url=target_url,
                        authorized_tools=_authorized_tools,
                    )
                except ClampdBlockedError:
                    raise
                except Exception as e:
                    if fail_open:
                        logger.warning(
                            "Clampd gateway error (fail-open): %s", e
                        )
                        continue
                    raise ClampdBlockedError(str(e)) from e

                if not result.allowed:
                    raise ClampdBlockedError(
                        result.denial_reason or "denied",
                        risk_score=result.risk_score,
                        response=result,
                    )
                # B3: Store scope token in contextvars (thread/async-safe)
                _scope_token_var.set(
                    result.scope_token or ""
                )
            finally:
                exit_delegation(token)

        return response

    client.chat.completions.create = guarded_create

    if check_response:
        # B3: Read scope token from contextvars instead of client attribute
        client._clampd_inspect = (
            lambda tool, data, req_id="": _inspect_response(
                clampd_client,
                tool,
                data,
                req_id,
                fail_open,
                _scope_token_var.get(),
            )
        )

    return client


# ── clampd.anthropic() — wrap Anthropic client ───────────────────────


def anthropic(
    client: Any,
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    scan_input: bool = True,
    scan_output: bool = True,
    guard_stream: bool = True,
    secret: str | None = None,
) -> Any:
    """Wrap an Anthropic client so all tool calls go through Clampd.

        import anthropic, clampd
        client = clampd.anthropic(anthropic.Anthropic(), agent_id="my-agent")
        # Use client.messages.create() as normal — tool_use blocks are guarded

    Set ``check_response=True`` to also inspect tool responses for PII or anomalies.
    Returns a drop-in replacement that intercepts tool_use blocks.
    """
    clampd_client = _get_client(agent_id=agent_id, secret=secret)
    original_create = client.messages.create

    def guarded_create(*args: Any, **kwargs: Any) -> Any:
        _authorized_tools = _extract_anthropic_tool_names(kwargs)
        # Streaming requests
        if kwargs.get("stream"):
            if scan_input:
                _scan_input_anthropic(clampd_client, kwargs, fail_open)
            raw_stream = original_create(*args, **kwargs)
            if _authorized_tools:
                if guard_stream:
                    return guard_anthropic_stream(
                        raw_stream, clampd_client,
                        agent_id=clampd_client.agent_id,
                        target_url=target_url,
                        fail_open=fail_open,
                        authorized_tools=_authorized_tools,
                    )
                else:
                    logger.warning(
                        "guard_stream explicitly disabled — streaming tool calls are not guarded."
                    )
            return raw_stream

        # ── INPUT GUARDRAIL ──
        if scan_input:
            _scan_input_anthropic(clampd_client, kwargs, fail_open)

        response = original_create(*args, **kwargs)

        # ── OUTPUT GUARDRAIL ──
        if scan_output:
            text_parts = [
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
                and getattr(block, "text", None)
            ]
            combined = "\n".join(text_parts) if text_parts else ""
            if combined.strip():
                try:
                    out_result = clampd_client.scan_output(combined)
                    if not out_result.allowed:
                        raise ClampdBlockedError(
                            out_result.denial_reason
                            or "Output blocked by guardrail",
                            risk_score=out_result.risk_score,
                            response=out_result,
                        )
                except ClampdBlockedError:
                    raise
                except Exception as e:
                    if not fail_open:
                        raise
                    logger.warning("Output scan failed (fail-open): %s", e)

        if response.stop_reason != "tool_use":
            return response

        if not response.content:
            return response

        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_args = (
                block.input if isinstance(block.input, dict) else {}
            )
            ctx, token = enter_delegation(clampd_client.agent_id)
            try:
                if ctx.depth > MAX_DELEGATION_DEPTH:
                    raise ClampdBlockedError(
                        f"Delegation chain too deep "
                        f"({ctx.depth} > {MAX_DELEGATION_DEPTH})",
                        risk_score=1.0,
                    )
                if ctx.has_cycle():
                    raise ClampdBlockedError(
                        f"Delegation cycle detected: "
                        f"{' -> '.join(ctx.chain)}",
                        risk_score=1.0,
                    )
                try:
                    proxy_result = clampd_client.proxy(
                        tool=block.name,
                        params=tool_args,
                        target_url=target_url,
                        authorized_tools=_authorized_tools,
                    )
                except ClampdBlockedError:
                    raise
                except Exception as e:
                    if fail_open:
                        logger.warning(
                            "Clampd gateway error (fail-open): %s", e
                        )
                        continue
                    raise ClampdBlockedError(str(e)) from e

                if not proxy_result.allowed:
                    raise ClampdBlockedError(
                        proxy_result.denial_reason or "denied",
                        risk_score=proxy_result.risk_score,
                        response=proxy_result,
                    )
                # B3: Store scope token in contextvars (thread/async-safe)
                _scope_token_var.set(
                    proxy_result.scope_token or ""
                )
            finally:
                exit_delegation(token)

        return response

    client.messages.create = guarded_create

    if check_response:
        # B3: Read scope token from contextvars instead of client attribute
        client._clampd_inspect = (
            lambda tool, data, req_id="": _inspect_response(
                clampd_client,
                tool,
                data,
                req_id,
                fail_open,
                _scope_token_var.get(),
            )
        )

    return client


# ── clampd.langchain() — callback handler ────────────────────────────


def langchain(
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    secret: str | None = None,
) -> Any:
    """Create a LangChain callback handler that guards all tool calls.

        agent.invoke(input, config={"callbacks": [clampd.langchain(agent_id="my-agent")]})

    Or attach globally:

        from langchain_core.globals import set_llm_cache
        callbacks = [clampd.langchain(agent_id="my-agent")]
    """
    from clampd.langchain_callback import ClampdCallbackHandler

    client = _get_client(agent_id=agent_id, secret=secret)
    return ClampdCallbackHandler(
        client,
        target_url=target_url,
        fail_open=fail_open,
        check_response=check_response,
    )


# ── clampd.adk() — Google ADK before_tool_callback ───────────────────


def adk(
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    secret: str | None = None,
) -> Callable[..., Any] | tuple[Callable[..., Any], Callable[..., Any]]:
    """Create Google ADK before_tool_callback (and optionally after_tool_callback).

        agent = Agent(
            model="gemini-2.0-flash",
            tools=[search, calculator],
            before_tool_callback=clampd.adk(agent_id="my-agent"),
        )

    With ``check_response=True``, returns a tuple of (before_tool, after_tool):

        before_cb, after_cb = clampd.adk(agent_id="my-agent", check_response=True)
        agent = Agent(..., before_tool_callback=before_cb, after_tool_callback=after_cb)

    Returns None to allow, or a response dict to block.
    """
    from clampd._guardrails import guard_tool_callback, inspect_response_callback

    client = _get_client(agent_id=agent_id, secret=secret)

    _last_scope_token = ""

    def before_tool(
        tool_name: str, args: dict[str, Any], context: Any
    ) -> dict[str, Any] | None:
        nonlocal _last_scope_token
        error, scope_token = guard_tool_callback(
            client, tool_name, args,
            target_url=target_url, fail_open=fail_open,
        )
        _last_scope_token = scope_token
        return error

    def after_tool(
        tool_name: str, response: Any, context: Any
    ) -> dict[str, Any] | None:
        return inspect_response_callback(
            client, tool_name, response,
            fail_open=fail_open, scope_token=_last_scope_token,
        )

    if check_response:
        return before_tool, after_tool
    return before_tool


# ── clampd.crewai() — CrewAI step callback guard ────────────────────


def crewai(
    *,
    agent_id: str | None = None,
    target_url: str = "",
    fail_open: bool = False,
    check_response: bool = False,
    secret: str | None = None,
) -> "ClampdCrewAIGuard":  # noqa: F821
    """Create a Clampd guard for CrewAI agents.

    Returns a ClampdCrewAIGuard with step_callback and wrap_tool methods.

        guard = clampd.crewai(agent_id="my-agent")
        agent = Agent(
            role="researcher",
            step_callback=guard.step_callback,
            tools=[search_tool],
        )
    """
    from clampd.crewai_callback import ClampdCrewAIGuard

    client = _get_client(agent_id=agent_id, secret=secret)
    return ClampdCrewAIGuard(
        client,
        target_url=target_url,
        fail_open=fail_open,
        check_response=check_response,
    )


# ── Delegation helpers ────────────────────────────────────────────────


def delegation_headers() -> dict[str, str]:
    """Get delegation context headers for cross-service HTTP calls."""
    return ClampdClient.delegation_headers()


def agent(agent_id: str) -> AbstractContextManager[DelegationContext]:
    """Decorator/context manager that sets up a delegation scope for an agent.

    All @clampd.guard() calls inside automatically inherit the delegation chain.

    Usage as decorator:
        @clampd.agent("orchestrator")
        def my_workflow():
            result = guarded_search(query="test")  # chain: orchestrator -> search-agent
            return result

    Usage as context manager:
        with clampd.agent("orchestrator"):
            result = guarded_search(query="test")
    """
    from contextlib import contextmanager

    from clampd.delegation import enter_delegation, exit_delegation

    @contextmanager
    def _scope() -> Iterator[DelegationContext]:
        ctx, token = enter_delegation(agent_id)
        try:
            yield ctx
        finally:
            exit_delegation(token)

    return _scope()
