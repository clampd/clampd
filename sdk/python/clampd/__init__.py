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
from clampd._errors import (
    ClampdClassificationError,
    ClampdDescriptorMismatchError,
    ClampdUnregisteredToolError,
)
from clampd._framework_adapters import _extract_tool_contract
from clampd._guardrails import (
    inspect_response as _inspect_response,
    scan_input_openai as _scan_input_openai,
    scan_input_anthropic as _scan_input_anthropic,
    extract_prompt_text_openai as _extract_prompt_text_openai,
    extract_prompt_text_anthropic as _extract_prompt_text_anthropic,
    scan_output_content as _scan_output_content,
    extract_openai_tool_names as _extract_openai_tool_names,
    extract_anthropic_tool_names as _extract_anthropic_tool_names,
    _raise_if_unregistered,
)
from clampd.stream_guard import guard_anthropic_stream, guard_openai_stream
from clampd.taxonomy import (
    Category,
    Operation,
    Subcategory,
    compute_scope as _compute_scope,
    valid_operations as _valid_operations,
    valid_subcategories as _valid_subcategories,
)
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
    "register_tool",
    # Error types
    "ClampdBlockedError",
    "ClampdClassificationError",
    "ClampdDescriptorMismatchError",
    "ClampdUnregisteredToolError",
    "ScopeVerificationError",
    # Scope verification (tool-side)
    "verify_scope_token",
    "require_scope",
    "get_current_scope_token",
    "ScopeTokenClaims",
    # Taxonomy (for register_tool)
    "Category",
    "Subcategory",
    "Operation",
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

# Process-local registry: tool_name → descriptor_hash. Last write wins.
# Populated by ``register_tool`` so callbacks (LangChain / CrewAI / etc.)
# can forward the canonical hash even when their own surface area can't
# see the full param schema. This is BELIEF — what the SDK thinks it
# registered. The backend may be ahead or behind; rug-pull detection is
# always re-checked at the gateway.
_registered_descriptors: dict[str, str] = {}


def _reset() -> None:
    """Reset all global SDK state. Intended for test isolation."""
    global _default_client
    _default_client = None
    _agent_clients.clear()
    _agent_secrets.clear()
    _shared_config.clear()
    _registered_descriptors.clear()


def init(
    *,
    agent_id: str | None = None,
    gateway_url: str | None = None,
    api_key: str | None = None,
    secret: str | None = None,
    agents: dict[str, str | None] | None = None,
) -> ClampdClient:
    """Initialize the global Clampd client. Call once at startup.

    All parameters fall back to environment variables:
      - agent_id   → CLAMPD_AGENT_ID
      - gateway_url → CLAMPD_GATEWAY_URL (default: http://localhost:8080)
      - api_key    → CLAMPD_API_KEY
      - secret     → CLAMPD_AGENT_SECRET

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

    agent_id = agent_id or os.environ.get("CLAMPD_AGENT_ID", "")
    gateway_url = gateway_url or os.environ.get("CLAMPD_GATEWAY_URL", "http://localhost:8080")
    api_key = api_key or os.environ.get("CLAMPD_API_KEY", "")
    secret = secret or os.environ.get("CLAMPD_AGENT_SECRET")

    if not agent_id:
        raise ValueError(
            "No agent_id provided. Pass agent_id= to init() or set CLAMPD_AGENT_ID env var."
        )
    if not api_key:
        logger.warning("No api_key provided. Set CLAMPD_API_KEY env var or pass api_key= to init().")
        api_key = ""

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


# ── clampd.register_tool() — explicit classification at import time ───


def register_tool(
    tool_or_name: Any,
    *,
    category: Category,
    subcategory: Subcategory,
    operation: Operation,
    description: str = "",
    param_schema: dict[str, Any] | None = None,
) -> None:
    """Register a tool descriptor with Clampd at import time.

    Unlike the guardrail wrappers (which backfill descriptors from observed
    traffic), ``register_tool`` lets tool authors declare classification
    explicitly. Tools registered this way are marked ``source="sdk"`` and
    bypass the dashboard admin-approval step — they never land in the
    unclassified default-deny state at runtime.

    Two calling conventions are supported:

        # 1. Explicit (name + kwargs) — the original signature
        clampd.register_tool(
            "db.run_query",
            category=Category.DB,
            subcategory=Subcategory.QUERY,
            operation=Operation.READ,
            description="Read-only SQL against the analytics DB",
        )

        # 2. Pass a framework tool object — name / description /
        #    param_schema are extracted automatically. Recognised types:
        #      - LangChain BaseTool
        #      - OpenAI tool dict   ({"type": "function", "function": {...}})
        #      - Anthropic tool dict ({"name": ..., "input_schema": ...})
        clampd.register_tool(
            my_langchain_tool,
            category=Category.SEARCH,
            subcategory=Subcategory.WEB,
            operation=Operation.READ,
        )

    When passing a tool object, ``description`` and ``param_schema`` are
    pulled from the object — supplying them as kwargs at the same time
    raises :class:`TypeError`.

    The ``(category, subcategory, operation)`` triple must be valid per the
    canonical taxonomy in ``ag-common/src/categories.toml`` — invalid
    combinations raise :class:`ClampdClassificationError` with a list of
    valid operations for the chosen subcategory.

    Network failures are logged at WARNING and swallowed: a registration
    failure must never block application startup. The next invocation of
    the tool will still classify correctly (the gateway falls back to
    observed traffic).
    """
    # ── Resolve (name, description, param_schema) ───────────────────────
    if isinstance(tool_or_name, str):
        name = tool_or_name
    else:
        extracted = _extract_tool_contract(tool_or_name)
        if extracted is None:
            raise TypeError(
                "register_tool: unrecognised tool object type "
                f"{type(tool_or_name).__name__}; pass str + kwargs or a "
                "langchain BaseTool / OpenAI tool dict / Anthropic tool dict"
            )
        # Disallow the ambiguous "object + override kwargs" combo — there's
        # no obviously-correct precedence and silent winners cause
        # rug-pull-detection mismatches between Python and TS.
        if description or param_schema is not None:
            raise TypeError(
                "Pass description/param_schema OR a tool object, not both"
            )
        name, description, param_schema = extracted

    # ── Validate the triple ─────────────────────────────────────────────
    if not isinstance(category, Category):
        try:
            category = Category(str(category))
        except ValueError as exc:
            raise ClampdClassificationError(
                f"Unknown category: {category!r}. "
                f"Valid categories: {[c.value for c in Category]}",
                category=str(category),
            ) from exc

    if not isinstance(subcategory, Subcategory):
        try:
            subcategory = Subcategory(str(subcategory))
        except ValueError as exc:
            raise ClampdClassificationError(
                f"Unknown subcategory: {subcategory!r}. "
                f"Valid subcategories under '{category.value}': "
                f"{_valid_subcategories(category)}",
                category=category.value,
                subcategory=str(subcategory),
                valid=_valid_subcategories(category),
            ) from exc

    if not isinstance(operation, Operation):
        try:
            operation = Operation(str(operation))
        except ValueError as exc:
            raise ClampdClassificationError(
                f"Unknown operation: {operation!r}. "
                f"Valid operations: {[o.value for o in Operation]}",
                operation=str(operation),
            ) from exc

    if subcategory.value not in _valid_subcategories(category):
        valid = _valid_subcategories(category)
        raise ClampdClassificationError(
            f"Subcategory '{subcategory.value}' is not valid for category "
            f"'{category.value}'. Valid subcategories: {valid}",
            category=category.value,
            subcategory=subcategory.value,
            valid=valid,
        )

    valid_ops = _valid_operations(category, subcategory)
    if operation.value not in valid_ops:
        raise ClampdClassificationError(
            f"Operation '{operation.value}' is not valid for "
            f"'{category.value}:{subcategory.value}'. "
            f"Valid operations: {valid_ops}",
            category=category.value,
            subcategory=subcategory.value,
            operation=operation.value,
            valid=valid_ops,
        )

    # ── Compute & cache canonical hash (independent of backend POST) ────
    # Same formula ag-common's contract_hash + the TS SDK use, so the SDK,
    # gateway, and ag-control all agree byte-for-byte on the descriptor
    # hash. Cache in ``_registered_descriptors`` BEFORE any I/O so
    # callbacks can forward the canonical hash even when CLAMPD_API_KEY
    # is unset or the gateway POST fails transiently (DNS, 5xx, ...).
    # The gateway remains the source of truth on whether a descriptor
    # is actually approved — this map only reflects what the SDK
    # *thinks* it registered.
    from clampd.contract_hash import contract_hash as _contract_hash
    _param_schema = param_schema or {}
    _descriptor_hash = _contract_hash(
        name=name,
        description=description,
        parameters=_param_schema,
    )
    _registered_descriptors[name] = _descriptor_hash

    # ── POST to gateway /v1/register ────────────────────────────────────
    #
    # The SDK only ever talks to the gateway. The gateway publishes a
    # ShadowEvent that ag-control consumes and upserts into Postgres.
    # The dashboard reads that table for display. CLAMPD_DASHBOARD_URL
    # / CLAMPD_ORG_ID are no longer used by register_tool — the gateway
    # resolves the org from the X-AG-Key.
    gateway_url = (
        _shared_config.get("gateway_url")
        or os.environ.get("CLAMPD_GATEWAY_URL")
        or "http://localhost:8080"
    ).rstrip("/")
    api_key = (
        _shared_config.get("api_key")
        or os.environ.get("CLAMPD_API_KEY", "")
    )
    if not api_key:
        logger.warning(
            "register_tool(%s): CLAMPD_API_KEY not set — descriptor was "
            "validated client-side but not sent to the gateway. Set "
            "CLAMPD_API_KEY to register descriptors with source=sdk.",
            name,
        )
        return

    scope = _compute_scope(category, subcategory, operation)

    body = {
        "name": name,
        "category": category.value,
        "subcategory": subcategory.value,
        "operation": operation.value,
        "description": description,
        "param_schema": _param_schema,
    }
    url = f"{gateway_url}/v1/register"
    headers = {"Content-Type": "application/json", "X-AG-Key": api_key}

    try:
        import httpx  # local import — same dep as client.py
        resp = httpx.post(url, headers=headers, json=body, timeout=5.0)
    except Exception as e:  # network, DNS, TLS, etc. — never fail hard
        logger.warning(
            "register_tool(%s): gateway unreachable (%s) — continuing without "
            "registration. Tool will still be auto-captured on first use.",
            name, e,
        )
        return

    if 200 <= resp.status_code < 300:
        logger.info(
            "register_tool(%s) → %s (source=sdk)", name, scope,
        )
        return

    # Non-2xx — log but do not raise
    try:
        reason = resp.json().get("error") or resp.text
    except Exception:
        reason = f"http_{resp.status_code}"
    logger.warning(
        "register_tool(%s): gateway returned %d (%s) — continuing.",
        name, resp.status_code, reason,
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
    description: str | None = None,
    param_schema: dict[str, Any] | None = None,
    descriptor_hash: str | None = None,
) -> Callable[[F], F]:
    """Decorator that guards any function through the Clampd pipeline.

        @clampd.guard(
            "database.query",
            description="Read-only SQL against the analytics DB",
            param_schema={"type": "object", "properties": {"sql": {"type": "string"}}},
        )
        def run_query(sql: str) -> str:
            return db.execute(sql)

    Set ``check_response=True`` to also inspect the return value for PII,
    data anomalies, or policy violations.

    ``description`` and ``param_schema`` participate in the canonical
    contract hash used for rug-pull detection — they must match the
    values sent to :func:`register_tool` for the same tool name. When
    omitted, they default to empty (``""``/``{}``) and the tool will not
    match a pre-registered descriptor, so rug-pull detection degrades to
    "unknown, informational only". Pass ``descriptor_hash`` explicitly
    to bypass both fields when the caller already has the hash cached.
    """
    client = _get_client(agent_id=agent_id, secret=secret)

    def decorator(fn: F) -> F:
        sig = inspect.signature(fn)

        # Canonical content-addressed hash — identical formula to the
        # dashboard-api register endpoint and the TypeScript SDK. Shares
        # the property that the hash changes iff the tool's external
        # contract (name, description, parameters) changes.
        #
        # Resolution order:
        #   1. Explicit `descriptor_hash=` kwarg on the decorator wins.
        #   2. If the tool was previously registered via
        #      `clampd.register_tool()` (in this process), use the hash that
        #      register call computed and cached in
        #      `_registered_descriptors`. This is the common case for tool
        #      authors who declare classification + description at
        #      register-time and then use `@guard("name")` (no description)
        #      at the call site. Without this fallback, guard would
        #      recompute the hash from EMPTY description/params and produce
        #      a different value than register sent, tripping the
        #      gateway's rug-pull check on every call.
        #   3. Otherwise compute fresh from the decorator's own kwargs.
        if descriptor_hash is not None:
            _desc_hash = descriptor_hash
        elif (description is None and param_schema is None
              and tool_name in _registered_descriptors):
            # Cache hit: register_tool() declared this descriptor — use
            # its hash so register/guard agree byte-for-byte.
            _desc_hash = _registered_descriptors[tool_name]
        else:
            from clampd.contract_hash import contract_hash as _contract_hash
            _desc_hash = _contract_hash(
                name=tool_name,
                description=description or "",
                parameters=param_schema or {},
            )
            # If register declared a different hash for this tool, the
            # caller has overridden the contract here — log so they know
            # they're producing a different content-address and may trip
            # rug-pull detection.
            if (tool_name in _registered_descriptors
                    and _registered_descriptors[tool_name] != _desc_hash):
                logger.warning(
                    "guard(%s): decorator description/param_schema produce a different "
                    "hash than register_tool() declared (registered=%s..., guard=%s...). "
                    "Gateway rug-pull check will deny unless register-time descriptor matches "
                    "this guard's descriptor. Either omit description/param_schema on the "
                    "decorator (to reuse register's hash), or pass identical values to both.",
                    tool_name,
                    _registered_descriptors[tool_name][:12],
                    _desc_hash[:12],
                )
        descriptor_hash_final = _desc_hash

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
                            tool_descriptor_hash=descriptor_hash_final,
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

                    _raise_if_unregistered(tool_name, resp)

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
                            tool_descriptor_hash=descriptor_hash_final,
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

                    _raise_if_unregistered(tool_name, resp)

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
        # Capture the LLM's prompt context so subsequent client.proxy()
        # calls can forward it. This makes the gateway's prompt-scoped
        # rules (R013/R014/R015/R031/R032/R038) fire on tool-call
        # traffic, not just on standalone /v1/scan-input.
        _prompt_context = _extract_prompt_text_openai(kwargs) or None

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
                        prompt_context=_prompt_context,
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
                        prompt_context=_prompt_context,
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

                _raise_if_unregistered(tc.function.name, result)

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
        # See clampd.openai() comment — captures prompt context so the
        # gateway's prompt-scoped rules fire on subsequent proxy calls.
        _prompt_context = _extract_prompt_text_anthropic(kwargs) or None
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
                        prompt_context=_prompt_context,
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
                        prompt_context=_prompt_context,
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

                _raise_if_unregistered(block.name, proxy_result)

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

    # Closure-local telemetry handles. ADK's callback contract returns
    # plain dicts to the framework, so we don't surface ProxyResponse
    # there — but we keep the last one around for diagnostic tooling
    # that wants to introspect matched_rules / session_flags.
    _last_scope_token = ""
    _last_proxy_response = None  # noqa: F841 (read by debuggers / plugins)
    _last_inspect_response = None  # noqa: F841

    def before_tool(
        tool_name: str, args: dict[str, Any], context: Any
    ) -> dict[str, Any] | None:
        nonlocal _last_scope_token, _last_proxy_response
        error, scope_token, resp = guard_tool_callback(
            client, tool_name, args,
            target_url=target_url, fail_open=fail_open,
        )
        _last_scope_token = scope_token
        _last_proxy_response = resp
        return error

    def after_tool(
        tool_name: str, response: Any, context: Any
    ) -> dict[str, Any] | None:
        nonlocal _last_inspect_response
        error = inspect_response_callback(
            client, tool_name, response,
            fail_open=fail_open, scope_token=_last_scope_token,
        )
        if error is None:
            return None
        # Capture the raw ProxyResponse for telemetry, then strip the
        # private key so ADK only sees the framework-stable shape.
        _last_inspect_response = error.pop("_response", None)
        return error

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
