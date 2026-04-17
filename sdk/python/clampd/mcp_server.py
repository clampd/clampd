"""Clampd MCP Proxy Server -- intercepts all tool calls through the 9-stage pipeline.

Architecture:

    LLM Client --> Clampd MCP Proxy --> [9-stage pipeline] --> Real MCP Tool Server

The proxy connects to one or more downstream MCP servers, discovers their tools,
and exposes them to the upstream LLM client. Every tool invocation is routed
through the Clampd gateway for security classification, policy evaluation,
scope enforcement, and audit logging before the call reaches the real tool.

Usage (CLI)::

    python -m clampd.mcp_server \\
        --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \\
        --agent-id "b0000000-0000-0000-0000-000000000001" \\
        --gateway http://localhost:8080

Usage (Claude Desktop config)::

    {
      "mcpServers": {
        "filesystem-guarded": {
          "command": "python",
          "args": ["-m", "clampd.mcp_server",
                   "--downstream", "npx -y @modelcontextprotocol/server-filesystem /tmp",
                   "--agent-id", "b0000000-0000-0000-0000-000000000001",
                   "--gateway", "http://localhost:8080"]
        }
      }
    }
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shlex
import sys
from collections.abc import Sequence
from typing import Any

from clampd.client import ClampdClient, ProxyResponse
from clampd.delegation import (
    MAX_DELEGATION_DEPTH,
    enter_delegation,
    exit_delegation,
)

# ---------------------------------------------------------------------------
# Lazy import for the ``mcp`` package -- give a friendly error if missing.
# ---------------------------------------------------------------------------

_MCP_INSTALL_HINT = (
    "The 'mcp' package is required for the Clampd MCP proxy server.\n"
    "Install it with:  pip install 'clampd[mcp]'"
)


def _import_mcp() -> dict[str, Any]:
    """Import and return MCP SDK modules, raising a clear error if absent."""
    try:
        from mcp.client.session import ClientSession  # noqa: F811
        from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: F811
        from mcp.server import Server  # noqa: F811
        from mcp.server.stdio import stdio_server  # noqa: F811
        from mcp.types import (  # noqa: F811
            CallToolResult,
            ImageContent,
            TextContent,
            Tool,
        )
    except ImportError as exc:
        raise ImportError(_MCP_INSTALL_HINT) from exc

    return {
        "Server": Server,
        "stdio_server": stdio_server,
        "CallToolResult": CallToolResult,
        "ImageContent": ImageContent,
        "TextContent": TextContent,
        "Tool": Tool,
        "StdioServerParameters": StdioServerParameters,
        "stdio_client": stdio_client,
        "ClientSession": ClientSession,
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("clampd.mcp_proxy")

# MCP servers communicate over stdio -- all diagnostic output goes to stderr
# so it never corrupts the JSON-RPC stream.
_LOG_HANDLER = logging.StreamHandler(sys.stderr)
_LOG_HANDLER.setFormatter(
    logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
)
logger.addHandler(_LOG_HANDLER)


# ---------------------------------------------------------------------------
# ClampdMCPProxy
# ---------------------------------------------------------------------------


class ClampdMCPProxy:
    """Proxy MCP server that interposes the Clampd 9-stage security pipeline
    between an LLM client and a real (downstream) MCP tool server.

    Parameters
    ----------
    gateway_url:
        Base URL of the Clampd ag-gateway (e.g. ``http://localhost:8080``).
    agent_id:
        UUID of the Clampd-registered agent identity.
    api_key:
        API key for the Clampd gateway (``X-AG-Key`` header).
    downstream_command:
        Shell command (or executable) to spawn the downstream MCP server.
        Examples: ``"npx -y @modelcontextprotocol/server-filesystem /tmp"``,
        ``"python -m some_mcp_server"``.
    downstream_args:
        Optional extra arguments appended to *downstream_command* when it is
        provided as a single token.  If *downstream_command* already contains
        spaces it is shell-parsed with :func:`shlex.split`.
    downstream_env:
        Optional environment variable overrides passed to the subprocess.
    parent_agent_id:
        Optional UUID of the agent that connects *to* this MCP server.
        When set, the delegation chain includes the parent so the gateway
        can track the full Agent A -> Agent B delegation path.
    dry_run:
        When ``True``, the proxy calls ``/v1/verify`` (stages 1-6 only)
        instead of ``/v1/proxy``.  The tool call is **never** forwarded to
        the downstream server -- useful for policy testing.
    timeout:
        HTTP timeout (seconds) for Clampd gateway requests.
    """

    def __init__(
        self,
        *,
        gateway_url: str = "http://localhost:8080",
        agent_id: str,
        api_key: str = "clmpd_demo_key",
        downstream_command: str,
        downstream_args: Sequence[str] | None = None,
        downstream_env: dict[str, str] | None = None,
        parent_agent_id: str | None = None,
        dry_run: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id
        self.api_key = api_key
        self.parent_agent_id = parent_agent_id
        self.dry_run = dry_run
        self.timeout = timeout

        # Parse the downstream command into (executable, args).
        parts = shlex.split(downstream_command)
        if downstream_args:
            parts.extend(downstream_args)
        if not parts:
            raise ValueError("downstream_command must not be empty")
        self._downstream_cmd = parts[0]
        self._downstream_args = parts[1:]
        self._downstream_env = downstream_env

        # Populated after _discover_tools().
        self._downstream_tools: list[Any] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_clampd_client(self) -> ClampdClient:
        """Create a fresh synchronous ClampdClient."""
        return ClampdClient(
            gateway_url=self.gateway_url,
            agent_id=self.agent_id,
            api_key=self.api_key,
            timeout=self.timeout,
        )

    def _check_with_clampd(
        self,
        clampd: ClampdClient,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ProxyResponse:
        """Route a tool call through the Clampd gateway.

        In normal mode this calls ``/v1/proxy``; in dry-run mode it calls
        ``/v1/verify`` (stages 1-6 only, no forwarding).

        The *target_url* is set to empty string (evaluate-only mode) since
        actual forwarding to the downstream server is handled by this proxy,
        not by the gateway.

        Delegation context is automatically entered before the gateway call
        so that the ClampdClient picks up the delegation chain from
        contextvars and includes it in the request body.
        """
        # MCP proxy handles downstream forwarding itself, so we use
        # evaluate-only mode (empty target_url) - same as the SDK.
        # A non-empty target_url pushes the gateway into Stages 7-8
        # (token exchange + HTTP forward) which fails for mcp:// URLs.
        target_url = ""

        # Enter delegation context so ClampdClient.proxy() automatically
        # includes caller_agent_id, delegation_chain, delegation_trace_id.
        # If parent_agent_id is set, we first enter delegation for the
        # parent so the chain reflects the full Agent A -> Agent B path.
        parent_token = None
        if self.parent_agent_id:
            _, parent_token = enter_delegation(self.parent_agent_id)

        ctx, token = enter_delegation(self.agent_id)

        # Guard against excessively deep delegation chains
        if ctx.depth > MAX_DELEGATION_DEPTH:
            exit_delegation(token)
            if parent_token is not None:
                exit_delegation(parent_token)
            return ProxyResponse(
                request_id="error",
                allowed=False,
                risk_score=1.0,
                denial_reason=f"Delegation depth {ctx.depth} exceeds maximum {MAX_DELEGATION_DEPTH}",
                latency_ms=0,
            )

        try:
            if self.dry_run:
                return clampd.verify(
                    tool=tool_name,
                    params=arguments,
                    target_url=target_url,
                )
            return clampd.proxy(
                tool=tool_name,
                params=arguments,
                target_url=target_url,
                prompt_context=f"MCP tool call: {tool_name}",
            )
        finally:
            try:
                exit_delegation(token)
            finally:
                if parent_token is not None:
                    exit_delegation(parent_token)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the proxy.

        1. Connect to the downstream MCP server via stdio subprocess.
        2. Discover its tools.
        3. Start our own MCP server on stdio, mirroring those tools.
        4. Intercept every ``call_tool`` through the Clampd pipeline.
        """
        mcp = _import_mcp()

        Server = mcp["Server"]
        stdio_server = mcp["stdio_server"]
        CallToolResult = mcp["CallToolResult"]
        TextContent = mcp["TextContent"]
        ImageContent = mcp["ImageContent"]
        Tool = mcp["Tool"]
        StdioServerParameters = mcp["StdioServerParameters"]
        stdio_client = mcp["stdio_client"]
        ClientSession = mcp["ClientSession"]

        # ---- 1. Connect to downstream ---------------------------------

        downstream_params = StdioServerParameters(
            command=self._downstream_cmd,
            args=self._downstream_args,
            env={**os.environ, **(self._downstream_env or {})},
        )

        logger.info(
            "Connecting to downstream MCP server: %s %s",
            self._downstream_cmd,
            " ".join(self._downstream_args),
        )

        async with stdio_client(downstream_params) as (ds_read, ds_write):
            async with ClientSession(ds_read, ds_write) as downstream:
                await downstream.initialize()

                # ---- 2. Discover tools --------------------------------

                tools_response = await downstream.list_tools()
                self._downstream_tools = tools_response.tools
                logger.info(
                    "Discovered %d tool(s) from downstream: %s",
                    len(self._downstream_tools),
                    ", ".join(t.name for t in self._downstream_tools),
                )

                if not self._downstream_tools:
                    logger.warning(
                        "Downstream server exposed zero tools -- the proxy "
                        "will start but has nothing to serve."
                    )

                # ---- 3. Build the proxy server ------------------------

                # Keep a reference so handlers can close-over it.
                _downstream = downstream
                _tools = self._downstream_tools
                _proxy = self  # capture for closures

                server = Server("clampd-proxy")

                @server.list_tools()  # type: ignore[untyped-decorator]
                async def handle_list_tools() -> list[Any]:
                    """Return the same tool list the downstream exposes."""
                    return [
                        Tool(
                            name=t.name,
                            description=_make_guarded_description(t.description),
                            inputSchema=t.inputSchema,
                        )
                        for t in _tools
                    ]

                @server.call_tool()  # type: ignore[untyped-decorator]
                async def handle_call_tool(
                    name: str, arguments: dict[str, Any] | None
                ) -> list[Any]:
                    """Intercept tool call, run Clampd pipeline, optionally forward."""
                    arguments = arguments or {}
                    logger.info(
                        "Intercepted tool call: %s(%s)",
                        name,
                        _truncate_json(arguments),
                    )

                    # -- Content scanning for file-write tools ----------
                    # Bypass #1-#5 fix: scan content of write_file/edit_file
                    # through scan-input before the normal proxy check.
                    content_scan_result = await _scan_file_content(
                        _proxy, name, arguments, logger
                    )
                    if content_scan_result is not None:
                        return [TextContent(type="text", text=content_scan_result)]

                    # -- Clampd check (sync client, run in thread) ------
                    clampd_client = _proxy._make_clampd_client()
                    try:
                        result = await asyncio.to_thread(
                            _proxy._check_with_clampd,
                            clampd_client,
                            name,
                            arguments,
                        )
                    finally:
                        clampd_client.close()

                    logger.info(
                        "Clampd decision for %s: allowed=%s risk=%.2f latency=%dms%s",
                        name,
                        result.allowed,
                        result.risk_score,
                        result.latency_ms,
                        f" denied={result.denial_reason}" if not result.allowed else "",
                    )

                    # -- Blocked ----------------------------------------
                    if not result.allowed:
                        denial = _format_denial(name, result)
                        return [TextContent(type="text", text=denial)]

                    # -- Dry-run: allowed but do not forward -------------
                    if _proxy.dry_run:
                        msg = (
                            f"[clampd dry-run] Tool '{name}' ALLOWED "
                            f"(risk={result.risk_score:.2f}, "
                            f"scope={result.scope_granted}). "
                            f"Call was NOT forwarded to the downstream server."
                        )
                        return [TextContent(type="text", text=msg)]

                    # -- Forward to downstream --------------------------
                    try:
                        ds_result = await _downstream.call_tool(name, arguments)
                    except Exception as exc:
                        logger.error(
                            "Downstream call_tool(%s) failed: %s", name, exc
                        )
                        return [
                            TextContent(
                                type="text",
                                text=f"[clampd] Downstream tool error: {exc}",
                            )
                        ]

                    # Pass through all content items (text, image, etc.)
                    return _normalise_downstream_content(
                        ds_result, TextContent, ImageContent
                    )

                # ---- 4. Serve on stdio --------------------------------

                mode_label = "DRY-RUN" if self.dry_run else "LIVE"
                logger.info(
                    "Clampd MCP proxy ready [%s] -- serving %d tool(s) "
                    "via gateway %s for agent %s",
                    mode_label,
                    len(_tools),
                    self.gateway_url,
                    self.agent_id,
                )

                async with stdio_server() as (read, write):
                    init_options = server.create_initialization_options()
                    await server.run(read, write, init_options)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# File content scanning for MCP write/edit tools (Bypass #1-#5 fix)
# ---------------------------------------------------------------------------

# File extensions whose content should always be scanned for dangerous patterns
_DANGEROUS_EXTENSIONS = frozenset({
    ".sql", ".sh", ".bash", ".zsh", ".py", ".rb", ".ps1", ".bat", ".cmd",
    ".js", ".ts", ".php", ".pl", ".lua", ".yaml", ".yml", ".json", ".xml",
    ".env", ".conf", ".cfg", ".ini", ".toml", ".log",
})

# MCP tools that write/modify file content - their content fields must be scanned
_FILE_WRITE_TOOLS = {
    "write_file": "content",
    "create_file": "content",
    "edit_file": "newText",
    "append_file": "content",
    "insert_text": "text",
}

# MCP tools that move/copy files - risk tags should propagate
_FILE_MOVE_TOOLS = {"move_file", "rename_file", "copy_file"}

# Tools that may leak runtime/system metadata
_METADATA_TOOLS = {"directory_tree", "list_directory", "list_directory_with_sizes"}

# Paths that should be excluded from directory listing results (Bypass #6 fix)
_EXCLUDED_PATH_PATTERNS = {
    "node-compile-cache", ".npm/_cacache", "__pycache__", ".cache/pip",
    ".rustup", ".cargo/registry", ".local/share/pnpm",
}


async def _scan_file_content(
    proxy: ClampdMCPProxy,
    tool_name: str,
    arguments: dict[str, Any],
    logger: logging.Logger,
) -> str | None:
    """Scan file content for dangerous patterns before allowing write/edit.

    Returns a denial message string if blocked, or None if the call should proceed.
    Fixes MCP bypass #1-#5: write_file/edit_file content was never scanned.
    """
    # Check if this is a file-write tool with scannable content
    content_field = _FILE_WRITE_TOOLS.get(tool_name)
    if content_field is None:
        return None

    content = arguments.get(content_field, "")
    if not content or not isinstance(content, str):
        return None

    # Check file extension - scan ALL extensions in the filename (double-ext bypass fix)
    file_path = arguments.get("path", arguments.get("file_path", ""))
    has_dangerous_ext = False
    if file_path and "." in file_path:
        # Check ALL extensions in the path, not just the last one
        # e.g., "evil.sql.jpg" → check both ".sql" and ".jpg"
        parts = file_path.lower().rsplit("/", 1)[-1].split(".")
        for part in parts[1:]:  # skip filename, check all extensions
            if f".{part}" in _DANGEROUS_EXTENSIONS:
                has_dangerous_ext = True
                break

    # Always scan if:
    # 1. Any extension in the filename is dangerous (.sql, .sh, .py, etc.)
    # 2. Content is >= 100 bytes (catches small payloads like "DROP TABLE users")
    # 3. Content contains any non-ASCII chars (encoding evasion indicator)
    # Only skip scanning for very short content with no dangerous extension and no suspicious chars
    has_suspicious_chars = any(ord(c) > 127 for c in content[:200]) if len(content) <= 500 else False
    if not has_dangerous_ext and len(content) < 100 and not has_suspicious_chars:
        return None

    logger.info(
        "Scanning %s content for %s (%d bytes, ext=%s)",
        tool_name, file_path, len(content), file_path.rsplit(".", 1)[-1] if "." in file_path else "unknown",
    )

    # Run scan-input on the file content through the gateway
    clampd_client = proxy._make_clampd_client()
    try:
        scan_result = await asyncio.to_thread(
            clampd_client.scan_input,
            content,
        )
    except Exception as exc:
        logger.warning("Content scan failed (allowing): %s", exc)
        return None
    finally:
        clampd_client.close()

    if scan_result and not scan_result.allowed:
        logger.warning(
            "BLOCKED %s to %s: risk=%.2f reason=%s rules=%s",
            tool_name, file_path, scan_result.risk_score,
            scan_result.denial_reason, scan_result.matched_rules,
        )
        return (
            f"[clampd] BLOCKED: {tool_name} to '{file_path}' denied.\n"
            f"Risk score: {scan_result.risk_score:.2f}\n"
            f"Reason: {scan_result.denial_reason or 'dangerous content detected'}\n"
            f"Matched rules: {', '.join(scan_result.matched_rules) or 'content policy violation'}\n"
            f"The file content contains dangerous patterns that violate security policy."
        )

    return None


def _make_guarded_description(original: str | None) -> str:
    """Prepend a security notice to the tool description."""
    prefix = "[Guarded by Clampd]"
    if original:
        return f"{prefix} {original}"
    return prefix


def _truncate_json(obj: Any, limit: int = 200) -> str:
    """Return a JSON string truncated to *limit* characters for logging."""
    try:
        raw = json.dumps(obj, default=str)
    except (TypeError, ValueError):
        raw = str(obj)
    if len(raw) > limit:
        return raw[:limit] + "..."
    return raw


def _format_denial(tool_name: str, result: ProxyResponse) -> str:
    """Build a human-readable denial message."""
    parts = [
        f"[clampd] Tool call '{tool_name}' was BLOCKED.",
        f"Reason: {result.denial_reason or 'policy violation'}",
        f"Risk score: {result.risk_score:.2f}",
        f"Request ID: {result.request_id}",
    ]
    if result.session_flags:
        parts.append(f"Session flags: {', '.join(result.session_flags)}")
    if result.degraded_stages:
        parts.append(f"Degraded stages: {', '.join(result.degraded_stages)}")
    return "\n".join(parts)


def _normalise_downstream_content(ds_result: Any, TextContent: type, ImageContent: type) -> list[Any]:
    """Extract content items from a downstream CallToolResult.

    The MCP SDK returns a ``CallToolResult`` whose ``.content`` is a list of
    typed content objects (``TextContent``, ``ImageContent``, etc.).  We pass
    them through unchanged so the upstream client sees exactly what the
    downstream produced.
    """
    contents: list[Any] = []
    if ds_result is None:
        return [TextContent(type="text", text="[clampd] Tool returned no content.")]

    # CallToolResult has a .content list
    raw_content = getattr(ds_result, "content", None)
    if raw_content is None:
        # Fallback: treat the whole thing as text
        return [TextContent(type="text", text=str(ds_result))]

    for item in raw_content:
        item_type = getattr(item, "type", None)
        if item_type == "text":
            contents.append(TextContent(type="text", text=item.text))
        elif item_type == "image":
            contents.append(
                ImageContent(
                    type="image",
                    data=item.data,
                    mimeType=item.mimeType,
                )
            )
        else:
            # Unknown content type -- serialize to text
            try:
                serialized = item.model_dump_json() if hasattr(item, "model_dump_json") else str(item)
            except Exception:
                serialized = str(item)
            contents.append(TextContent(type="text", text=serialized))

    if not contents:
        contents.append(TextContent(type="text", text="[clampd] Tool returned empty content."))

    return contents


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clampd.mcp_server",
        description=(
            "Clampd MCP Proxy Server -- routes all MCP tool calls through "
            "the Clampd 9-stage security pipeline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m clampd.mcp_server \\\n"
            '    --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \\\n'
            '    --agent-id "b0000000-0000-0000-0000-000000000001" \\\n'
            "    --gateway http://localhost:8080\n"
            "\n"
            "  # Dry-run mode (stages 1-6 only, no forwarding):\n"
            "  python -m clampd.mcp_server \\\n"
            '    --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \\\n'
            '    --agent-id "b0000000-0000-0000-0000-000000000001" \\\n'
            "    --gateway http://localhost:8080 \\\n"
            "    --dry-run\n"
        ),
    )

    parser.add_argument(
        "--downstream",
        required=True,
        help=(
            "Shell command to spawn the downstream MCP server. "
            'Example: "npx -y @modelcontextprotocol/server-filesystem /tmp"'
        ),
    )
    parser.add_argument(
        "--agent-id",
        required=True,
        help="Clampd agent UUID.",
    )
    parser.add_argument(
        "--gateway",
        default="http://localhost:8080",
        help="Clampd gateway URL (default: http://localhost:8080).",
    )
    parser.add_argument(
        "--api-key",
        default="clmpd_demo_key",
        help="Clampd API key (default: clmpd_demo_key).",
    )
    parser.add_argument(
        "--parent-agent-id",
        default=None,
        help=(
            "UUID of the parent agent connecting to this MCP server. "
            "When set, the delegation chain includes the parent for "
            "full cross-agent tracking."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Run in dry-run mode: call /v1/verify (stages 1-6) instead of "
            "/v1/proxy. The tool call is never forwarded to the downstream "
            "server."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds for gateway requests (default: 30).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug logging.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """CLI entry point for ``python -m clampd.mcp_server``."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    proxy = ClampdMCPProxy(
        gateway_url=args.gateway,
        agent_id=args.agent_id,
        api_key=args.api_key,
        downstream_command=args.downstream,
        parent_agent_id=args.parent_agent_id,
        dry_run=args.dry_run,
        timeout=args.timeout,
    )

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info("Shutting down Clampd MCP proxy.")


if __name__ == "__main__":
    main()
