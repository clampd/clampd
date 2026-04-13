"""ClampdClient — gateway HTTP client."""

from __future__ import annotations

import asyncio
import os
import re as _re
import time
from typing import Any

import httpx
from pydantic import BaseModel

from clampd.auth import make_agent_jwt
from clampd.delegation import get_delegation

# ── Schema injection detection patterns (compiled once at import time) ──

_SCHEMA_INJECTION_PATTERNS = {
    "xml_injection": [
        _re.compile(r"</?functions\s*>", _re.IGNORECASE),
        _re.compile(r"<function[\s>]", _re.IGNORECASE),
        _re.compile(r"</?tool\s*>", _re.IGNORECASE),
        _re.compile(r"</?tool_call\s*>", _re.IGNORECASE),
        _re.compile(r"</?tool_code\s*>", _re.IGNORECASE),
        _re.compile(r"</?tools\s*>", _re.IGNORECASE),
        _re.compile(r"<system\s*>", _re.IGNORECASE),
    ],
    "json_injection": [
        _re.compile(r'"inputSchema"\s*:'),
        _re.compile(r'"parameters"\s*:\s*\{[^}]*"type"\s*:\s*"object"'),
    ],
    "tool_steering": [
        # Multi-word patterns only — single words like "DEPRECATED" cause
        # false positives in normal conversation (alert fatigue risk).
        _re.compile(r"use\s+\w+\s+instead\b", _re.IGNORECASE),
        _re.compile(r"\breplaced\s+by\b", _re.IGNORECASE),
        _re.compile(r"\bsuperseded\s+by\b", _re.IGNORECASE),
    ],
    "constraint_weakening": [
        _re.compile(r'allowed_directories["\s]*:\s*\[\s*\]', _re.IGNORECASE),
        _re.compile(r'allowed_directories["\s]*:\s*\["\*"\]', _re.IGNORECASE),
        _re.compile(r'"type"\s*:\s*"any"'),
        _re.compile(r'"required"\s*:\s*\[\s*\]'),
    ],
}


class SchemaInjectionWarning:
    """Warning about a detected schema injection attempt in message content."""

    __slots__ = ("alert_type", "matched_pattern", "risk_score", "message_index")

    def __init__(self, alert_type: str, matched_pattern: str, risk_score: float, message_index: int = -1):
        self.alert_type = alert_type
        self.matched_pattern = matched_pattern
        self.risk_score = risk_score
        self.message_index = message_index

    def __repr__(self) -> str:
        return f"SchemaInjectionWarning({self.alert_type!r}, pattern={self.matched_pattern!r}, risk={self.risk_score})"


# Risk scores per alert type
_SCHEMA_RISK_SCORES: dict[str, float] = {
    "xml_injection": 0.95,
    "json_injection": 0.90,
    "constraint_weakening": 0.88,
    "tool_steering": 0.80,
}


def scan_for_schema_injection(messages: list[dict[str, Any]]) -> list[SchemaInjectionWarning]:
    """Scan conversation messages for schema injection / tool poisoning attempts.

    Checks all message content (user, system, assistant turns) for:
    - XML tool definition tags (<functions>, <tool>, etc.)
    - JSON tool definition structures ("inputSchema", "parameters")
    - Tool confusion via DEPRECATED/OBSOLETE steering
    - Schema constraint weakening (allowed_directories: [], type: "any")

    Returns a list of warnings, highest risk first. Empty list = clean.
    """
    warnings: list[SchemaInjectionWarning] = []

    for idx, msg in enumerate(messages):
        raw = msg.get("content", "")
        if isinstance(raw, str):
            content = raw
        elif isinstance(raw, list):
            # Anthropic-style content blocks: [{"type": "text", "text": "..."}]
            content = "\n".join(
                b.get("text", "") for b in raw
                if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
            )
        else:
            content = ""
        if not content:
            continue

        for alert_type, patterns in _SCHEMA_INJECTION_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    warnings.append(
                        SchemaInjectionWarning(
                            alert_type=alert_type,
                            matched_pattern=match.group(),
                            risk_score=_SCHEMA_RISK_SCORES[alert_type],
                            message_index=idx,
                        )
                    )
                    break  # One match per alert_type per message is enough

    # Sort by risk (highest first)
    warnings.sort(key=lambda w: w.risk_score, reverse=True)
    return warnings


class ProxyResponse(BaseModel):
    request_id: str = ""
    allowed: bool
    raw_action: str = "pass"  # "pass", "flag", or "block" (from gateway)
    risk_score: float
    scope_granted: str | None = None
    tool_response: Any | None = None
    denial_reason: str | None = None
    reasoning: str | None = None
    matched_rules: list[str] = []
    latency_ms: int = 0
    degraded_stages: list[str] = []
    session_flags: list[str] = []
    scope_token: str | None = None

    model_config = {"populate_by_name": True}

    def __init__(self, **data: Any) -> None:
        # Accept "action" from gateway JSON and map to raw_action
        if "action" in data and "raw_action" not in data:
            data["raw_action"] = data.pop("action")
        super().__init__(**data)

    @property
    def action(self) -> str:
        """Reconciled action: 'exempt' when allowed despite a block rule."""
        if self.allowed and self.raw_action == "block":
            return "exempt"
        return self.raw_action

    @property
    def score(self) -> float:
        return self.risk_score


class ScanResponse(BaseModel):
    allowed: bool
    risk_score: float
    denial_reason: str | None = None
    matched_rules: list[str] = []
    latency_ms: int = 0

    @property
    def action(self) -> str:
        return "pass" if self.allowed else "block"


class ScanOutputResponse(ScanResponse):
    pii_found: list[dict[str, Any]] = []
    secrets_found: list[dict[str, Any]] = []


class ClampdBlockedError(Exception):
    """Raised when Clampd denies a tool call."""

    def __init__(self, reason: str, *, risk_score: float = 1.0, response: ProxyResponse | ScanResponse | ScanOutputResponse | None = None):
        self.reason = reason
        self.risk_score = risk_score
        self.response = response
        self.matched_rules: list[str] = response.matched_rules if response else []
        self.session_flags: list[str] = getattr(response, "session_flags", []) if response else []
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        msg = f"Blocked: {self.reason} (risk={self.risk_score:.2f})"
        if self.matched_rules:
            msg += f" | rules: {', '.join(self.matched_rules)}"
        if self.session_flags:
            msg += f" | session: {', '.join(self.session_flags)}"
        return msg


class ClampdClient:
    """HTTP client for the Clampd gateway."""

    def __init__(
        self,
        *,
        gateway_url: str = "http://localhost:8080",
        agent_id: str,
        api_key: str | None = None,
        secret: str | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 0,
        base_delay_ms: int = 500,
        cb_threshold: int = 5,
        cb_reset_timeout_ms: int = 30000,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id
        self.api_key = api_key or os.environ.get("CLAMPD_API_KEY", "")
        self.session_id = session_id
        self._secret = secret
        self._jwt_ttl = 3600
        self._jwt = make_agent_jwt(agent_id, secret=secret)
        self._jwt_expires_at = time.monotonic() + self._jwt_ttl
        self._http = httpx.Client(timeout=timeout)
        # Retry config
        self.max_retries = max_retries
        self.base_delay_ms = base_delay_ms
        # Circuit breaker config
        self._cb_threshold = cb_threshold
        self._cb_reset_timeout_ms = cb_reset_timeout_ms
        self._cb_failures = 0
        self._cb_opened_at: float = 0.0
        self._cb_state: str = "closed"  # closed, open, half-open

    def _get_jwt(self) -> str:
        """Return a valid JWT, regenerating if within 60s of expiry."""
        if time.monotonic() >= self._jwt_expires_at - 60:
            self._jwt = make_agent_jwt(self.agent_id, secret=self._secret)
            self._jwt_expires_at = time.monotonic() + self._jwt_ttl
        return self._jwt

    def _headers(self, *, tools: list[str] | None = None) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._get_jwt()}",
            "X-AG-Key": self.api_key,
            "Content-Type": "application/json",
        }
        if self.session_id:
            h["X-AG-Session"] = self.session_id
        if tools:
            h["X-AG-Authorized-Tools"] = ",".join(tools)
        return h

    def proxy(self, tool: str, params: dict[str, Any], target_url: str = "", prompt_context: str | None = None, tool_descriptor_hash: str | None = None, *, authorized_tools: list[str] | None = None) -> ProxyResponse:
        """Evaluate a tool call through the Clampd gateway.

        When target_url is empty (default), the gateway runs evaluate-only mode:
        classify + policy check, no token exchange or forwarding. The tool
        executes locally in the agent's runtime.

        When target_url is set, the gateway also exchanges a micro-token and
        forwards the request to the target, inspecting the response.

        When authorized_tools is provided, the gateway locks this session
        to only allow the specified tools (prevents tool surface expansion attacks).
        """
        body: dict[str, Any] = {"tool": tool, "params": params, "target_url": target_url}
        if prompt_context:
            body["prompt_context"] = prompt_context
        if tool_descriptor_hash:
            body["tool_descriptor_hash"] = tool_descriptor_hash
        # Send delegation context if a chain exists.
        # Auto-append this agent to the chain if not already present.
        ctx = get_delegation()
        if ctx is not None and ctx.chain:
            chain = ctx.chain
            if self.agent_id and (not chain or chain[-1] != self.agent_id):
                chain = chain + [self.agent_id]
            if len(chain) > 1:
                body["delegation_chain"] = chain
                body["delegation_trace_id"] = ctx.trace_id
        return self._post("/v1/proxy", body, authorized_tools=authorized_tools)

    @staticmethod
    def delegation_headers() -> dict[str, str]:
        """Get delegation headers for cross-service HTTP calls."""
        ctx = get_delegation()
        if ctx is None or len(ctx.chain) < 2:
            return {}
        return {
            "X-Clampd-Delegation-Trace": ctx.trace_id,
            "X-Clampd-Delegation-Chain": ",".join(ctx.chain),
            "X-Clampd-Delegation-Confidence": ctx.confidence,
        }

    def verify(self, tool: str, params: dict[str, Any], target_url: str = "") -> ProxyResponse:
        return self._post("/v1/verify", {"tool": tool, "params": params, "target_url": target_url})

    def inspect(self, tool: str, response_data: Any, request_id: str = "", scope_token: str = "") -> ProxyResponse:
        """Inspect a tool response for PII, anomalies, or policy violations.

        When scope_token is provided (from a prior proxy() call),
        the gateway can verify this response came from a Clampd-approved call.
        """
        body: dict[str, Any] = {"tool": tool, "response_data": response_data}
        if request_id:
            body["request_id"] = request_id
        if scope_token:
            body["scope_token"] = scope_token
        return self._post("/v1/inspect", body)

    def scan_input(self, text: str, message_count: int = 0) -> ScanResponse:
        """Scan prompt text for injection/policy violations."""
        body: dict[str, Any] = {"text": text}
        if message_count:
            body["message_count"] = message_count
        proxy_resp = self._post("/v1/scan-input", body)
        return ScanResponse.model_validate(proxy_resp.model_dump())

    def scan_output(self, text: str, request_id: str = "") -> ScanOutputResponse:
        """Scan LLM response text for PII, secrets, policy violations.

        Returns a typed ScanOutputResponse with pii_found and secrets_found fields.
        """
        body: dict[str, Any] = {"text": text}
        if request_id:
            body["request_id"] = request_id
        try:
            resp = self._http.post(f"{self.gateway_url}/v1/scan-output", headers=self._headers(), json=body)
        except Exception:
            return ScanOutputResponse(allowed=False, risk_score=1.0, denial_reason="gateway_error")

        if resp.status_code == 200:
            return ScanOutputResponse.model_validate(resp.json())

        try:
            data = resp.json()
            reason = data.get("denial_reason") or data.get("error") or f"http_{resp.status_code}"
        except Exception:
            reason = f"http_{resp.status_code}"
        return ScanOutputResponse(allowed=False, risk_score=1.0, denial_reason=reason)

    # ── Circuit breaker ─────────────────────────────────────────────────

    def _cb_allow_request(self) -> bool:
        """Return True if the circuit breaker allows a request."""
        if self._cb_state == "closed":
            return True
        if self._cb_state == "open":
            elapsed_ms = (time.monotonic() - self._cb_opened_at) * 1000
            if elapsed_ms >= self._cb_reset_timeout_ms:
                self._cb_state = "half-open"
                return True
            return False
        # half-open: allow one probe request
        return True

    def _cb_record_success(self) -> None:
        """Record a successful request, resetting the circuit breaker."""
        self._cb_failures = 0
        self._cb_state = "closed"

    def _cb_record_failure(self) -> None:
        """Record a failed request, potentially opening the circuit breaker."""
        self._cb_failures += 1
        if self._cb_failures >= self._cb_threshold:
            self._cb_state = "open"
            self._cb_opened_at = time.monotonic()

    # ── HTTP post with retry + circuit breaker ───────────────────────────

    def _post(self, path: str, body: dict[str, Any], *, authorized_tools: list[str] | None = None) -> ProxyResponse:
        if not self._cb_allow_request():
            return ProxyResponse(
                request_id="error", allowed=False, risk_score=1.0,
                denial_reason="circuit_breaker_open", latency_ms=0,
            )

        last_result: ProxyResponse | None = None
        for attempt in range(1 + self.max_retries):
            retryable = False
            try:
                resp = self._http.post(
                    f"{self.gateway_url}{path}",
                    headers=self._headers(tools=authorized_tools),
                    json=body,
                )
            except httpx.TimeoutException:
                retryable = True
                last_result = ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_timeout", latency_ms=0,
                )
                self._cb_record_failure()
                if attempt < self.max_retries:
                    time.sleep(self.base_delay_ms * (2 ** attempt) / 1000)
                continue
            except httpx.ConnectError:
                retryable = True
                last_result = ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_unreachable", latency_ms=0,
                )
                self._cb_record_failure()
                if attempt < self.max_retries:
                    time.sleep(self.base_delay_ms * (2 ** attempt) / 1000)
                continue
            except Exception:
                self._cb_record_failure()
                return ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_error", latency_ms=0,
                )

            if resp.status_code == 200:
                self._cb_record_success()
                return ProxyResponse.model_validate(resp.json())

            # Retry on 5xx and 429; don't retry on other 4xx
            if resp.status_code == 429 or resp.status_code >= 500:
                retryable = True
                self._cb_record_failure()
            elif 400 <= resp.status_code < 500:
                # Client errors (except 429) are not retryable
                retryable = False

            # Extract denial_reason from gateway JSON response if available
            try:
                data = resp.json()
                error_code = data.get("error_code", "")
                error_msg = data.get("denial_reason") or data.get("error") or f"http_{resp.status_code}"
                if "InvalidSignature" in error_msg or "JWT validation failed" in error_msg:
                    if resp.status_code == 401:
                        error_msg = (
                            "Agent authentication failed. This usually means the agent is suspended "
                            "or the signing secret is incorrect. Check your agent status in the dashboard "
                            "or verify CLAMPD_AGENT_SECRET / secret= parameter."
                        )
                        error_code = error_code or "agent_auth_failed"
                reason = f"{error_code}: {error_msg}" if error_code else error_msg
            except Exception:
                reason = f"http_{resp.status_code}"

            last_result = ProxyResponse(
                request_id="error", allowed=False, risk_score=1.0,
                denial_reason=reason, latency_ms=0,
            )

            if not retryable or attempt >= self.max_retries:
                return last_result

            time.sleep(self.base_delay_ms * (2 ** attempt) / 1000)

        # Should not reach here, but safety fallback
        return last_result or ProxyResponse(
            request_id="error", allowed=False, risk_score=1.0,
            denial_reason="gateway_error", latency_ms=0,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ClampdClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncClampdClient:
    """Async HTTP client for the Clampd gateway (B2: async support)."""

    def __init__(
        self,
        *,
        gateway_url: str = "http://localhost:8080",
        agent_id: str,
        api_key: str | None = None,
        secret: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 0,
        base_delay_ms: int = 500,
        cb_threshold: int = 5,
        cb_reset_timeout_ms: int = 30000,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id
        self.api_key = api_key or os.environ.get("CLAMPD_API_KEY", "")
        self._secret = secret
        self._jwt_ttl = 3600
        # B4: Create JWT before httpx client — no resource leak if JWT fails
        self._jwt = make_agent_jwt(agent_id, secret=secret)
        self._jwt_expires_at = time.monotonic() + self._jwt_ttl
        self._http = httpx.AsyncClient(timeout=timeout)
        # Retry config
        self.max_retries = max_retries
        self.base_delay_ms = base_delay_ms
        # Circuit breaker config
        self._cb_threshold = cb_threshold
        self._cb_reset_timeout_ms = cb_reset_timeout_ms
        self._cb_failures = 0
        self._cb_opened_at: float = 0.0
        self._cb_state: str = "closed"

    def _get_jwt(self) -> str:
        """Return a valid JWT, regenerating if within 60s of expiry."""
        if time.monotonic() >= self._jwt_expires_at - 60:
            self._jwt = make_agent_jwt(self.agent_id, secret=self._secret)
            self._jwt_expires_at = time.monotonic() + self._jwt_ttl
        return self._jwt

    def _headers(self, *, tools: list[str] | None = None) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._get_jwt()}",
            "X-AG-Key": self.api_key,
            "Content-Type": "application/json",
        }
        if tools:
            h["X-AG-Authorized-Tools"] = ",".join(tools)
        return h

    async def proxy(
        self,
        tool: str,
        params: dict[str, Any],
        target_url: str = "",
        prompt_context: str | None = None,
        tool_descriptor_hash: str | None = None,
        *,
        authorized_tools: list[str] | None = None,
    ) -> ProxyResponse:
        """Evaluate a tool call through the Clampd gateway (async)."""
        body: dict[str, Any] = {
            "tool": tool,
            "params": params,
            "target_url": target_url,
        }
        if prompt_context:
            body["prompt_context"] = prompt_context
        if tool_descriptor_hash:
            body["tool_descriptor_hash"] = tool_descriptor_hash
        ctx = get_delegation()
        if ctx is not None and len(ctx.chain) > 1:
            body["delegation_chain"] = ctx.chain
            body["delegation_trace_id"] = ctx.trace_id
        return await self._post("/v1/proxy", body, authorized_tools=authorized_tools)

    async def verify(
        self,
        tool: str,
        params: dict[str, Any],
        target_url: str = "",
    ) -> ProxyResponse:
        return await self._post(
            "/v1/verify",
            {"tool": tool, "params": params, "target_url": target_url},
        )

    async def inspect(
        self,
        tool: str,
        response_data: Any,
        request_id: str = "",
        scope_token: str = "",
    ) -> ProxyResponse:
        """Inspect a tool response (async)."""
        body: dict[str, Any] = {
            "tool": tool,
            "response_data": response_data,
        }
        if request_id:
            body["request_id"] = request_id
        if scope_token:
            body["scope_token"] = scope_token
        return await self._post("/v1/inspect", body)

    async def scan_input(
        self, text: str, message_count: int = 0
    ) -> ScanResponse:
        """Scan prompt text for injection/policy violations (async)."""
        body: dict[str, Any] = {"text": text}
        if message_count:
            body["message_count"] = message_count
        proxy_resp = await self._post("/v1/scan-input", body)
        return ScanResponse.model_validate(proxy_resp.model_dump())

    async def scan_output(
        self, text: str, request_id: str = ""
    ) -> ScanOutputResponse:
        """Scan LLM response text for PII, secrets, policy violations (async)."""
        body: dict[str, Any] = {"text": text}
        if request_id:
            body["request_id"] = request_id
        try:
            resp = await self._http.post(
                f"{self.gateway_url}/v1/scan-output",
                headers=self._headers(),
                json=body,
            )
        except Exception:
            return ScanOutputResponse(allowed=False, risk_score=1.0, denial_reason="gateway_error")

        if resp.status_code == 200:
            return ScanOutputResponse.model_validate(resp.json())

        try:
            data: dict[str, Any] = resp.json()
            reason = (
                data.get("denial_reason")
                or data.get("error")
                or f"http_{resp.status_code}"
            )
        except Exception:
            reason = f"http_{resp.status_code}"
        return ScanOutputResponse(allowed=False, risk_score=1.0, denial_reason=reason)

    # ── Circuit breaker ─────────────────────────────────────────────────

    def _cb_allow_request(self) -> bool:
        """Return True if the circuit breaker allows a request."""
        if self._cb_state == "closed":
            return True
        if self._cb_state == "open":
            elapsed_ms = (time.monotonic() - self._cb_opened_at) * 1000
            if elapsed_ms >= self._cb_reset_timeout_ms:
                self._cb_state = "half-open"
                return True
            return False
        # half-open: allow one probe request
        return True

    def _cb_record_success(self) -> None:
        self._cb_failures = 0
        self._cb_state = "closed"

    def _cb_record_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= self._cb_threshold:
            self._cb_state = "open"
            self._cb_opened_at = time.monotonic()

    # ── HTTP post with retry + circuit breaker ───────────────────────────

    async def _post(
        self, path: str, body: dict[str, Any], *, authorized_tools: list[str] | None = None
    ) -> ProxyResponse:
        if not self._cb_allow_request():
            return ProxyResponse(
                request_id="error", allowed=False, risk_score=1.0,
                denial_reason="circuit_breaker_open", latency_ms=0,
            )

        last_result: ProxyResponse | None = None
        for attempt in range(1 + self.max_retries):
            retryable = False
            try:
                resp = await self._http.post(
                    f"{self.gateway_url}{path}",
                    headers=self._headers(tools=authorized_tools),
                    json=body,
                )
            except httpx.TimeoutException:
                retryable = True
                last_result = ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_timeout", latency_ms=0,
                )
                self._cb_record_failure()
                if attempt < self.max_retries:
                    await asyncio.sleep(self.base_delay_ms * (2 ** attempt) / 1000)
                continue
            except httpx.ConnectError:
                retryable = True
                last_result = ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_unreachable", latency_ms=0,
                )
                self._cb_record_failure()
                if attempt < self.max_retries:
                    await asyncio.sleep(self.base_delay_ms * (2 ** attempt) / 1000)
                continue
            except Exception:
                self._cb_record_failure()
                return ProxyResponse(
                    request_id="error", allowed=False, risk_score=1.0,
                    denial_reason="gateway_error", latency_ms=0,
                )

            if resp.status_code == 200:
                self._cb_record_success()
                return ProxyResponse.model_validate(resp.json())

            # Retry on 5xx and 429; don't retry on other 4xx
            if resp.status_code == 429 or resp.status_code >= 500:
                retryable = True
                self._cb_record_failure()
            elif 400 <= resp.status_code < 500:
                retryable = False

            try:
                data = resp.json()
                error_code = data.get("error_code", "")
                error_msg = (
                    data.get("denial_reason")
                    or data.get("error")
                    or f"http_{resp.status_code}"
                )
                if "InvalidSignature" in error_msg or "JWT validation failed" in error_msg:
                    if resp.status_code == 401:
                        error_msg = (
                            "Agent authentication failed. This usually means the agent is suspended "
                            "or the signing secret is incorrect. Check your agent status in the dashboard "
                            "or verify CLAMPD_AGENT_SECRET / secret= parameter."
                        )
                        error_code = error_code or "agent_auth_failed"
                reason = f"{error_code}: {error_msg}" if error_code else error_msg
            except Exception:
                reason = f"http_{resp.status_code}"

            last_result = ProxyResponse(
                request_id="error", allowed=False, risk_score=1.0,
                denial_reason=reason, latency_ms=0,
            )

            if not retryable or attempt >= self.max_retries:
                return last_result

            await asyncio.sleep(self.base_delay_ms * (2 ** attempt) / 1000)

        return last_result or ProxyResponse(
            request_id="error", allowed=False, risk_score=1.0,
            denial_reason="gateway_error", latency_ms=0,
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncClampdClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
