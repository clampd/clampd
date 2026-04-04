"""Automatic delegation chain tracking via contextvars."""
from __future__ import annotations

import contextvars
import uuid
from dataclasses import dataclass, field

MAX_DELEGATION_DEPTH = 5


@dataclass
class DelegationContext:
    """Tracks the delegation chain for cross-agent calls."""
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    chain: list[str] = field(default_factory=list)
    confidence: str = "verified"  # verified | inferred | declared

    @property
    def depth(self) -> int:
        return len(self.chain)

    @property
    def caller_agent_id(self) -> str | None:
        """The agent that initiated this delegation hop."""
        return self.chain[-2] if len(self.chain) >= 2 else None

    def has_cycle(self) -> bool:
        return len(self.chain) != len(set(self.chain))


# Per-request delegation context — propagates through async/await automatically
_delegation_ctx: contextvars.ContextVar[DelegationContext | None] = contextvars.ContextVar(
    'clampd_delegation', default=None
)


def get_delegation() -> DelegationContext | None:
    """Get current delegation context (if inside a delegated call)."""
    return _delegation_ctx.get()


def enter_delegation(agent_id: str) -> tuple[DelegationContext, contextvars.Token[DelegationContext | None]]:
    """Enter a delegation scope. Returns context and reset token."""
    parent = _delegation_ctx.get()
    if parent is not None:
        # Nested call — extend the chain
        ctx = DelegationContext(
            trace_id=parent.trace_id,
            chain=parent.chain + [agent_id],
            confidence=parent.confidence,
        )
    else:
        # Root call — start a new chain
        ctx = DelegationContext(
            trace_id=uuid.uuid4().hex[:16],
            chain=[agent_id],
        )
    token = _delegation_ctx.set(ctx)
    return ctx, token


def exit_delegation(token: contextvars.Token[DelegationContext | None]) -> None:
    """Exit delegation scope, restoring previous context."""
    _delegation_ctx.reset(token)
