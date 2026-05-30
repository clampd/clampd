"""Internal SDK exception types.

Kept separate from ``client.py`` (where ``ClampdBlockedError`` lives for
historical reasons) so new error types don't force a circular import.
"""

from __future__ import annotations


class ClampdEnrollError(Exception):
    """Raised when agent enrollment with the gateway fails."""


class ClampdClassificationError(ValueError):
    """Raised when a tool classification triple is invalid.

    Thrown by :func:`clampd.register_tool` when the provided
    ``(category, subcategory, operation)`` combination does not appear in
    the canonical taxonomy (``ag-common/src/categories.toml``).

    The message always lists valid alternatives so the caller can correct
    the call site without leaving the editor.
    """

    def __init__(
        self,
        message: str,
        *,
        category: str | None = None,
        subcategory: str | None = None,
        operation: str | None = None,
        valid: list[str] | None = None,
    ) -> None:
        self.category = category
        self.subcategory = subcategory
        self.operation = operation
        self.valid = list(valid or [])
        super().__init__(message)


class ClampdUnregisteredToolError(Exception):
    """Tool was called but no descriptor exists in the gateway."""

    def __init__(self, tool_name: str, *, hint: str | None = None):
        self.tool_name = tool_name
        self.hint = hint or (
            f"Call clampd.register_tool({tool_name!r}, category=..., "
            f"subcategory=..., operation=...) at module load time."
        )
        super().__init__(f"Tool {tool_name!r} is not registered with Clampd. {self.hint}")


class ClampdDescriptorMismatchError(Exception):
    """Tool was called with a descriptor hash that doesn't match any approved hash.

    Distinct from :class:`ClampdUnregisteredToolError` (which means the tool
    is unknown entirely) and from :class:`ClampdBlockedError` (which signals
    a policy / risk decision against an approved descriptor): this error
    means the tool *is* known, but its current descriptor hash is not on
    the approved list — most often the tool's name / description /
    parameter schema changed since the dashboard approved it (rug-pull
    detection) and the new version needs to be approved.
    """

    def __init__(
        self,
        tool_name: str,
        *,
        attempted_hash: str | None = None,
        hint: str | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.attempted_hash = attempted_hash
        if hint is not None:
            self.hint = hint
        elif attempted_hash:
            self.hint = (
                f"Approve hash {attempted_hash[:16]}... in the dashboard "
                f"for tool {tool_name!r}."
            )
        else:
            self.hint = (
                f"Approve the new descriptor hash for tool {tool_name!r} "
                f"in the dashboard."
            )
        super().__init__(
            f"Tool {tool_name!r} descriptor hash does not match any approved "
            f"version. {self.hint}"
        )


__all__ = [
    "ClampdClassificationError",
    "ClampdUnregisteredToolError",
    "ClampdDescriptorMismatchError",
]
