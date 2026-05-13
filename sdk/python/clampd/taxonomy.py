"""Clampd tool classification taxonomy (Python mirror).

The ``TAXONOMY`` dict is codegen'd from the canonical source of truth
(``services/crates/ag-common/src/categories.toml``) by ag-common's
``build.rs`` and lives in ``clampd/_generated_taxonomy.py``. Edit the TOML,
not the generated file. Only the enums below and the helpers at the bottom
are hand-written — if the TOML gains a new category/subcategory/operation,
add it to the matching enum here by hand.

The three-level shape is:

    category -> subcategory -> operation

Every tool registered with Clampd must map to exactly one
``(category, subcategory, operation)`` triple. Rules, thresholds, compliance
mappings, and dashboard UX all derive from this taxonomy.

Because subcategory and operation validity depends on the parent category,
this module exposes flat enums covering every value across all parents plus
runtime validation helpers (``validate`` / ``compute_scope``). Use them to
fail fast on invalid combinations before calling ``register_tool``.
"""

from __future__ import annotations

import enum

# ── Flat enums ─────────────────────────────────────────────────────────


class Category(str, enum.Enum):
    """Top-level tool category.

    Mirrors ``[category.<cat>]`` tables in ``categories.toml``.
    """

    COMMS = "comms"
    DB = "db"
    EXEC = "exec"
    FS = "fs"
    NET = "net"
    AUTH = "auth"
    LLM = "llm"
    CLOUD = "cloud"
    SCM = "scm"
    BROWSER = "browser"
    AGENT = "agent"
    PAYMENT = "payment"


class Subcategory(str, enum.Enum):
    """Subcategory within a category.

    Flat union across all categories. Use :func:`validate` to ensure the
    subcategory is valid for the chosen category.
    """

    # comms
    EMAIL = "email"
    SLACK = "slack"
    SMS = "sms"
    NOTIFICATION = "notification"
    MESSAGING = "messaging"
    # db
    QUERY = "query"
    MUTATE = "mutate"
    SCHEMA = "schema"
    # exec
    SHELL = "shell"
    CODE = "code"
    FUNCTION = "function"
    # fs
    FILE = "file"
    BLOB = "blob"
    # net
    HTTP = "http"
    DNS = "dns"
    SOCKET = "socket"
    # auth
    SECRET = "secret"
    CREDENTIAL = "credential"
    TOKEN = "token"
    OAUTH = "oauth"
    # llm
    INPUT = "input"
    OUTPUT = "output"
    EMBEDDING = "embedding"
    # cloud
    INFRA = "infra"
    IAM = "iam"
    DEPLOY = "deploy"
    # scm
    GIT = "git"
    # browser
    PAGE = "page"
    SCREENSHOT = "screenshot"
    # agent
    DELEGATE = "delegate"
    SPAWN = "spawn"
    A2A = "a2a"
    CONFIG = "config"
    # payment
    TRANSACTION = "transaction"
    BILLING = "billing"
    INVOICE = "invoice"


class Operation(str, enum.Enum):
    """Operation within a subcategory.

    Flat union across all subcategories. Use :func:`validate` to ensure the
    operation is valid for the chosen (category, subcategory) pair.
    """

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    RUN = "run"
    DESTRUCTIVE = "destructive"
    REFRESH = "refresh"


# ── Canonical tree (source of truth mirror) ────────────────────────────

# Imported from the generated module. The source of truth is
# ``services/crates/ag-common/src/categories.toml``; ag-common's build.rs
# regenerates ``_generated_taxonomy.py`` on TOML edits.
from ._generated_taxonomy import TAXONOMY as TAXONOMY  # noqa: F401


# ── Helpers ────────────────────────────────────────────────────────────


def _coerce(value: object) -> str:
    """Coerce an enum member or string to its string value."""
    if isinstance(value, enum.Enum):
        return str(value.value)
    return str(value)


def valid_subcategories(category: Category | str) -> list[str]:
    """Return the list of valid subcategories under *category*."""
    cat = _coerce(category)
    return list(TAXONOMY.get(cat, {}).keys())


def valid_operations(category: Category | str, subcategory: Subcategory | str) -> list[str]:
    """Return the list of valid operations under *category*/*subcategory*."""
    cat = _coerce(category)
    sub = _coerce(subcategory)
    return list(TAXONOMY.get(cat, {}).get(sub, []))


def validate(
    category: Category | str,
    subcategory: Subcategory | str,
    operation: Operation | str,
) -> bool:
    """Return True if the (category, subcategory, operation) triple is valid.

    Accepts either enum members or their string values for convenience.
    """
    cat = _coerce(category)
    sub = _coerce(subcategory)
    op = _coerce(operation)

    sub_map = TAXONOMY.get(cat)
    if sub_map is None:
        return False
    ops = sub_map.get(sub)
    if ops is None:
        return False
    return op in ops


def compute_scope(
    category: Category | str,
    subcategory: Subcategory | str,
    operation: Operation | str,
) -> str:
    """Compose the ``category:subcategory:operation`` scope string.

    Does not validate the triple — call :func:`validate` first if needed.
    """
    return f"{_coerce(category)}:{_coerce(subcategory)}:{_coerce(operation)}"


__all__ = [
    "Category",
    "Subcategory",
    "Operation",
    "TAXONOMY",
    "valid_subcategories",
    "valid_operations",
    "validate",
    "compute_scope",
]
