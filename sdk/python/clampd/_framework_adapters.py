"""Shared framework-tool adapters for the Clampd Python SDK.

Centralises tool-object introspection helpers so ``register_tool`` and
the per-framework callbacks (LangChain, CrewAI, ...) all extract the
same (name, description, parameter schema) triple — keeping the
``descriptor_hash`` consistent across registration and runtime.
"""

from __future__ import annotations

from typing import Any


def _schema_to_dict(args_schema: Any) -> dict[str, Any]:
    """Convert a pydantic args_schema (v1 or v2) to a JSON Schema dict.

    Returns ``{}`` when no schema is available, when the schema call
    raises, or when it returns a non-dict — ``contract_hash`` treats
    that as the explicit "empty contract" case so the gateway can still
    detect rug-pulls rather than silently skipping.
    """
    if args_schema is None:
        return {}
    if hasattr(args_schema, "model_json_schema"):  # pydantic v2
        try:
            result = args_schema.model_json_schema()
        except Exception:
            return {}
        return result if isinstance(result, dict) else {}
    if hasattr(args_schema, "schema"):  # pydantic v1
        try:
            result = args_schema.schema()
        except Exception:
            return {}
        return result if isinstance(result, dict) else {}
    return {}


def _extract_tool_contract(
    obj: Any,
) -> tuple[str, str, dict[str, Any]] | None:
    """Inspect ``obj`` and return ``(name, description, param_schema_dict)``
    if it looks like a recognised framework tool object, else ``None``.

    Recognised types:
      - LangChain ``BaseTool`` (duck-typed via ``name``/``description``/
        ``args_schema`` attributes).
      - OpenAI tool dict: ``{"type": "function", "function": {...}}``.
      - Anthropic tool dict: ``{"name": ..., "input_schema": ...}``.
    """
    # OpenAI tool dict
    if (
        isinstance(obj, dict)
        and obj.get("type") == "function"
        and isinstance(obj.get("function"), dict)
    ):
        fn = obj["function"]
        name = fn.get("name", "")
        description = fn.get("description", "") or ""
        param_schema = fn.get("parameters", {}) or {}
        return name, description, param_schema

    # Anthropic tool dict
    if (
        isinstance(obj, dict)
        and "name" in obj
        and "input_schema" in obj
    ):
        name = obj.get("name", "")
        description = obj.get("description", "") or ""
        param_schema = obj.get("input_schema", {}) or {}
        return name, description, param_schema

    # LangChain BaseTool (duck-typed)
    if (
        hasattr(obj, "name")
        and hasattr(obj, "description")
        and hasattr(obj, "args_schema")
    ):
        raw_name = getattr(obj, "name", "")
        raw_description = getattr(obj, "description", "") or ""
        name = raw_name if isinstance(raw_name, str) else str(raw_name)
        description = (
            raw_description if isinstance(raw_description, str) else str(raw_description)
        )
        param_schema = _schema_to_dict(getattr(obj, "args_schema", None))
        return name, description, param_schema

    return None


__all__ = ["_schema_to_dict", "_extract_tool_contract"]
