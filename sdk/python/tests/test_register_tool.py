"""Tests for clampd.register_tool — explicit tool classification at import."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

import clampd
from clampd import (
    Category,
    ClampdClassificationError,
    Operation,
    Subcategory,
)
from clampd.taxonomy import TAXONOMY, compute_scope, validate


# ── Taxonomy internal-consistency tests ────────────────────────────────


class TestTaxonomy:
    def test_all_categories_have_at_least_one_subcategory(self):
        for cat, subs in TAXONOMY.items():
            assert subs, f"Category {cat!r} has no subcategories"

    def test_all_subcategories_have_at_least_one_operation(self):
        for cat, subs in TAXONOMY.items():
            for sub, ops in subs.items():
                assert ops, f"Subcategory {cat}.{sub} has no operations"

    def test_every_category_enum_value_in_taxonomy(self):
        for member in Category:
            assert member.value in TAXONOMY, (
                f"Category.{member.name} missing from TAXONOMY"
            )

    def test_compute_scope_string(self):
        scope = compute_scope(Category.DB, Subcategory.QUERY, Operation.READ)
        assert scope == "db:query:read"

    def test_validate_accepts_known_triple(self):
        assert validate(Category.DB, Subcategory.QUERY, Operation.READ) is True

    def test_validate_rejects_bad_operation(self):
        # fs.file does not permit run
        assert validate("fs", "file", "run") is False

    def test_validate_rejects_bad_subcategory_for_category(self):
        # db has no slack subcategory
        assert validate("db", "slack", "read") is False

    def test_validate_rejects_unknown_category(self):
        assert validate("made_up", "query", "read") is False


# ── register_tool tests ────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Give every test a known clean env."""
    # SDK→gateway only as of v0.16.0 — no dashboard URL, no org_id required.
    monkeypatch.setenv("CLAMPD_GATEWAY_URL", "http://gateway-test:8080")
    monkeypatch.setenv("CLAMPD_API_KEY", "clmpd_test_key")
    monkeypatch.delenv("CLAMPD_DASHBOARD_URL", raising=False)
    monkeypatch.delenv("CLAMPD_ORG_ID", raising=False)
    # Avoid leaking _shared_config across tests
    clampd._reset()
    yield
    clampd._reset()


class TestRegisterToolValid:
    def test_valid_triple_posts_expected_body(self):
        with patch("httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp

            clampd.register_tool(
                "db.run_query",
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation=Operation.READ,
                description="Read-only SQL",
            )

        assert mock_post.called
        url = mock_post.call_args[0][0]
        # SDK→gateway only — no dashboard URL, no /orgs/ in path.
        assert url == "http://gateway-test:8080/v1/register"

        body = mock_post.call_args[1]["json"]
        # Gateway resolves org from X-AG-Key, computes scope + descriptor_hash
        # server-side, returns them in the response. Body is purely the
        # descriptor contract.
        assert body == {
            "name": "db.run_query",
            "category": "db",
            "subcategory": "query",
            "operation": "read",
            "description": "Read-only SQL",
            "param_schema": {},
        }

        headers = mock_post.call_args[1]["headers"]
        assert headers["Content-Type"] == "application/json"
        assert headers["X-AG-Key"] == "clmpd_test_key"

    def test_string_values_coerced_to_enums(self):
        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            # Pass strings; register_tool should accept and coerce.
            clampd.register_tool(
                "slack.post_message",
                category="comms",           # type: ignore[arg-type]
                subcategory="slack",        # type: ignore[arg-type]
                operation="send",           # type: ignore[arg-type]
            )
        body = mock_post.call_args[1]["json"]
        assert body["category"] == "comms"
        assert body["subcategory"] == "slack"
        assert body["operation"] == "send"

    def test_logs_info_on_success(self, caplog):
        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            with caplog.at_level(logging.INFO, logger="clampd"):
                clampd.register_tool(
                    "fs.write_file",
                    category=Category.FS,
                    subcategory=Subcategory.FILE,
                    operation=Operation.WRITE,
                )
        assert any(
            "fs.write_file" in r.getMessage() and "fs:file:write" in r.getMessage()
            for r in caplog.records
        )


class TestRegisterToolInvalid:
    def test_invalid_operation_for_subcategory_raises(self):
        # db.query allows "read" only, not "write"
        with pytest.raises(ClampdClassificationError) as excinfo:
            clampd.register_tool(
                "db.bad",
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation=Operation.WRITE,
            )
        msg = str(excinfo.value)
        assert "db:query" in msg
        assert "read" in msg  # valid ops listed

    def test_invalid_subcategory_for_category_raises(self):
        # db has no "slack" subcategory
        with pytest.raises(ClampdClassificationError) as excinfo:
            clampd.register_tool(
                "db.bad",
                category=Category.DB,
                subcategory=Subcategory.SLACK,
                operation=Operation.READ,
            )
        msg = str(excinfo.value)
        assert "slack" in msg
        assert "db" in msg

    def test_unknown_category_string_raises(self):
        with pytest.raises(ClampdClassificationError):
            clampd.register_tool(
                "whatever",
                category="made_up_category",          # type: ignore[arg-type]
                subcategory=Subcategory.QUERY,
                operation=Operation.READ,
            )

    def test_unknown_operation_string_raises(self):
        with pytest.raises(ClampdClassificationError):
            clampd.register_tool(
                "whatever",
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation="teleport",                 # type: ignore[arg-type]
            )

    def test_invalid_triple_does_not_hit_network(self):
        with patch("httpx.post") as mock_post:
            with pytest.raises(ClampdClassificationError):
                clampd.register_tool(
                    "db.bad",
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.DESTRUCTIVE,
                )
        assert not mock_post.called


class TestRegisterToolNetworkTolerance:
    def test_backend_unreachable_logs_warning_does_not_raise(self, caplog):
        with patch("httpx.post", side_effect=OSError("connection refused")):
            with caplog.at_level(logging.WARNING, logger="clampd"):
                # Must not raise
                clampd.register_tool(
                    "db.query_safe",
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                )
        assert any(
            "gateway unreachable" in r.getMessage() for r in caplog.records
        )

    def test_backend_returns_500_logs_warning_does_not_raise(self, caplog):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "db down"}
        mock_resp.text = '{"error":"db down"}'

        with patch("httpx.post", return_value=mock_resp):
            with caplog.at_level(logging.WARNING, logger="clampd"):
                clampd.register_tool(
                    "db.query_safe",
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                )
        assert any(
            "returned 500" in r.getMessage() for r in caplog.records
        )

    def test_missing_api_key_skips_post_with_warning(self, monkeypatch, caplog):
        # As of v0.16, the gateway resolves org from the X-AG-Key. With no
        # API key set the SDK can't authenticate, so it logs and skips the
        # network call (taxonomy validation + _registered_descriptors cache
        # already happened before this point).
        monkeypatch.delenv("CLAMPD_API_KEY", raising=False)
        with patch("httpx.post") as mock_post:
            with caplog.at_level(logging.WARNING, logger="clampd"):
                clampd.register_tool(
                    "db.no_key",
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                )
        assert not mock_post.called
        assert any(
            "CLAMPD_API_KEY not set" in r.getMessage()
            for r in caplog.records
        )


# ── register_tool framework-object overload tests ──────────────────────


class TestRegisterToolFromFrameworkObject:
    """Verify the (tool_object) overload of register_tool extracts the
    same (name, description, param_schema) triple that the per-framework
    callbacks use — keeping the descriptor_hash stable across registration
    and runtime.
    """

    def _post_body(self, mock_post):
        assert mock_post.called, "register_tool did not POST to backend"
        return mock_post.call_args[1]["json"]

    def test_langchain_basetool_overload(self):
        """Pass a langchain-style BaseTool — the descriptor_hash POSTed
        must equal the one ``langchain_callback.on_tool_start`` would
        forward via ``_registered_descriptors``."""
        # Build a minimal BaseTool stub. Avoids a hard runtime dep on
        # langchain — duck-typed via name/description/args_schema as
        # ``_extract_tool_contract`` does.
        tool_obj = MagicMock()
        tool_obj.name = "lc.web_search"
        tool_obj.description = "Search the public web"
        # No args_schema → param_schema becomes {} (matches
        # _schema_to_dict(None))
        tool_obj.args_schema = None

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            clampd.register_tool(
                tool_obj,
                category=Category.NET,
                subcategory=Subcategory.HTTP,
                operation=Operation.READ,
            )

        body = self._post_body(mock_post)
        assert body["name"] == "lc.web_search"
        assert body["description"] == "Search the public web"
        assert body["param_schema"] == {}
        # Gateway computes scope + descriptor_hash server-side; SDK no
        # longer pre-asserts them in the request body. The canonical hash
        # is still recorded in _registered_descriptors so framework
        # callbacks can forward it.
        assert "scope" not in body
        assert "descriptor_hash" not in body
        assert "source" not in body

        from clampd.contract_hash import contract_hash
        expected = contract_hash("lc.web_search", "Search the public web", {})
        assert clampd._registered_descriptors["lc.web_search"] == expected

    def test_openai_tool_dict_overload(self):
        openai_tool = {
            "type": "function",
            "function": {
                "name": "openai.lookup_user",
                "description": "Look up a user by email",
                "parameters": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},
                    "required": ["email"],
                },
            },
        }
        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            clampd.register_tool(
                openai_tool,
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation=Operation.READ,
            )

        body = self._post_body(mock_post)
        assert body["name"] == "openai.lookup_user"
        assert body["description"] == "Look up a user by email"
        assert body["param_schema"] == openai_tool["function"]["parameters"]
        assert "descriptor_hash" not in body  # gateway computes server-side

        # SDK-recorded hash equals canonical (callback forwards this).
        from clampd.contract_hash import contract_hash
        expected = contract_hash(
            "openai.lookup_user",
            "Look up a user by email",
            openai_tool["function"]["parameters"],
        )
        assert clampd._registered_descriptors["openai.lookup_user"] == expected

    def test_anthropic_tool_dict_overload(self):
        anth_tool = {
            "name": "anth.run_query",
            "description": "Run an analytics SQL query",
            "input_schema": {
                "type": "object",
                "properties": {"sql": {"type": "string"}},
                "required": ["sql"],
            },
        }
        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            clampd.register_tool(
                anth_tool,
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation=Operation.READ,
            )

        body = self._post_body(mock_post)
        assert body["name"] == "anth.run_query"
        assert body["description"] == "Run an analytics SQL query"
        assert body["param_schema"] == anth_tool["input_schema"]
        assert "descriptor_hash" not in body  # gateway computes server-side

        from clampd.contract_hash import contract_hash
        expected = contract_hash(
            "anth.run_query",
            "Run an analytics SQL query",
            anth_tool["input_schema"],
        )
        assert clampd._registered_descriptors["anth.run_query"] == expected

    def test_typeerror_when_both_object_and_kwargs(self):
        """description= or param_schema= alongside a tool object is ambiguous."""
        openai_tool = {
            "type": "function",
            "function": {"name": "x", "description": "y", "parameters": {}},
        }
        with patch("httpx.post") as mock_post:
            with pytest.raises(TypeError, match="description.*param_schema|tool object"):
                clampd.register_tool(
                    openai_tool,
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                    description="overridden",
                )
            with pytest.raises(TypeError):
                clampd.register_tool(
                    openai_tool,
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                    param_schema={"type": "object"},
                )
        # No backend POST was made — both raised before I/O.
        assert not mock_post.called

    def test_typeerror_when_unrecognised_object(self):
        """Random objects without name/description/args_schema are rejected."""

        class NotATool:
            pass

        with patch("httpx.post") as mock_post:
            with pytest.raises(TypeError, match="unrecognised tool object"):
                clampd.register_tool(
                    NotATool(),
                    category=Category.DB,
                    subcategory=Subcategory.QUERY,
                    operation=Operation.READ,
                )
        assert not mock_post.called

    def test_string_form_still_works(self):
        """Backwards-compat: name + description= + param_schema= keeps working."""
        param_schema = {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
        }
        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            clampd.register_tool(
                "legacy.fetch",
                category=Category.DB,
                subcategory=Subcategory.QUERY,
                operation=Operation.READ,
                description="Fetch by id",
                param_schema=param_schema,
            )

        body = mock_post.call_args[1]["json"]
        assert body["name"] == "legacy.fetch"
        assert body["description"] == "Fetch by id"
        assert body["param_schema"] == param_schema
        assert "descriptor_hash" not in body  # gateway computes server-side

        from clampd.contract_hash import contract_hash
        expected = contract_hash("legacy.fetch", "Fetch by id", param_schema)
        assert clampd._registered_descriptors["legacy.fetch"] == expected
