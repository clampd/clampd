"""Tests for clampd.client - HTTP gateway client."""

from unittest.mock import MagicMock, patch

from clampd.client import ClampdBlockedError, ClampdClient
from tests.conftest import make_response


class TestClampdClient:
    def test_proxy_sends_correct_body(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response().model_dump()
        mock_client._http.post.return_value = mock_resp

        mock_client.proxy("database.query", {"query": "SELECT 1"}, "http://tool:5555")

        call_args = mock_client._http.post.call_args
        assert "/v1/proxy" in call_args[0][0]
        body = call_args[1]["json"]
        assert body["tool"] == "database.query"
        assert body["params"]["query"] == "SELECT 1"
        assert body["target_url"] == "http://tool:5555"

    def test_proxy_returns_response_on_200(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        mock_client._http.post.return_value = mock_resp

        result = mock_client.proxy("db.query", {"q": "test"})
        assert result.allowed is True
        assert result.risk_score == 0.1

    def test_proxy_returns_blocked_on_http_error(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "internal failure"}
        mock_client._http.post.return_value = mock_resp

        result = mock_client.proxy("db.query", {"q": "test"})
        assert result.allowed is False
        assert result.risk_score == 1.0
        assert result.denial_reason == "internal failure"

    def test_proxy_returns_generic_error_on_network_failure(self, mock_client):
        mock_client._http.post.side_effect = Exception("Connection refused")

        result = mock_client.proxy("db.query", {"q": "test"})
        assert result.allowed is False
        assert result.denial_reason == "gateway_error"

    def test_verify_calls_verify_endpoint(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response().model_dump()
        mock_client._http.post.return_value = mock_resp

        mock_client.verify("db.query", {"q": "test"})

        call_args = mock_client._http.post.call_args
        assert "/v1/verify" in call_args[0][0]

    def test_context_manager(self):
        with patch("clampd.client.httpx.Client"):
            with ClampdClient(agent_id="test") as client:
                assert client is not None


class TestClampdBlockedError:
    def test_string_reason(self):
        err = ClampdBlockedError("too dangerous", risk_score=0.95)
        assert "too dangerous" in str(err)
        assert err.risk_score == 0.95
        assert err.response is None

    def test_with_response(self):
        resp = make_response(allowed=False, denial_reason="policy violation", risk_score=0.8)
        err = ClampdBlockedError("policy violation", risk_score=0.8, response=resp)
        assert err.response is resp
        assert err.risk_score == 0.8
