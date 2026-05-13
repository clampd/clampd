"""Tests for ClampdClient retry and circuit breaker logic."""

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from clampd.client import ClampdClient
from tests.conftest import make_response


@pytest.fixture
def cb_client():
    """A ClampdClient with circuit breaker and retry configured, mocked HTTP."""
    with patch("clampd.client.httpx.Client") as MockHttpx:
        client = ClampdClient(
            agent_id="test-agent-cb",
            gateway_url="http://test:8080",
            max_retries=3,
            base_delay_ms=10,  # small for fast tests
            cb_threshold=3,
            cb_reset_timeout_ms=100,  # 100ms for fast tests
        )
        client._http = MockHttpx.return_value
        yield client


class TestCircuitBreaker:
    def test_cb_opens_after_threshold_failures(self, cb_client):
        """Circuit breaker opens after cb_threshold consecutive failures."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "server error"}
        cb_client._http.post.return_value = mock_resp

        # Make enough calls to trip the breaker (each call retries 3 times = 4 attempts)
        # threshold=3, so 3 failures open the breaker. One call with 4 attempts (all 500)
        # records 4 failures which exceeds threshold.
        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False

        # Breaker should now be open
        assert cb_client._cb_state == "open"

        # Next call should be rejected immediately without hitting HTTP
        cb_client._http.post.reset_mock()
        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        assert result.denial_reason == "circuit_breaker_open"
        cb_client._http.post.assert_not_called()

    def test_cb_allows_probe_after_reset_timeout(self, cb_client):
        """After reset timeout, circuit breaker transitions to half-open and allows a probe."""
        # Force breaker open
        cb_client._cb_state = "open"
        cb_client._cb_failures = 5
        cb_client._cb_opened_at = time.monotonic() - 1.0  # 1 second ago > 100ms timeout

        # Should transition to half-open and allow request
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        cb_client._http.post.return_value = mock_resp

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is True
        # Successful probe resets to closed
        assert cb_client._cb_state == "closed"
        assert cb_client._cb_failures == 0

    def test_cb_reopens_on_half_open_failure(self, cb_client):
        """If the probe request in half-open fails, breaker re-opens."""
        cb_client._cb_state = "open"
        cb_client._cb_failures = 5
        cb_client._cb_opened_at = time.monotonic() - 1.0  # past reset timeout

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "still broken"}
        cb_client._http.post.return_value = mock_resp

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        # Should be open again (failures exceeded threshold)
        assert cb_client._cb_state == "open"


class TestRetry:
    def test_retry_succeeds_after_transient_failure(self, cb_client):
        """Retry recovers from a transient 500 followed by 200."""
        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.json.return_value = {"error": "transient"}

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = make_response(allowed=True).model_dump()

        cb_client._http.post.side_effect = [fail_resp, ok_resp]

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is True
        assert cb_client._http.post.call_count == 2

    def test_retry_on_timeout_exception(self, cb_client):
        """Retry on httpx.TimeoutException."""
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = make_response(allowed=True).model_dump()

        cb_client._http.post.side_effect = [
            httpx.TimeoutException("timed out"),
            ok_resp,
        ]

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is True

    def test_retry_on_connect_error(self, cb_client):
        """Retry on httpx.ConnectError."""
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = make_response(allowed=True).model_dump()

        cb_client._http.post.side_effect = [
            httpx.ConnectError("refused"),
            ok_resp,
        ]

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is True

    def test_retry_on_429(self, cb_client):
        """Retry on 429 Too Many Requests."""
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.json.return_value = {"error": "rate limited"}

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = make_response(allowed=True).model_dump()

        cb_client._http.post.side_effect = [rate_limited, ok_resp]

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is True

    def test_no_retry_on_4xx(self, cb_client):
        """4xx errors (except 429) are not retried."""
        bad_req = MagicMock()
        bad_req.status_code = 400
        bad_req.json.return_value = {"error": "bad request"}
        cb_client._http.post.return_value = bad_req

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        # Should only be called once (no retries)
        assert cb_client._http.post.call_count == 1

    def test_no_retry_on_403(self, cb_client):
        """403 Forbidden is not retried."""
        forbidden = MagicMock()
        forbidden.status_code = 403
        forbidden.json.return_value = {"error": "forbidden"}
        cb_client._http.post.return_value = forbidden

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        assert cb_client._http.post.call_count == 1

    def test_no_retry_on_401(self, cb_client):
        """401 Unauthorized is not retried."""
        unauth = MagicMock()
        unauth.status_code = 401
        unauth.json.return_value = {"error": "unauthorized"}
        cb_client._http.post.return_value = unauth

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        assert cb_client._http.post.call_count == 1

    def test_no_retry_when_max_retries_zero(self):
        """With max_retries=0, no retries happen."""
        with patch("clampd.client.httpx.Client") as MockHttpx:
            client = ClampdClient(
                agent_id="test-agent",
                gateway_url="http://test:8080",
                max_retries=0,
            )
            client._http = MockHttpx.return_value

            fail_resp = MagicMock()
            fail_resp.status_code = 500
            fail_resp.json.return_value = {"error": "server error"}
            client._http.post.return_value = fail_resp

            result = client.proxy("test.tool", {"x": 1})
            assert result.allowed is False
            assert client._http.post.call_count == 1

    def test_exhausts_all_retries(self, cb_client):
        """When all retries fail, returns the last failure result."""
        fail_resp = MagicMock()
        fail_resp.status_code = 503
        fail_resp.json.return_value = {"error": "service unavailable"}
        cb_client._http.post.return_value = fail_resp

        result = cb_client.proxy("test.tool", {"x": 1})
        assert result.allowed is False
        # 1 initial + 3 retries = 4 attempts
        assert cb_client._http.post.call_count == 4
