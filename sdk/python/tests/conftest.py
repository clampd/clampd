"""Shared test fixtures for Clampd Python SDK tests."""

import os
from unittest.mock import patch

import pytest

from clampd.client import ClampdClient, ProxyResponse

# Ensure all tests have a JWT signing secret available
os.environ.setdefault("JWT_SECRET", "test-secret-for-sdk-tests-32chars!")


def make_response(allowed: bool = True, risk_score: float = 0.1, denial_reason: str | None = None) -> ProxyResponse:
    return ProxyResponse(
        request_id="req-test-123",
        allowed=allowed,
        risk_score=risk_score,
        denial_reason=denial_reason,
        latency_ms=5,
        scope_granted="db:read" if allowed else None,
        tool_response="ok" if allowed else None,
    )


@pytest.fixture
def mock_client():
    """A ClampdClient with mocked HTTP transport."""
    with patch("clampd.client.httpx.Client") as MockHttpx:
        client = ClampdClient(agent_id="test-agent-001", gateway_url="http://test:8080")
        # The internal _http is the mock
        client._http = MockHttpx.return_value
        yield client
