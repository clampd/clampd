"""Shared test fixtures for Clampd Python SDK tests."""

import os
import uuid as _uuid
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import clampd.enroll as _enroll
from clampd._corrective import synthetic_denial
from clampd.client import AsyncClampdClient, ClampdClient, ProxyResponse

# Ensure all tests have a JWT signing secret available
os.environ.setdefault("JWT_SECRET", "test-secret-for-sdk-tests-32chars!")


@pytest.fixture(autouse=True)
def _offline_enrollment(request, monkeypatch):
    """clampd.init() enrolls over the network; stub it so unit tests run
    offline. Each logical name maps to a stable UUID + a real Ed25519 key.

    Skipped for the enrollment unit tests, which exercise the real enroll()."""
    if request.module.__name__.rsplit(".", 1)[-1] in ("test_enroll", "test_dsn"):
        yield
        return
    monkeypatch.setenv("CLAMPD_DSN", "clampd+http://ag_test_x@localhost:8080")
    keys: dict[str, Ed25519PrivateKey] = {}

    def fake_enroll(host, org_key, name):
        keys.setdefault(name, Ed25519PrivateKey.generate())
        agent_id = str(_uuid.uuid5(_uuid.NAMESPACE_DNS, name))
        return _enroll.Identity(private_key=keys[name], agent_id=agent_id)

    monkeypatch.setattr(_enroll, "enroll", fake_enroll)
    yield


@pytest.fixture(autouse=True)
def _default_signing_key(monkeypatch):
    """Many tests construct ClampdClient directly without a key. Inject a real
    Ed25519 key when none is given so JWT signing works without enrollment.
    An explicit signing_key (incl. a dummy) is passed through unchanged."""
    for cls in (ClampdClient, AsyncClampdClient):
        orig = cls.__init__

        def patched(self, *args, _orig=orig, signing_key=None, **kwargs):
            if signing_key is None:
                signing_key = Ed25519PrivateKey.generate()
            _orig(self, *args, signing_key=signing_key, **kwargs)

        monkeypatch.setattr(cls, "__init__", patched)
    yield


def make_response(allowed: bool = True, risk_score: float = 0.1, denial_reason: str | None = None) -> ProxyResponse:
    # v0.20: synthesize a typed StructuredDenial from the test's plain reason
    # string so legacy fixtures keep working without per-test rewrites.
    denial = synthetic_denial("TEST/blocked", denial_reason) if denial_reason else None
    return ProxyResponse(
        request_id="req-test-123",
        allowed=allowed,
        risk_score=risk_score,
        denial=denial,
        latency_ms=5,
        scope_granted="db:read" if allowed else None,
        tool_response="ok" if allowed else None,
    )


@pytest.fixture
def mock_client():
    """A ClampdClient with mocked HTTP transport."""
    with patch("clampd.client.httpx.Client") as MockHttpx:
        client = ClampdClient(
            agent_id="test-agent-001",
            gateway_url="http://test:8080",
            signing_key=Ed25519PrivateKey.generate(),
        )
        # The internal _http is the mock
        client._http = MockHttpx.return_value
        yield client
