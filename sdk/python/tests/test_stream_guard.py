"""Tests for clampd.stream_guard — streaming tool call interception."""

from unittest.mock import MagicMock, patch

import pytest

from clampd.client import ClampdBlockedError, ClampdClient
from clampd.stream_guard import guard_anthropic_stream, guard_openai_stream
from tests.conftest import make_response


@pytest.fixture
def mock_client():
    """A ClampdClient with mocked HTTP transport."""
    with patch("clampd.client.httpx.Client") as MockHttpx:
        client = ClampdClient(agent_id="test-agent-stream", gateway_url="http://test:8080")
        client._http = MockHttpx.return_value
        yield client


def _make_openai_text_chunk(content: str):
    """Create a mock OpenAI streaming chunk with text content."""
    chunk = MagicMock()
    choice = MagicMock()
    choice.delta.tool_calls = None
    choice.delta.content = content
    choice.finish_reason = None
    chunk.choices = [choice]
    return chunk


def _make_openai_tool_chunk(index: int, name: str | None = None, arguments: str | None = None, finish_reason: str | None = None):
    """Create a mock OpenAI streaming chunk with tool call data."""
    chunk = MagicMock()
    choice = MagicMock()
    choice.finish_reason = finish_reason

    tc = MagicMock()
    tc.index = index
    fn = MagicMock()
    fn.name = name
    fn.arguments = arguments
    tc.function = fn

    choice.delta.tool_calls = [tc]
    chunk.choices = [choice]
    return chunk


def _make_anthropic_text_event(text: str):
    """Create a mock Anthropic text event."""
    event = MagicMock()
    event.type = "content_block_delta"
    event.delta.type = "text_delta"
    event.delta.text = text
    return event


def _make_anthropic_tool_start(name: str):
    """Create a mock Anthropic content_block_start for tool_use."""
    event = MagicMock()
    event.type = "content_block_start"
    event.content_block.type = "tool_use"
    event.content_block.name = name
    return event


def _make_anthropic_tool_delta(partial_json: str):
    """Create a mock Anthropic input_json_delta event."""
    event = MagicMock()
    event.type = "content_block_delta"
    event.delta.type = "input_json_delta"
    event.delta.partial_json = partial_json
    return event


def _make_anthropic_block_stop():
    """Create a mock Anthropic content_block_stop event."""
    event = MagicMock()
    event.type = "content_block_stop"
    return event


class TestOpenAIStreamGuard:
    def test_text_chunks_pass_through(self, mock_client):
        """Text-only streaming chunks pass through immediately."""
        chunks = [
            _make_openai_text_chunk("Hello"),
            _make_openai_text_chunk(" world"),
        ]
        stream = iter(chunks)

        guarded = guard_openai_stream(stream, mock_client)
        results = list(guarded)

        assert len(results) == 2
        assert results[0].choices[0].delta.content == "Hello"
        assert results[1].choices[0].delta.content == " world"

    def test_tool_calls_buffered_and_guarded(self, mock_client):
        """Tool call chunks are buffered and proxied before yielding."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        mock_client._http.post.return_value = mock_resp

        chunks = [
            _make_openai_text_chunk("Let me help."),
            _make_openai_tool_chunk(0, name="search", arguments='{"q":'),
            _make_openai_tool_chunk(0, name=None, arguments='"test"}', finish_reason="tool_calls"),
        ]
        stream = iter(chunks)

        guarded = guard_openai_stream(stream, mock_client, authorized_tools=["search"])
        results = list(guarded)

        # Text chunk + 2 tool chunks (allowed)
        assert len(results) == 3
        # proxy() was called for the tool
        assert mock_client._http.post.call_count == 1

    def test_blocked_tool_call_raises(self, mock_client):
        """Blocked tool call raises ClampdBlockedError."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(
            allowed=False, denial_reason="dangerous tool", risk_score=0.95
        ).model_dump()
        mock_client._http.post.return_value = mock_resp

        chunks = [
            _make_openai_tool_chunk(0, name="rm_rf", arguments='{}', finish_reason="tool_calls"),
        ]
        stream = iter(chunks)

        guarded = guard_openai_stream(stream, mock_client, authorized_tools=["rm_rf"])

        with pytest.raises(ClampdBlockedError) as exc_info:
            list(guarded)

        assert "dangerous tool" in str(exc_info.value)

    def test_fail_open_on_gateway_error(self, mock_client):
        """With fail_open=True, gateway errors don't block the stream."""
        # Mock proxy() directly to raise a non-ClampdBlockedError exception
        mock_client.proxy = MagicMock(side_effect=ConnectionError("gateway down"))

        chunks = [
            _make_openai_tool_chunk(0, name="search", arguments='{"q":"x"}', finish_reason="tool_calls"),
        ]
        stream = iter(chunks)

        guarded = guard_openai_stream(
            stream, mock_client, fail_open=True, authorized_tools=["search"]
        )
        # Should not raise -- buffered chunks are yielded after all tool calls processed
        results = list(guarded)
        assert len(results) == 1

    def test_multiple_tool_calls(self, mock_client):
        """Multiple tool calls in the same stream are all guarded."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        mock_client._http.post.return_value = mock_resp

        chunks = [
            _make_openai_tool_chunk(0, name="search", arguments='{"q":"a"}'),
            _make_openai_tool_chunk(1, name="calc", arguments='{"expr":"1+1"}', finish_reason="tool_calls"),
        ]
        stream = iter(chunks)

        guarded = guard_openai_stream(stream, mock_client, authorized_tools=["search", "calc"])
        results = list(guarded)

        assert len(results) == 2
        # proxy() called once per tool
        assert mock_client._http.post.call_count == 2

    def test_proxies_original_attributes(self, mock_client):
        """The stream proxy proxies attributes from the original stream."""
        original = MagicMock()
        original.response = MagicMock()
        original.response.status_code = 200
        original.__iter__ = MagicMock(return_value=iter([]))

        guarded = guard_openai_stream(original, mock_client)
        # Should proxy .response attribute
        assert guarded.response == original.response


class TestAnthropicStreamGuard:
    def test_text_events_pass_through(self, mock_client):
        """Non-tool events pass through immediately."""
        events = [
            _make_anthropic_text_event("Hello"),
            _make_anthropic_text_event(" world"),
        ]
        stream = iter(events)

        guarded = guard_anthropic_stream(stream, mock_client)
        results = list(guarded)

        assert len(results) == 2

    def test_tool_use_buffered_and_guarded(self, mock_client):
        """Tool use blocks are buffered and proxied before yielding."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        mock_client._http.post.return_value = mock_resp

        events = [
            _make_anthropic_text_event("Let me search."),
            _make_anthropic_tool_start("search"),
            _make_anthropic_tool_delta('{"q":'),
            _make_anthropic_tool_delta('"test"}'),
            _make_anthropic_block_stop(),
        ]
        stream = iter(events)

        guarded = guard_anthropic_stream(stream, mock_client, authorized_tools=["search"])
        results = list(guarded)

        # 1 text event + 4 tool events (start, 2 deltas, stop)
        assert len(results) == 5
        assert mock_client._http.post.call_count == 1

    def test_blocked_tool_use_raises(self, mock_client):
        """Blocked tool use raises ClampdBlockedError."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(
            allowed=False, denial_reason="policy violation", risk_score=0.9
        ).model_dump()
        mock_client._http.post.return_value = mock_resp

        events = [
            _make_anthropic_tool_start("dangerous_tool"),
            _make_anthropic_tool_delta('{}'),
            _make_anthropic_block_stop(),
        ]
        stream = iter(events)

        guarded = guard_anthropic_stream(stream, mock_client, authorized_tools=["dangerous_tool"])

        with pytest.raises(ClampdBlockedError) as exc_info:
            list(guarded)

        assert "policy violation" in str(exc_info.value)

    def test_fail_open_on_gateway_error(self, mock_client):
        """With fail_open=True, gateway errors don't block the stream."""
        # Mock proxy() directly to raise a non-ClampdBlockedError exception
        mock_client.proxy = MagicMock(side_effect=ConnectionError("gateway down"))

        events = [
            _make_anthropic_tool_start("search"),
            _make_anthropic_tool_delta('{"q":"x"}'),
            _make_anthropic_block_stop(),
        ]
        stream = iter(events)

        guarded = guard_anthropic_stream(
            stream, mock_client, fail_open=True, authorized_tools=["search"]
        )
        # Should not raise; in fail_open mode, buffered events are NOT yielded
        results = list(guarded)
        assert len(results) == 0

    def test_mixed_text_and_tool(self, mock_client):
        """Text events interleaved with tool blocks work correctly."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = make_response(allowed=True).model_dump()
        mock_client._http.post.return_value = mock_resp

        events = [
            _make_anthropic_text_event("Before tool"),
            _make_anthropic_tool_start("calc"),
            _make_anthropic_tool_delta('{"expr":"2+2"}'),
            _make_anthropic_block_stop(),
            _make_anthropic_text_event("After tool"),
        ]
        stream = iter(events)

        guarded = guard_anthropic_stream(stream, mock_client, authorized_tools=["calc"])
        results = list(guarded)

        # 2 text events + 3 tool events
        assert len(results) == 5
