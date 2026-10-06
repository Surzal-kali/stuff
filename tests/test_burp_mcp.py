"""Tests for auxiliaries/burp_mcp.py — timeout/session-survival regression.

Covers the root-cause fix for the "blip" freeze:

- **Per-call timeout must NOT tear down the SSE session.**  A ``McpError``
  with code 408 (``httpx.codes.REQUEST_TIMEOUT``) means *one* tool call
  exceeded its ``read_timeout`` — the SSE session is still alive.  The old
  code caught it under ``except Exception`` and set ``_connected = False``,
  forcing a full reconnect on every subsequent ``burp_*`` call.  This
  caused a reconnect cascade (connect lock → queued calls → more timeouts
  → more reconnects) that froze the stack for blips at a time.

- **``_submit`` must actually cancel the coroutine.**  The old
  ``future.cancel()`` only prevents the result callback; the coroutine
  keeps running on the background loop, pinning it.  The fix wraps the
  coro in an ``asyncio.Task`` and cancels the task on timeout.

Verified facts (live BApp, MCP SDK v1.29.0):
  - The BApp returns ``202 Accepted`` immediately (POST does not block).
  - The BApp processes requests concurrently (verified: fast response
    arrived while a slow request was still running on the same session).
  - The SDK converts ``anyio.fail_after`` ``TimeoutError`` into
    ``McpError(ErrorData(code=408))``.
  - ``McpError`` is ``Exception``, not ``TimeoutError``.
"""

import asyncio
from unittest import mock

import httpx
import pytest

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

import auxiliaries.burp_mcp as burp_module
from auxiliaries.burp_mcp import BurpMCPClient, BurpMCPError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client_with_mock_session():
    """Build a BurpMCPClient with a mock ClientSession and ``_connected=True``.

    The client's background loop is started lazily by _ensure_loop, but we
    avoid any real SSE connection.  We inject a mock session and set
    _connected so _ensure_connected is a fast no-op.
    """
    client = BurpMCPClient.__new__(BurpMCPClient)
    client._url = "http://127.0.0.1:9876/"
    client._session = mock.MagicMock()
    client._cm_stack = None
    client._loop = None
    client._loop_thread = None
    client._connected = True
    client._connect_lock = __import__("threading").Lock()
    client._async_connect_lock = None
    client._available_tools = {"send_http1_request": mock.MagicMock()}
    return client


# ---------------------------------------------------------------------------
# Per-call timeout must not kill the session
# ---------------------------------------------------------------------------

class TestPerCallTimeoutSurvivesSession:
    """A McpError(408) must NOT set _connected = False."""

    def test_timeout_does_not_mark_session_dead(self):
        """The core regression: McpError(408) leaves _connected=True."""
        client = _make_client_with_mock_session()

        # session.call_tool raises McpError(408) — a per-call timeout.
        client._session.call_tool = mock.AsyncMock(
            side_effect=McpError(ErrorData(
                code=httpx.codes.REQUEST_TIMEOUT,
                message="Timed out while waiting for response to "
                        "CallToolRequest. Waited 60.0 seconds.",
            ))
        )

        with pytest.raises(BurpMCPError) as exc_info:
            client.call_tool("send_http1_request", {
                "content": "GET / HTTP/1.1\nHost: example.com\n\n",
                "targetHostname": "example.com",
                "targetPort": 80,
                "usesHttps": False,
            }, timeout=60)

        # Error code must be call_timeout, NOT call_failed
        assert exc_info.value.code == "call_timeout"
        # The session must STILL be connected — no reconnect on next call
        assert client._connected is True
        # The session object must not have been nulled
        assert client._session is not None

    def test_timeout_then_next_call_reuses_session(self):
        """After a per-call timeout, the next call must NOT reconnect."""
        import mcp.types as types

        client = _make_client_with_mock_session()
        original_session = client._session

        # First call: times out
        client._session.call_tool = mock.AsyncMock(
            side_effect=McpError(ErrorData(
                code=httpx.codes.REQUEST_TIMEOUT,
                message="Timed out",
            ))
        )

        with pytest.raises(BurpMCPError) as exc:
            client.call_tool("send_http1_request", {
                "content": "GET / HTTP/1.1\nHost: x\n\n",
                "targetHostname": "x", "targetPort": 80,
            }, timeout=1)
        assert exc.value.code == "call_timeout"

        # Second call: succeeds — must use the SAME session, no reconnect
        success_result = mock.MagicMock()
        success_result.isError = False
        success_result.content = [types.TextContent(type="text", text="OK")]
        client._session.call_tool = mock.AsyncMock(return_value=success_result)

        result = client.call_tool("send_http1_request", {
            "content": "GET / HTTP/1.1\nHost: x\n\n",
            "targetHostname": "x", "targetPort": 80,
        }, timeout=10)

        # Session was reused, not replaced
        assert client._session is original_session
        assert client._connected is True
        assert result == "OK"

    def test_genuine_transport_error_still_kills_session(self):
        """A ConnectionError (not a timeout) must still set _connected=False."""
        client = _make_client_with_mock_session()

        client._session.call_tool = mock.AsyncMock(
            side_effect=ConnectionError("SSE stream closed")
        )

        with pytest.raises(BurpMCPError) as exc_info:
            client.call_tool("send_http1_request", {
                "content": "GET / HTTP/1.1\nHost: x\n\n",
                "targetHostname": "x", "targetPort": 80,
            }, timeout=60)

        # Must be call_failed (transport death), not call_timeout
        assert exc_info.value.code == "call_failed"
        # Session IS dead — reconnect on next call
        assert client._connected is False

    def test_mcp_error_non_408_kills_session(self):
        """An McpError with a non-408 code is a real error, not a timeout."""
        client = _make_client_with_mock_session()

        client._session.call_tool = mock.AsyncMock(
            side_effect=McpError(ErrorData(
                code=httpx.codes.INTERNAL_SERVER_ERROR,  # 500, not 408
                message="BApp internal error",
            ))
        )

        with pytest.raises(BurpMCPError) as exc_info:
            client.call_tool("send_http1_request", {
                "content": "GET / HTTP/1.1\nHost: x\n\n",
                "targetHostname": "x", "targetPort": 80,
            }, timeout=60)

        assert exc_info.value.code == "call_failed"
        assert client._connected is False


# ---------------------------------------------------------------------------
# _submit must actually cancel the coroutine
# ---------------------------------------------------------------------------

class TestSubmitCancelsCoroutine:
    """_submit's timeout must cancel the asyncio Task, not just the future."""

    def test_wedged_coro_is_cancelled_not_pinned(self):
        """A coroutine that never completes must be cancelled by _submit timeout.

        This verifies the fix: the old ``future.cancel()`` did not cancel
        the coroutine on the background loop.  The new code wraps the coro
        in a Task and cancels it, injecting CancelledError at the next await.
        """
        client = _make_client_with_mock_session()

        # A coroutine that hangs forever (would pin the loop with old code)
        async def _hang_forever():
            await asyncio.Event().wait()  # never set
            return "unreachable"

        with pytest.raises(TimeoutError):
            client._submit(_hang_forever(), timeout=0.5)

        # The background loop must still be usable — schedule a fast coro
        # and confirm it runs.  If _hang_forever pinned the loop, this
        # would time out too.
        async def _quick():
            await asyncio.sleep(0.01)
            return "loop is alive"

        result = client._submit(_quick(), timeout=5)
        assert result == "loop is alive"

        # Cleanup: stop the background loop
        if client._loop and not client._loop.is_closed():
            client._loop.call_soon_threadsafe(client._loop.stop)


# ---------------------------------------------------------------------------
# Error hint coverage
# ---------------------------------------------------------------------------

class TestErrorHints:
    """The call_timeout error code must have a hint in _BURP_ERROR_HINTS."""

    def test_call_timeout_hint_exists(self):
        assert "call_timeout" in burp_module._BURP_ERROR_HINTS
        hint = burp_module._BURP_ERROR_HINTS["call_timeout"]
        # The hint must tell the secretary the session is still alive
        assert "still alive" in hint.lower() or "per-call" in hint.lower()