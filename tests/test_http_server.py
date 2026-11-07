"""Tests for the streamable-HTTP hosted transport (no live calls)."""

import asyncio

import httpx
import pytest

import blackdome_mcp.server as server
from blackdome_mcp.http_server import ApiKeyCapture, _extract_key, create_http_app


def _scope(headers):
    return {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }


class _LifespanDriver:
    """Drive ASGI lifespan startup/shutdown around an app (no extra deps)."""

    def __init__(self, app):
        self.app = app
        self.inbox = [{"type": "lifespan.startup"}]
        self.responses = []
        self._task = None

    async def __aenter__(self):
        async def receive():
            while not self.inbox:
                await asyncio.sleep(0.01)
            return self.inbox.pop(0)

        async def send(message):
            self.responses.append(message)

        self._task = asyncio.create_task(self.app({"type": "lifespan"}, receive, send))
        while not any(r["type"] == "lifespan.startup.complete" for r in self.responses):
            if any(r["type"] == "lifespan.startup.failed" for r in self.responses):
                raise RuntimeError("lifespan startup failed")
            await asyncio.sleep(0.01)
        return self

    async def __aexit__(self, *exc):
        self.inbox.append({"type": "lifespan.shutdown"})
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except Exception:
            self._task.cancel()


# ---------------------------------------------------------------------------
# Key extraction
# ---------------------------------------------------------------------------


def test_extract_key_bearer():
    assert _extract_key(_scope({"Authorization": "Bearer bd_abc123"})) == "bd_abc123"


def test_extract_key_bearer_case_insensitive():
    assert _extract_key(_scope({"authorization": "bearer bd_abc123"})) == "bd_abc123"


def test_extract_key_x_api_key():
    assert _extract_key(_scope({"X-API-Key": "bd_abc123"})) == "bd_abc123"


def test_extract_key_bearer_wins_over_x_api_key():
    scope = _scope({"Authorization": "Bearer bd_first", "X-API-Key": "bd_second"})
    assert _extract_key(scope) == "bd_first"


def test_extract_key_missing():
    assert _extract_key(_scope({})) == ""


def test_extract_key_raw_authorization_passthrough():
    assert _extract_key(_scope({"Authorization": "bd_raw"})) == "bd_raw"


# ---------------------------------------------------------------------------
# Key precedence: per-request contextvar over env var
# ---------------------------------------------------------------------------


def test_current_api_key_prefers_request_key(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "bd_env_key")
    token = server.set_request_api_key("bd_request_key")
    try:
        assert server.current_api_key() == "bd_request_key"
    finally:
        server._REQUEST_API_KEY.reset(token)


def test_current_api_key_falls_back_to_env(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "bd_env_key")
    assert server.current_api_key() == "bd_env_key"


def test_headers_use_request_key(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    token = server.set_request_api_key("bd_request_key")
    try:
        headers = server._headers()
        assert headers["Authorization"] == "Bearer bd_request_key"
    finally:
        server._REQUEST_API_KEY.reset(token)


def test_headers_keyless_when_no_key(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    assert "Authorization" not in server._headers()


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_sets_and_resets_key(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    seen = {}

    async def downstream(scope, receive, send):
        seen["key"] = server.current_api_key()

    app = ApiKeyCapture(downstream)
    await app(_scope({"Authorization": "Bearer bd_mw"}), None, None)
    assert seen["key"] == "bd_mw"
    # Reset after the request: no leak into the next one.
    assert server.current_api_key() == ""


@pytest.mark.asyncio
async def test_middleware_non_http_passthrough():
    calls = []

    async def downstream(scope, receive, send):
        calls.append(scope["type"])

    app = ApiKeyCapture(downstream)
    await app({"type": "websocket", "headers": []}, None, None)
    assert calls == ["websocket"]


# ---------------------------------------------------------------------------
# End-to-end app boot (ASGI transport, no network)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streamable_http_hosted_flow(monkeypatch):
    """Hosted flow in one lifespan (the session manager boots once per process):
    keyless initialize works, and a keyed tool call forwards the per-request
    key to the upstream API."""
    monkeypatch.setattr(server, "API_KEY", "")
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"items": [], "count": 0})

    transport = httpx.MockTransport(handler)
    real_client = server.httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    server.httpx.AsyncClient = _factory
    try:
        app = create_http_app()
        async with _LifespanDriver(app):
            asgi_transport = httpx.ASGITransport(app=app)
            # Use the PRE-PATCH client class: the patch above rewrites any
            # httpx.AsyncClient construction to the mock upstream transport.
            async with real_client(
                transport=asgi_transport, base_url="http://test"
            ) as client:
                # 1. Keyless initialize — free tier must connect with no key.
                keyless_init = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1.0"},
                        },
                    },
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                )
                assert keyless_init.status_code == 200
                assert "BlackDome" in keyless_init.text or "serverInfo" in keyless_init.text

                # 2. Keyed initialize — customer key rides the Authorization header.
                init = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1.0"},
                        },
                    },
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer bd_customer_key",
                    },
                )
                assert init.status_code == 200
                session_id = init.headers.get("mcp-session-id")
                assert session_id
                await client.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "Mcp-Session-Id": session_id,
                        "Authorization": "Bearer bd_customer_key",
                    },
                )
                tool_call = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "top_attackers",
                            "arguments": {"days": 1},
                        },
                    },
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "Mcp-Session-Id": session_id,
                        "Authorization": "Bearer bd_customer_key",
                    },
                )
                assert tool_call.status_code == 200
        assert captured, "expected an upstream API call"
        upstream_auth = captured[-1].headers.get("Authorization", "")
        assert upstream_auth == "Bearer bd_customer_key"
    finally:
        server.httpx.AsyncClient = real_client
