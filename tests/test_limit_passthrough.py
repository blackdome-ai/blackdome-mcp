"""The API's daily-limit information reaches the MCP client (hosted HTTP headers and a note in the tool result).

No live calls: the upstream API is an httpx.MockTransport, the hosted app is driven over ASGI.
"""

import asyncio
import json

import httpx
import pytest

import blackdome_mcp.server as server
from blackdome_mcp.http_server import create_http_app
from test_http_server import _LifespanDriver

LIMIT_HEADERS = {
    "RateLimit-Limit": "100",
    "RateLimit-Remaining": "4",
    "RateLimit-Reset": "3720",
    "RateLimit-Policy": "100;w=86400, 60;w=60",
}
DAILY_SENTENCE = "Daily request limit reached: BlackDome Free allows 100 requests a day."


def _mcp_headers(key, session_id=None):
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


def _sse_result(text):
    """The JSON-RPC message out of an SSE (or plain JSON) answer."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


async def _hosted_tool_call(monkeypatch, handler, *, init_key="bd_customer_key", call_key="bd_customer_key",
                            extra_headers=None):
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)   # one session manager per lifespan
    captured = []

    def recording(request):
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(recording)
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    app = create_http_app()
    async with _LifespanDriver(app):
        async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post("/mcp", headers=_mcp_headers(init_key), json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1.0"}},
            })
            session_id = init.headers["mcp-session-id"]
            await client.post("/mcp", headers=_mcp_headers(init_key, session_id),
                              json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            answer = await client.post("/mcp", headers={**_mcp_headers(call_key, session_id), **(extra_headers or {})}, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "top_attackers", "arguments": {"days": 1}},
            })
    return answer, captured


@pytest.mark.asyncio
async def test_hosted_answer_carries_the_daily_limit_headers_and_a_near_note(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"items": [], "count": 0}, headers=LIMIT_HEADERS)

    answer, captured = await _hosted_tool_call(monkeypatch, handler)
    assert captured, "expected an upstream API call"
    assert answer.status_code == 200
    for name, value in LIMIT_HEADERS.items():
        assert answer.headers.get(name) == value, name
    result = _sse_result(answer.text)["result"]
    note = result["content"][-1]
    assert note["text"] == (
        "Daily request limit nearly reached: 4 of 100 requests left today. "
        "The count starts again at 00:00 UTC (in 1 h 2 min)."
    )
    assert note["_meta"][server.LIMIT_META_KEY] == {
        "state": "near", "limit": 100, "remaining": 4, "reset_seconds": 3720,
    }


@pytest.mark.asyncio
async def test_hosted_answer_far_from_the_limit_has_headers_and_no_note(monkeypatch):
    plenty = {**LIMIT_HEADERS, "RateLimit-Remaining": "80"}

    def handler(request):
        return httpx.Response(200, json={"items": [], "count": 0}, headers=plenty)

    answer, _ = await _hosted_tool_call(monkeypatch, handler)
    assert answer.headers.get("RateLimit-Remaining") == "80"
    content = _sse_result(answer.text)["result"]["content"]
    assert not any(server.LIMIT_META_KEY in (item.get("_meta") or {}) for item in content)


@pytest.mark.asyncio
async def test_hosted_answer_when_the_daily_limit_is_reached(monkeypatch):
    refused = {**LIMIT_HEADERS, "RateLimit-Remaining": "0", "Retry-After": "3720"}

    def handler(request):
        return httpx.Response(429, json={"detail": DAILY_SENTENCE}, headers=refused)

    answer, _ = await _hosted_tool_call(monkeypatch, handler)
    assert answer.headers.get("RateLimit-Remaining") == "0"
    note = _sse_result(answer.text)["result"]["content"][-1]
    assert note["text"] == f"{DAILY_SENTENCE} The count starts again at 00:00 UTC (in 1 h 2 min)."
    assert note["_meta"][server.LIMIT_META_KEY]["state"] == "reached"


@pytest.mark.asyncio
async def test_keyless_answer_has_no_limit_headers(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"items": [], "count": 0})

    answer, _ = await _hosted_tool_call(monkeypatch, handler)
    assert "ratelimit-limit" not in {name.lower() for name in answer.headers}


def test_stdio_tool_result_gets_the_note_without_http():
    """The note does not depend on the HTTP transport: the same tools/call handler builds it in stdio mode."""

    async def run():
        real_client = httpx.AsyncClient

        def handler(request):
            return httpx.Response(200, json={"items": [], "count": 0}, headers={**LIMIT_HEADERS, "RateLimit-Remaining": "1"})

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client(*args, **kwargs)

        server.httpx.AsyncClient = _factory
        try:
            return await server._call_tool_with_limit_note("top_attackers", {"days": 1})
        finally:
            server.httpx.AsyncClient = real_client

    result = asyncio.run(run())
    content = result[0] if isinstance(result, tuple) else result
    assert content[-1].text.startswith("Daily request limit nearly reached: 1 of 100 requests left today.")


@pytest.mark.asyncio
async def test_hosted_keyed_error_preserves_upstream_daily_headers(monkeypatch):
    upstream = {**LIMIT_HEADERS, "RateLimit-Remaining": "67"}

    def handler(request):
        assert request.headers["Authorization"] == "Bearer bd_customer_key"
        return httpx.Response(403, json={"detail": "This request is forbidden."}, headers=upstream)

    answer, _ = await _hosted_tool_call(monkeypatch, handler)
    assert {name: answer.headers[name] for name in upstream} == upstream


@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [True, False])
async def test_hosted_limits_follow_the_current_call_key_and_ignore_inbound_limits(monkeypatch, accepted):
    inbound = {name: "123" for name in LIMIT_HEADERS}

    def handler(request):
        assert request.headers["Authorization"] == "Bearer bd_current_customer_key"
        assert all(name not in request.headers for name in inbound)
        if accepted:
            return httpx.Response(200, json={"items": []}, headers=LIMIT_HEADERS)
        return httpx.Response(401, json={"detail": "Invalid API key"}, headers={"WWW-Authenticate": "Bearer"})

    answer, captured = await _hosted_tool_call(
        monkeypatch, handler, call_key="bd_current_customer_key", extra_headers=inbound,
    )
    assert captured
    if accepted:
        assert {name: answer.headers.get(name) for name in LIMIT_HEADERS} == LIMIT_HEADERS
    else:
        assert all(name not in answer.headers for name in LIMIT_HEADERS)
