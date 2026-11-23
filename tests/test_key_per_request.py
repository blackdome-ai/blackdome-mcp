"""Hosted MCP: every tool call uses the key of the request that carried it (sweep 2026-11-21).

Proved fault: initialize with key A, call with key B, the upstream API saw A. Driven end to end over ASGI
against the real hosted app, with a mock upstream.
"""

import json

import httpx
import pytest

import blackdome_mcp.http_server as http_server
import blackdome_mcp.server as server
from blackdome_mcp.http_server import create_http_app
from test_http_server import _LifespanDriver

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "top_attackers", "arguments": {"days": 1}}}


def _headers(key=None, session_id=None):
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


async def _session(monkeypatch, steps, *, init_key):
    """Initialize with ``init_key``, then send ``steps`` (a list of keys, None for no key) as tool calls."""
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    monkeypatch.setattr(server, "_KEY_CHECKS", server.OrderedDict())
    upstream = []

    def handler(request):
        # A sent key is first checked on /me (test_wrong_key.py); only the tool's own call is recorded here.
        if request.url.path == "/api/v1/blackdome/me":
            return httpx.Response(200, json={})
        upstream.append(request.headers.get("Authorization"))
        return httpx.Response(200, json={"items": [], "count": 0})

    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    app = create_http_app()
    answers = []
    async with _LifespanDriver(app):
        async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post("/mcp", headers=_headers(init_key), json=INIT)
            session_id = init.headers["mcp-session-id"]
            await client.post("/mcp", headers=_headers(init_key, session_id),
                              json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            for key in steps:
                answers.append(await client.post("/mcp", headers=_headers(key, session_id), json=CALL))
    return answers, upstream


@pytest.mark.asyncio
async def test_a_call_with_key_b_on_a_session_begun_with_key_a_is_made_with_b(monkeypatch):
    answers, upstream = await _session(monkeypatch, ["bd_key_B", "bd_key_A"], init_key="bd_key_A")
    assert [a.status_code for a in answers] == [200, 200]
    assert upstream == ["Bearer bd_key_B", "Bearer bd_key_A"]


@pytest.mark.asyncio
async def test_a_keyless_call_on_a_keyed_session_is_refused_not_served_on_the_remembered_key(monkeypatch):
    answers, upstream = await _session(monkeypatch, [None], init_key="bd_key_A")
    assert answers[0].status_code == 401
    body = json.loads(answers[0].text)
    assert body["error"]["message"].startswith("Unauthenticated")
    assert body["id"] == CALL["id"]                        # the refused request's own id, not null (D5)
    assert "bd_key_A" not in answers[0].text
    assert upstream == []                                  # nothing went upstream


def test_the_refusal_names_each_request_of_a_batch_and_null_for_what_has_no_id():
    batch = json.dumps([{"jsonrpc": "2.0", "id": "a", "method": "ping"},
                        {"jsonrpc": "2.0", "method": "notifications/initialized"}]).encode()
    assert [item["id"] for item in json.loads(http_server.unauthenticated_body(batch))] == ["a", None]
    assert json.loads(http_server.unauthenticated_body(b"not json"))["id"] is None
    assert json.loads(http_server.unauthenticated_body(b'{"id": true}'))["id"] is None


@pytest.mark.asyncio
async def test_a_keyless_session_stays_free_and_may_add_a_key(monkeypatch):
    answers, upstream = await _session(monkeypatch, [None, "bd_key_B"], init_key=None)
    assert [a.status_code for a in answers] == [200, 200]
    assert upstream == [None, "Bearer bd_key_B"]


def test_only_session_ids_are_remembered_never_keys():
    assert all(value is True for value in http_server._KEYED_SESSIONS.values())
    assert not any("bd_" in session_id for session_id in http_server._KEYED_SESSIONS)


@pytest.mark.asyncio
async def test_the_mcp_clients_address_from_nginx_goes_to_a_loopback_api(monkeypatch):
    """Keyless MCP users are counted as themselves: X-Real-IP from nginx is passed on to an API on loopback."""
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    seen = []

    def handler(request):
        seen.append(request.headers.get("X-Real-IP"))
        return httpx.Response(200, json={"items": [], "count": 0})

    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    for base, expected in (("http://127.0.0.1:7860", "203.0.113.7"), ("https://api.blackdome.ai", None)):
        monkeypatch.setenv("BLACKDOME_BASE_URL", base)       # the hosted entry point reads it (D6)
        monkeypatch.setattr(server, "BASE_URL", base)
        monkeypatch.setattr(server.mcp, "_session_manager", None)
        app = create_http_app()
        async with _LifespanDriver(app):
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
            async with real_client(transport=transport, base_url="http://test") as client:
                nginx = {**_headers(), "X-Real-IP": "203.0.113.7"}
                init = await client.post("/mcp", headers=nginx, json=INIT)
                session_id = init.headers["mcp-session-id"]
                await client.post("/mcp", headers={**nginx, "Mcp-Session-Id": session_id},
                                  json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                await client.post("/mcp", headers={**nginx, "Mcp-Session-Id": session_id}, json=CALL)
        assert seen[-1] == expected, base


def test_an_x_real_ip_from_a_peer_that_is_not_nginx_is_not_passed_on():
    from types import SimpleNamespace

    from mcp.server.lowlevel.server import request_ctx

    def address_for(peer):
        scope = {"type": "http", "client": (peer, 1), "headers": [(b"x-real-ip", b"203.0.113.7")]}
        token = request_ctx.set(SimpleNamespace(request=SimpleNamespace(scope=scope)))
        try:
            return server._client_address_from_nginx()
        finally:
            request_ctx.reset(token)

    assert address_for("127.0.0.1") == "203.0.113.7"
    assert address_for("198.51.100.9") is None
