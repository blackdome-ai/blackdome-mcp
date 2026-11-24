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


@pytest.fixture(autouse=True)
def _fresh_allowance_cache(monkeypatch):
    """The hosted server keeps each key's last allowance headers for a few seconds; no test sees another's."""
    monkeypatch.setattr(server, "_ALLOWANCE_CACHE", server.OrderedDict())


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
        if request.url.path == server.ALLOWANCES_PATH:
            return httpx.Response(200, json={})       # the initialize answers' own allowance read
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


# Walkthrough 2026-11-23, item 13: every hosted answer to a keyed request carries the REST API's full header set,
# per-minute and daily, including the answers that make no API call of their own.
FULL_SET = {
    **LIMIT_HEADERS,
    "X-RateLimit-Minute-Limit": "60",
    "X-RateLimit-Minute-Remaining": "41",
    "X-RateLimit-Minute-Reset": "17",
}


@pytest.mark.asyncio
async def test_every_hosted_keyed_answer_carries_the_full_set(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server, "_ALLOWANCE_CACHE", server.OrderedDict())
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    allowance_reads = []

    def handler(request):
        if request.url.path == server.ALLOWANCES_PATH:
            allowance_reads.append(request)
            if request.headers.get("authorization") != "Bearer bd_customer_key":
                return httpx.Response(401, json={"detail": "Invalid API key"})
            return httpx.Response(200, json={}, headers=FULL_SET)
        return httpx.Response(200, json={"items": [], "count": 0},
                              headers={**FULL_SET, "X-RateLimit-Minute-Remaining": "40"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    app = create_http_app()
    async with _LifespanDriver(app):
        async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post("/mcp", headers=_mcp_headers("bd_customer_key"), json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1.0"}},
            })
            session_id = init.headers["mcp-session-id"]
            initialized = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id),
                                            json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            listed = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id),
                                       json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            called = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id), json={
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "top_attackers", "arguments": {"days": 1}},
            })
            wrong = await client.post("/mcp", headers=_mcp_headers("bd_wrong_key_value"), json={
                "jsonrpc": "2.0", "id": 4, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1.0"}},
            })

    for answer in (init, initialized, listed):
        for name, value in FULL_SET.items():
            assert answer.headers.get(name) == value, (answer.request.content[:60], name)
    # The tool call reports the window its own API call was answered with, not a separate read.
    assert called.headers.get("X-RateLimit-Minute-Remaining") == "40"
    assert all(name in called.headers for name in FULL_SET)
    # One read for the session's first answer; the notification and the tool list reuse it (review 2026-11-23).
    # The wrong key is a key of its own: its read is refused and nothing is kept for it.
    assert len(allowance_reads) == 2
    assert not any("ratelimit" in name.lower() for name in wrong.headers)


@pytest.mark.asyncio
async def test_hosted_answers_reuse_the_last_values_for_a_few_seconds(monkeypatch):
    """Review 2026-11-23: each answer that made no tool call read /limits, a key check on the API each time, and
    a key past that read's own ceiling of 120 a minute got answers with no headers."""
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    monkeypatch.setattr(server, "_ALLOWANCE_CACHE", server.OrderedDict())
    clock = [1000.0]
    monkeypatch.setattr(server, "_allowance_clock", lambda: clock[0])
    allowance_reads = []

    def handler(request):
        if request.url.path == server.ALLOWANCES_PATH:
            allowance_reads.append(request)
            return httpx.Response(200, json={}, headers=FULL_SET)
        return httpx.Response(200, json={"items": [], "count": 0},
                              headers={**FULL_SET, "X-RateLimit-Minute-Remaining": "40"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    app = create_http_app()
    async with _LifespanDriver(app):
        async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post("/mcp", headers=_mcp_headers("bd_customer_key"), json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1.0"}},
            })
            session_id = init.headers["mcp-session-id"]
            await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id), json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "top_attackers", "arguments": {"days": 1}},
            })
            clock[0] += 2
            # The tool call's own values, two seconds older: no read, the reset counts aged by two seconds.
            listed = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id),
                                       json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            assert len(allowance_reads) == 1
            assert listed.headers.get("X-RateLimit-Minute-Remaining") == "40"
            assert listed.headers.get("X-RateLimit-Minute-Reset") == "15"
            assert listed.headers.get("RateLimit-Reset") == "3718"
            clock[0] += server.ALLOWANCE_CACHE_SECONDS
            # Older than the reuse window: read again.
            relisted = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id),
                                         json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
            assert len(allowance_reads) == 2
            assert relisted.headers.get("X-RateLimit-Minute-Remaining") == "41"


def test_kept_values_are_dropped_when_a_window_rolls_over(monkeypatch):
    monkeypatch.setattr(server, "_ALLOWANCE_CACHE", server.OrderedDict())
    clock = [50.0]
    monkeypatch.setattr(server, "_allowance_clock", lambda: clock[0])
    server.remember_allowances("bd_customer_key", {**FULL_SET, "X-RateLimit-Minute-Reset": "2"})
    assert server._cached_allowances("bd_customer_key")["X-RateLimit-Minute-Reset"] == "2"
    assert server._cached_allowances("bd_other_key_value") is None
    clock[0] += 2
    # The minute window has rolled over, so its remaining count is no longer true.
    assert server._cached_allowances("bd_customer_key") is None
    # The key itself is never kept.
    assert all("bd_customer_key" not in ident for ident in server._ALLOWANCE_CACHE)


# Second review 2026-11-23, finding 2: (a) when the allowance read itself is refused with a 429, that answer carries the
# key's full set (the API attaches it to every answer to a valid key) and the hosted answer passed none on; (b) a plan
# with a per-minute limit and no daily limit (OEM) gets the minute set from the API and the hosted answers got none.
def _plan_set(daily, per_minute, *, minute_remaining="41"):
    values = {
        "X-RateLimit-Minute-Limit": str(per_minute),
        "X-RateLimit-Minute-Remaining": minute_remaining,
        "X-RateLimit-Minute-Reset": "17",
    }
    if daily is None:
        values["RateLimit-Policy"] = f"{per_minute};w=60"
    else:
        values.update({"RateLimit-Limit": str(daily), "RateLimit-Remaining": str(daily - 7),
                       "RateLimit-Reset": "3720", "RateLimit-Policy": f"{daily};w=86400, {per_minute};w=60"})
    return values


PLAN_SETS = {
    "analyst": (5000, 60),
    "analyst-trialing": (5000, 60),
    "pro": (50000, 300),
    "pro-trialing": (50000, 300),
    "oem": (None, 5000),
}


async def _hosted_session(monkeypatch, handler):
    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    app = create_http_app()
    async with _LifespanDriver(app):
        async with real_client(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post("/mcp", headers=_mcp_headers("bd_customer_key"), json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1.0"}},
            })
            session_id = init.headers["mcp-session-id"]
            called = await client.post("/mcp", headers=_mcp_headers("bd_customer_key", session_id), json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "top_attackers", "arguments": {"days": 1}},
            })
    return init, called


@pytest.mark.asyncio
@pytest.mark.parametrize("plan", sorted(PLAN_SETS))
async def test_a_refused_allowance_read_still_passes_its_headers_on(monkeypatch, plan):
    daily, per_minute = PLAN_SETS[plan]
    refused = {**_plan_set(daily, per_minute), "Retry-After": "17"}

    def handler(request):
        if request.url.path == server.ALLOWANCES_PATH:
            return httpx.Response(429, json={"detail": "Too many reads of your allowances in a minute."},
                                  headers=refused)
        return httpx.Response(200, json={"items": [], "count": 0}, headers=_plan_set(daily, per_minute))

    init, _ = await _hosted_session(monkeypatch, handler)
    for name, value in _plan_set(daily, per_minute).items():
        assert init.headers.get(name) == value, name
    assert "retry-after" not in {name.lower() for name in init.headers}     # the read's refusal is not the answer's


@pytest.mark.asyncio
@pytest.mark.parametrize("plan", sorted(PLAN_SETS))
async def test_every_plan_gets_its_own_set_on_hosted_answers(monkeypatch, plan):
    daily, per_minute = PLAN_SETS[plan]

    def handler(request):
        if request.url.path == server.ALLOWANCES_PATH:
            return httpx.Response(200, json={}, headers=_plan_set(daily, per_minute))
        return httpx.Response(200, json={"items": [], "count": 0},
                              headers=_plan_set(daily, per_minute, minute_remaining="40"))

    init, called = await _hosted_session(monkeypatch, handler)
    for answer, remaining in ((init, "41"), (called, "40")):
        expected = _plan_set(daily, per_minute, minute_remaining=remaining)
        assert {name: answer.headers.get(name) for name in expected} == expected
        if daily is None:
            assert "ratelimit-limit" not in {name.lower() for name in answer.headers}
    # A minute-only set is no daily limit: the tool result gets no daily-limit note.
    content = _sse_result(called.text)["result"]["content"]
    assert not any(server.LIMIT_META_KEY in (item.get("_meta") or {}) for item in content)


def test_a_minute_only_answer_never_makes_a_daily_note():
    response = httpx.Response(429, json={"detail": "Rate limit exceeded"}, headers=_plan_set(None, 5000))
    info = server._limit_from_response(response)
    assert info["headers"] == _plan_set(None, 5000)
    assert info["limit"] is None and info["remaining"] is None
    assert server._limit_note(info) is None
    holder = {}
    server._keep_lowest(holder, info)
    daily = server._limit_from_response(httpx.Response(200, headers=_plan_set(5000, 60)))
    server._keep_lowest(holder, daily)
    assert holder["info"] is daily                      # a daily set replaces a minute-only one
    server._keep_lowest(holder, info)
    assert holder["info"] is daily                      # and is never replaced by one
