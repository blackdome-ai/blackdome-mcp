"""A wrong key is refused, never quietly served the free data (full test 2026-11-21, 04-mcp finding 9, item D5).

The free tools' public routes answer a bad key as if no key was sent, so the MCP server checks a sent key on
/api/v1/blackdome/me first. No live calls: the API is an httpx.MockTransport.
"""

import asyncio

import httpx
import pytest

import blackdome_mcp.server as server
from blackdome_mcp import plans

FREE_CALLS = [
    ("lookup_attacker_ip", {"ip": "192.0.2.7"}),
    ("top_attackers", {}),
    ("attack_map", {}),
    ("attack_heatmap", {}),
    ("credential_preview", {}),
    ("recent_iocs", {}),
    ("ioc_trends", {}),
]


@pytest.fixture(autouse=True)
def _fresh_key_checks():
    server._KEY_CHECKS.clear()
    yield
    server._KEY_CHECKS.clear()


def _call(name, arguments, handler):
    async def run():
        real_client = httpx.AsyncClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client(*args, **kwargs)

        server.httpx.AsyncClient = _factory
        try:
            return await server._call_tool_with_limit_note(name, arguments)
        finally:
            server.httpx.AsyncClient = real_client

    return asyncio.run(run())


def _api(me_status):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/api/v1/blackdome/me":
            return httpx.Response(me_status, json={"detail": "Invalid API key"})
        return httpx.Response(200, json={"attackers": [], "events": [], "found": True})

    return seen, handler


@pytest.mark.parametrize("name,arguments", FREE_CALLS)
def test_a_wrong_key_is_refused_and_the_public_route_is_never_called(monkeypatch, name, arguments):
    monkeypatch.setattr(server, "API_KEY", "bd_wrong")
    seen, handler = _api(401)
    result = _call(name, arguments, handler)
    assert result.isError is True
    text = result.content[0].text
    assert text == "Authentication failed (401): " + plans.refusal(name, "bad_key", hosted=False)
    assert "not accepted" in text
    assert seen == ["/api/v1/blackdome/me"]


@pytest.mark.parametrize("me_status", [200, 403, 429, 503])
def test_a_key_that_is_not_refused_goes_ahead(monkeypatch, me_status):
    monkeypatch.setattr(server, "API_KEY", "bd_good")
    seen, handler = _api(me_status)
    result = _call("top_attackers", {}, handler)
    assert not getattr(result, "isError", False)
    assert seen == ["/api/v1/blackdome/me", "/api/blackdome/top-attackers"]


def test_no_key_is_not_checked(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    seen, handler = _api(401)
    _call("top_attackers", {}, handler)
    assert seen == ["/api/blackdome/top-attackers"]


def test_the_check_is_remembered_so_a_key_is_not_charged_twice(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "bd_good")
    seen, handler = _api(200)
    _call("top_attackers", {}, handler)
    _call("attack_heatmap", {}, handler)
    assert seen.count("/api/v1/blackdome/me") == 1
    # The key itself is never kept, only its digest.
    assert "bd_good" not in repr(server._KEY_CHECKS)


def test_a_paid_route_is_not_checked_twice(monkeypatch):
    """/api/v1 routes refuse a bad key themselves; only the public routes need the check."""
    monkeypatch.setattr(server, "API_KEY", "bd_good")
    seen, handler = _api(200)
    _call("whoami", {}, handler)
    assert seen == ["/api/v1/blackdome/me"]
