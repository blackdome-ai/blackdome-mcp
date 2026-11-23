"""The hosted server calls the API on loopback, and the tools can call nothing but the paths api.blackdome.ai exposes.

Full test 2026-11-21 (04-mcp finding 4, item D6): all keyless hosted users shared one daily allowance because the
hosted server called the API through its public host. On loopback nginx's allowlist no longer stands in front of
the API, so a caller value placed in a path must never reach another route. No live calls: httpx.MockTransport.
"""

import asyncio
import re
from pathlib import Path

import httpx
import pytest

import blackdome_mcp.http_server as http_server
import blackdome_mcp.server as server

SOURCE = Path(server.__file__).read_text()
# The two locations nginx exposes on api.blackdome.ai (/etc/nginx/sites-enabled/api.blackdome.ai).
NGINX_EXPOSED = re.compile(
    r"^(?:/api/v1/blackdome/|/api/blackdome/(?:lookup|top-attackers|map|credentials/preview|audit|iocs)(?:/|$))"
)


@pytest.fixture(autouse=True)
def _fresh_key_checks(monkeypatch):
    monkeypatch.setattr(server, "_KEY_CHECKS", server.OrderedDict())


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


def _recording():
    seen = []

    def handler(request):
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json={"items": [], "found": True})

    return seen, handler


def test_every_path_in_the_tools_is_one_nginx_exposes_on_the_public_host():
    paths = [p for p in re.findall(r"[\"'](/api/[^\"'{]*)", SOURCE) if p != server._PUBLIC_ROUTE_PREFIX]
    assert len(paths) > 25
    for path in paths:
        assert NGINX_EXPOSED.match(path), path


def test_the_allowlist_in_the_code_is_nginxs():
    for path in ["/api/blackdome/lookup/1.2.3.4", "/api/blackdome/map/events", "/api/v1/blackdome/me",
                 "/api/blackdome/iocs/public/trends"]:
        assert server._api_path(path) == path
    for path in ["/api/blackdome/internal", "/ops/api/ku/state", "/api/v1/other", "/api/blackdome/lookupx",
                 "/api/v1/blackdome/../../ops", "/api/v1/blackdome/a%2Fb", "/api/v1/blackdome/x?y=1"]:
        with pytest.raises(ValueError):
            server._api_path(path)


HOSTILE = ["", ".", "..", "%2e%2e", "a/b", "../me", "a?b=1", "a#b", "a%2Fb", "-x", " x", "x\n", "é", "a" * 300]
PATH_TOOLS = [
    ("verify_sigil", "sigil_id", {}),
    ("list_payloads", "sha256", {}),
    ("get_actor", "actor_id", {}),
    ("get_session_transcript", "session_id", {}),
    ("get_detonation_report", "detonation_id", {}),
    ("get_artifact", "sha256", {}),
    ("lookup_attacker_ip", "ip", {}),
]


@pytest.mark.parametrize("name,param,extra", PATH_TOOLS)
@pytest.mark.parametrize("value", HOSTILE)
def test_a_value_that_is_not_a_plain_id_is_refused_before_any_request(monkeypatch, name, param, extra, value):
    monkeypatch.setattr(server, "API_KEY", "bd_fixture")
    seen, handler = _recording()
    result = _call(name, {param: value, **extra}, handler)
    if name in ("list_payloads", "get_actor") and value == "":
        # An empty id means "the list" for these two tools, a fixed path.
        assert seen and seen[-1].split("?")[0] in ("/api/v1/blackdome/payloads", "/api/v1/blackdome/actors")
        return
    assert result.isError is True, (name, value)
    assert result.content[0].text == "Invalid request parameters."
    assert seen == [], (name, value, seen)


def test_export_format_is_one_of_three():
    seen, handler = _recording()
    result = _call("export_iocs", {"fmt": "../../me"}, handler)
    assert result.isError is True and seen == []


@pytest.mark.parametrize("name,arguments,path", [
    ("get_detonation_report", {"detonation_id": "job:0f96a06e"}, "/api/v1/blackdome/intel/detonations/job%3A0f96a06e"),
    ("get_session_transcript", {"session_id": "acc23b6930b2405b_391b7394"},
     "/api/v1/blackdome/intel/sessions/acc23b6930b2405b_391b7394/transcript"),
    ("verify_sigil", {"sigil_id": "SIGIL-EEEB0646"}, "/api/blackdome/audit/SIGIL-EEEB0646"),
    ("lookup_attacker_ip", {"ip": "2001:db8::1"}, "/api/blackdome/lookup/2001%3Adb8%3A%3A1"),
    ("lookup_attacker_ip", {"ip": "::1"}, "/api/blackdome/lookup/%3A%3A1"),
])
def test_real_ids_still_reach_their_route(monkeypatch, name, arguments, path):
    monkeypatch.setattr(server, "API_KEY", "")
    seen, handler = _recording()
    result = _call(name, arguments, handler)
    assert not getattr(result, "isError", False), result
    assert seen[-1].split("?")[0] == path


def test_the_hosted_entry_point_calls_the_api_on_loopback(monkeypatch):
    monkeypatch.setattr(server, "BASE_URL", "https://api.blackdome.ai")
    monkeypatch.delenv("BLACKDOME_BASE_URL", raising=False)
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    http_server.create_http_app()
    assert server.BASE_URL == "http://127.0.0.1:7860"
    assert server._base_url_is_loopback()


def test_the_environment_still_overrides_the_hosted_upstream(monkeypatch):
    monkeypatch.setattr(server, "BASE_URL", "https://api.blackdome.ai")
    monkeypatch.setenv("BLACKDOME_BASE_URL", "https://api.example.test/")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    http_server.create_http_app()
    assert server.BASE_URL == "https://api.example.test"


def test_the_stdio_package_keeps_the_public_host():
    assert re.search(r'"BLACKDOME_BASE_URL", "https://api.blackdome.ai"', SOURCE)


def test_the_machines_pm2_entry_point_names_the_loopback_api():
    ecosystem = Path(__file__).resolve().parents[3] / "ecosystem.mcp.config.js"
    if not ecosystem.is_file():
        pytest.skip("the PM2 file lives in the monorepo only")
    block = ecosystem.read_text().split('name: "blackdome-mcp-http"', 1)[1]
    assert 'BLACKDOME_BASE_URL: "http://127.0.0.1:7860"' in block.split("autorestart", 1)[0]


def test_a_keyless_caller_at_the_daily_limit_is_not_told_about_a_key(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    text = server._limit_note_text({"limit": 100, "remaining": 0, "reset_seconds": 60})
    assert "use without an account allows 100 requests a day" in text
    assert "this key" not in text
