"""A refusal, an upstream error or a timeout is a failed tool call (isError true), never a successful one.

Full test 2026-11-21 (04-mcp.md, finding 5): every 401, 403, 404, 400 and timeout came back with isError false, so
an assistant could not tell a failure from data. No live calls: the API is an httpx.MockTransport.
"""

import asyncio

import httpx
import pytest

import blackdome_mcp.server as server


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


def _is_error(result):
    return bool(getattr(result, "isError", False))


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 502])
@pytest.mark.parametrize("name,arguments", [
    ("list_payloads", {}),
    ("explain_ioc", {"indicator_type": "domain", "indicator_value": "example.test"}),
    ("list_catalogue_families", {}),
])
def test_an_upstream_refusal_or_error_is_a_failed_call(monkeypatch, status, name, arguments):
    monkeypatch.setattr(server, "API_KEY", "bd_fixture")
    if status == 404 and name == "explain_ioc":
        pytest.skip("a miss is an answer (no evidence record), not a failure")
    result = _call(name, arguments, lambda request: httpx.Response(status, json={"detail": "fixture refusal"}))
    assert _is_error(result), (name, status)


def test_a_timeout_is_a_failed_call(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")

    def handler(request):
        raise httpx.ReadTimeout("timed out", request=request)

    assert _is_error(_call("top_attackers", {}, handler))


def test_invalid_parameters_are_a_failed_call(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "bd_fixture")
    result = _call("compare_samples", {"left_sha256": "nope", "right_sha256": "a" * 64},
                   lambda request: httpx.Response(200, json={}))
    assert _is_error(result)
    assert result.content[0].text == "Invalid request parameters."


def test_an_answer_is_not_a_failed_call(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    result = _call("top_attackers", {}, lambda request: httpx.Response(200, json={"attackers": []}))
    assert not _is_error(result)


def test_a_not_found_lookup_is_an_answer(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    result = _call("lookup_attacker_ip", {"ip": "192.0.2.7"}, lambda request: httpx.Response(404, json={}))
    assert not _is_error(result)


def test_a_timeout_says_what_happened(monkeypatch):
    """Full test 2026-11-21 (D3): attack_map and list_notable_sessions failed with the blank "Request failed: "."""
    monkeypatch.setattr(server, "API_KEY", "")

    def handler(request):
        raise httpx.ReadTimeout("", request=request)

    for name, arguments in (("attack_map", {}), ("explain_ioc", {"indicator_type": "ip", "indicator_value": "192.0.2.7"})):
        result = _call(name, arguments, handler)
        assert result.content[0].text == (
            f"The BlackDome API did not answer within {server.TIMEOUT} seconds. Try again."), name


def test_the_default_wait_is_under_the_public_proxy_timeout(monkeypatch):
    monkeypatch.delenv("BLACKDOME_TIMEOUT", raising=False)
    import importlib.util

    spec = importlib.util.spec_from_file_location("server_default_timeout", server.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert 30 <= module.TIMEOUT < 60
