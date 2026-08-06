"""Offline tests for blackdome-mcp using httpx MockTransport (no live calls).

Each test patches the module's httpx.AsyncClient so that requests are routed
through a MockTransport handler that captures the outgoing request and returns
a canned response. This lets us assert URL/params construction, password
masking, the export_iocs format branch, error mapping, and keyless headers
without ever touching a real server.
"""

import json
from contextlib import contextmanager

import httpx
import pytest

import blackdome_mcp.server as server


@contextmanager
def mock_api(handler):
    """Patch server.httpx.AsyncClient to use a MockTransport with `handler`.

    `handler(request) -> httpx.Response`. The captured requests are also
    appended to a list yielded to the caller for assertions.
    """
    captured = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(_handler)
    real_client = server.httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    server.httpx.AsyncClient = _factory
    try:
        yield captured
    finally:
        server.httpx.AsyncClient = real_client


def json_response(payload, status=200):
    return httpx.Response(status, json=payload)


# ---------------------------------------------------------------------------
# URL + params construction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_builds_correct_url():
    def handler(request):
        return json_response({"ip": "1.2.3.4", "total_events": 1})

    with mock_api(handler) as captured:
        await server.lookup_attacker_ip("1.2.3.4")

    assert str(captured[0].url) == f"{server.BASE_URL}/api/blackdome/lookup/1.2.3.4"
    assert captured[0].method == "GET"


@pytest.mark.asyncio
async def test_top_attackers_params():
    def handler(request):
        return json_response({"items": [], "count": 0})

    with mock_api(handler) as captured:
        await server.top_attackers(days=14, limit=3)

    url = captured[0].url
    assert url.path == "/api/blackdome/top-attackers"
    assert url.params["days"] == "14"
    assert url.params["limit"] == "3"


@pytest.mark.asyncio
async def test_attack_map_enforces_min_limit_10():
    def handler(request):
        return json_response({"events": []})

    with mock_api(handler) as captured:
        await server.attack_map(limit=3)  # below min -> clamped to 10

    assert captured[0].url.params["limit"] == "10"


@pytest.mark.asyncio
async def test_attack_heatmap_enforces_min_limit_5():
    def handler(request):
        return json_response({"countries": []})

    with mock_api(handler) as captured:
        await server.attack_heatmap(limit=2)  # below min -> clamped to 5

    assert captured[0].url.params["limit"] == "5"


@pytest.mark.asyncio
async def test_recent_iocs_uses_public_path():
    def handler(request):
        return json_response({"total": 0, "iocs": []})

    with mock_api(handler) as captured:
        await server.recent_iocs(ioc_type="sha256", limit=3)

    url = captured[0].url
    # MUST be the redacted public preview, NOT the keyed /iocs feeds
    assert url.path == "/api/blackdome/iocs/public"
    assert url.params["ioc_type"] == "sha256"
    assert url.params["limit"] == "3"


@pytest.mark.asyncio
async def test_ioc_trends_path():
    def handler(request):
        return json_response({"period_days": 7})

    with mock_api(handler) as captured:
        await server.ioc_trends(days=7)

    assert captured[0].url.path == "/api/blackdome/iocs/public/trends"
    assert captured[0].url.params["days"] == "7"


@pytest.mark.asyncio
async def test_search_credentials_keyed_path():
    def handler(request):
        return json_response({"credentials": [], "total": 0})

    with mock_api(handler) as captured:
        await server.search_credentials(username="root", protocol="ssh")

    url = captured[0].url
    assert url.path == "/api/v1/blackdome/credentials/search"
    assert url.params["username"] == "root"
    assert url.params["protocol"] == "ssh"


@pytest.mark.asyncio
async def test_list_payloads_list_vs_detail():
    def handler(request):
        return json_response({"ok": True})

    with mock_api(handler) as captured:
        await server.list_payloads()  # list mode
        await server.list_payloads(sha256="abc123")  # detail mode

    assert captured[0].url.path == "/api/v1/blackdome/payloads"
    assert captured[1].url.path == "/api/v1/blackdome/payloads/abc123"


@pytest.mark.asyncio
async def test_get_actor_list_vs_sessions():
    def handler(request):
        return json_response({"items": [], "count": 0})

    with mock_api(handler) as captured:
        await server.get_actor()  # list mode
        await server.get_actor(actor_id="deadbeef")  # sessions mode

    assert captured[0].url.path == "/api/v1/blackdome/actors"
    assert captured[1].url.path == "/api/v1/blackdome/actors/deadbeef/sessions"


@pytest.mark.asyncio
async def test_whoami_path():
    def handler(request):
        return json_response({"slug": "demo", "plan": "intel_community"})

    with mock_api(handler) as captured:
        await server.whoami()

    assert captured[0].url.path == "/api/v1/blackdome/me"


@pytest.mark.asyncio
async def test_verify_sigil_404_is_not_found_not_error():
    def handler(request):
        return json_response({"detail": "Sigil not found"}, status=404)

    with mock_api(handler):
        out = await server.verify_sigil("SIGIL-NOPE")

    parsed = json.loads(out)
    assert parsed["found"] is False
    assert parsed["sigil_id"] == "SIGIL-NOPE"


# ---------------------------------------------------------------------------
# Password masking (the critical security requirement)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_masks_plaintext_passwords():
    leaky = {
        "ip": "176.65.139.56",
        "total_events": 492,
        "credentials_attempted": [
            {"username": "admin", "password": "admin", "protocol": "ssh", "attempt_count": 163},
            {"username": "root", "password": "p@ssw0rd123", "protocol": "ssh", "attempt_count": 9},
        ],
    }

    def handler(request):
        return json_response(leaky)

    with mock_api(handler):
        out = await server.lookup_attacker_ip("176.65.139.56")

    parsed = json.loads(out)
    passwords = [c["password"] for c in parsed["credentials_attempted"]]
    assert passwords == ["********", "********"]
    # usernames / protocol metadata preserved
    assert parsed["credentials_attempted"][0]["username"] == "admin"
    assert parsed["credentials_attempted"][0]["protocol"] == "ssh"
    # raw plaintext must not appear anywhere in the output
    assert "p@ssw0rd123" not in out
    assert '"password": "admin"' not in out


@pytest.mark.asyncio
async def test_search_credentials_does_not_mask_plaintext():
    # The PAID tool intentionally returns plaintext (password_plain).
    paid = {
        "credentials": [
            {"username": "admin", "password_plain": "admin", "password_hash": "8c69", "protocol": "ssh"},
        ],
        "total": 1,
    }

    def handler(request):
        return json_response(paid)

    with mock_api(handler):
        out = await server.search_credentials(username="admin")

    parsed = json.loads(out)
    assert parsed["credentials"][0]["password_plain"] == "admin"


# ---------------------------------------------------------------------------
# export_iocs format branch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_iocs_csv_returns_raw_text():
    csv_body = "ioc_type,ioc_value,confidence\nsha256,88ede6,90\n"

    def handler(request):
        assert request.url.path == "/api/v1/blackdome/threat-intel/feed/csv"
        # Accept header should request text/csv on the csv branch
        assert request.headers["accept"] == "text/csv"
        return httpx.Response(200, text=csv_body, headers={"content-type": "text/csv"})

    with mock_api(handler):
        out = await server.export_iocs(fmt="csv")

    assert out == csv_body  # raw text body returned verbatim
    assert out.startswith("ioc_type,ioc_value,confidence")


@pytest.mark.asyncio
async def test_export_iocs_stix_returns_bundle_json():
    bundle = {"type": "bundle", "id": "bundle--blackdome-20260610003925", "objects": []}

    def handler(request):
        assert request.url.path == "/api/v1/blackdome/threat-intel/feed/stix"
        assert request.headers["accept"] == "application/json"
        return json_response(bundle)

    with mock_api(handler):
        out = await server.export_iocs(fmt="stix")

    parsed = json.loads(out)
    assert parsed["type"] == "bundle"
    assert "objects" in parsed


@pytest.mark.asyncio
async def test_export_iocs_json_returns_flat_feed():
    feed = {"feed": "blackdome-threat-intel", "count": 0, "iocs": []}

    def handler(request):
        assert request.url.path == "/api/v1/blackdome/threat-intel/feed/json"
        return json_response(feed)

    with mock_api(handler):
        out = await server.export_iocs(fmt="json")

    parsed = json.loads(out)
    assert parsed["feed"] == "blackdome-threat-intel"
    assert "iocs" in parsed


@pytest.mark.asyncio
async def test_export_iocs_rejects_bad_format():
    out = await server.export_iocs(fmt="xml")
    assert "Invalid fmt" in out


@pytest.mark.asyncio
async def test_export_iocs_default_params():
    def handler(request):
        return json_response({"feed": "x", "iocs": []})

    with mock_api(handler) as captured:
        await server.export_iocs(fmt="json")

    params = captured[0].url.params
    assert params["min_confidence"] == "50"  # documented default
    assert params["min_severity"] == "medium"
    assert params["days"] == "30"


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_format_error_401():
    def handler(request):
        return json_response({"detail": "Missing or invalid API key"}, status=401)

    with mock_api(handler):
        out = await server.search_credentials(username="root")

    assert "401" in out
    assert "API key" in out
    assert "pricing" in out


@pytest.mark.asyncio
async def test_format_error_403():
    def handler(request):
        return json_response(
            {"detail": "STIX export requires Pro or Enterprise Threat Intel access."},
            status=403,
        )

    with mock_api(handler):
        out = await server.export_iocs(fmt="stix")

    assert "403" in out
    assert "plan" in out.lower()


@pytest.mark.asyncio
async def test_format_error_429():
    def handler(request):
        return httpx.Response(429, json={"detail": "rate limited"}, headers={"Retry-After": "30"})

    with mock_api(handler):
        out = await server.top_attackers()

    assert "429" in out
    assert "30" in out
    assert "Rate limited" in out


# ---------------------------------------------------------------------------
# Headers — keyless omits Authorization
# ---------------------------------------------------------------------------


def test_headers_omits_authorization_when_keyless(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "")
    headers = server._headers()
    assert "Authorization" not in headers
    assert headers["Accept"] == "application/json"


def test_headers_includes_bearer_when_key_set(monkeypatch):
    monkeypatch.setattr(server, "API_KEY", "bd_testkey")
    headers = server._headers()
    assert headers["Authorization"] == "Bearer bd_testkey"
    assert headers["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# Paid intel tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_notable_sessions_builds_params_and_clamps_limit():
    def handler(request):
        return json_response({"sessions": [], "count": 0})

    with mock_api(handler) as captured:
        await server.list_notable_sessions(
            min_commands=4,
            since="2026-06-01T00:00:00Z",
            service="ssh",
            technique="T1059",
            human_likely=True,
            actor_id="actor-1",
            limit=999,
        )

    url = captured[0].url
    assert url.path == "/api/v1/blackdome/intel/sessions"
    assert url.params["min_commands"] == "4"
    assert url.params["since"] == "2026-06-01T00:00:00Z"
    assert url.params["service"] == "ssh"
    assert url.params["technique"] == "T1059"
    assert url.params["human_likely"] == "true"
    assert url.params["actor_id"] == "actor-1"
    assert url.params["limit"] == "100"


@pytest.mark.asyncio
async def test_get_session_transcript_quotes_path_and_clamps_limit():
    def handler(request):
        return json_response(
            {
                "session": {"session_id": "sess/with space", "persona_stage": "Curious"},
                "steps": [
                    {
                        "seq": 1,
                        "command": "id",
                        "output_preview": "uid=0",
                        "exit_code": 0,
                        "cwd": "/tmp",
                        "techniques": ["T1059"],
                    }
                ],
                "total_steps": 1,
                "truncated": False,
            }
        )

    with mock_api(handler) as captured:
        await server.get_session_transcript("sess/with space", limit=5000, offset=7)

    url = captured[0].url
    assert (
        url.raw_path.decode()
        == "/api/v1/blackdome/intel/sessions/sess%2Fwith%20space/transcript?limit=1000&offset=7"
    )
    assert url.params["limit"] == "1000"
    assert url.params["offset"] == "7"


@pytest.mark.asyncio
async def test_list_detonations_builds_params_and_clamps_limit():
    def handler(request):
        return json_response({"detonations": [], "count": 0})

    with mock_api(handler) as captured:
        await server.list_detonations(
            verdict="malware",
            vm_type="linux",
            sha256="a" * 64,
            since="2026-06-01T00:00:00Z",
            limit=500,
        )

    url = captured[0].url
    assert url.path == "/api/v1/blackdome/intel/detonations"
    assert url.params["verdict"] == "malware"
    assert url.params["vm_type"] == "linux"
    assert url.params["sha256"] == "a" * 64
    assert url.params["since"] == "2026-06-01T00:00:00Z"
    assert url.params["limit"] == "100"


@pytest.mark.asyncio
async def test_get_detonation_report_quotes_path():
    def handler(request):
        return json_response(
            {
                "detonation_id": "det/with space",
                "sha256": "b" * 64,
                "verdict": "malware",
                "report_available": True,
                "report_body": {"behavior": []},
            }
        )

    with mock_api(handler) as captured:
        await server.get_detonation_report("det/with space")

    assert (
        captured[0].url.raw_path.decode()
        == "/api/v1/blackdome/intel/detonations/det%2Fwith%20space"
    )


@pytest.mark.asyncio
async def test_get_artifact_quotes_path_and_does_not_return_transcript_fields():
    def handler(request):
        assert "/transcript" not in request.url.path
        return json_response(
            {
                "artifact": {
                    "sha256": "c/with space",
                    "magika_label": "ELF",
                    "session_id": "sess-1",
                    "actor_id": "actor-1",
                },
                "detonation": {"detonation_id": "det-1", "verdict": "malware"},
                "iocs": [],
                "dropped_by_session": {
                    "session_id": "sess-1",
                    "actor_id": "actor-1",
                    "first_ts": "2026-06-01T00:00:00Z",
                    "last_ts": "2026-06-01T00:01:00Z",
                    "command_count": 4,
                },
            }
        )

    with mock_api(handler) as captured:
        out = await server.get_artifact("c/with space")

    assert captured[0].url.raw_path.decode() == "/api/v1/blackdome/intel/artifacts/c%2Fwith%20space"
    assert '"command":' not in out
    assert '"output_preview":' not in out
