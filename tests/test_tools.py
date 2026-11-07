"""Offline tests for blackdome-mcp using httpx MockTransport (no live calls).

Each test patches the module's httpx.AsyncClient so that requests are routed
through a MockTransport handler that captures the outgoing request and returns
a canned response. This lets us assert URL/params construction, password
masking, the export_iocs format branch, error mapping, and keyless headers
without ever touching a real server.
"""

import ast
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

import blackdome_mcp.server as server

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


# ---------------------------------------------------------------------------
# Immutable release consistency
# ---------------------------------------------------------------------------

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_GATE_SCRIPT = _PACKAGE_ROOT / "scripts/check_release_artifact.py"
_RELEASE_VERSION = "0.4.0"
_CANONICAL_SERVER_NAME = "io.github.blackdome-ai/blackdome-mcp"
_RELEASE_TOOL_NAMES = (
    "lookup_attacker_ip",
    "top_attackers",
    "attack_map",
    "attack_heatmap",
    "credential_preview",
    "verify_sigil",
    "recent_iocs",
    "ioc_trends",
    "export_iocs",
    "search_credentials",
    "credential_stats",
    "list_payloads",
    "get_actor",
    "warboard",
    "list_notable_sessions",
    "get_session_transcript",
    "list_detonations",
    "get_detonation_report",
    "get_artifact",
    "whoami",
    "explain_ioc",
    "compare_samples",
    "get_evidence_cluster",
    "get_reproducible_novelty",
    "get_threatdrop_case",
    "get_takedown_status",
)
_README_TOOL_NAMES = (
    "lookup_attacker_ip",
    "top_attackers",
    "attack_map",
    "attack_heatmap",
    "credential_preview",
    "verify_sigil",
    "recent_iocs",
    "ioc_trends",
    "export_iocs",
    "search_credentials",
    "credential_stats",
    "list_payloads",
    "get_actor",
    "warboard",
    "list_notable_sessions",
    "get_session_transcript",
    "list_detonations",
    "get_detonation_report",
    "get_artifact",
    "explain_ioc",
    "compare_samples",
    "get_evidence_cluster",
    "get_reproducible_novelty",
    "get_threatdrop_case",
    "get_takedown_status",
    "whoami",
)


def _decorated_tool_names() -> tuple[str, ...]:
    """Return MCP tool names from the source decorators without importing a live service."""
    tree = ast.parse((_PACKAGE_ROOT / "src/blackdome_mcp/server.py").read_text())
    names = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "mcp"
            and decorator.func.attr == "tool"
            for decorator in node.decorator_list
        ):
            names.append(node.name)
    return tuple(names)


def _readme_tool_names() -> tuple[str, ...]:
    readme = (_PACKAGE_ROOT / "README.md").read_text()
    tools_section = readme.split("## Available Tools", 1)[1].split("## Example Prompts", 1)[0]
    return tuple(re.findall(r"^\| `([^`]+)` \|", tools_section, flags=re.MULTILINE))


def test_release_metadata_and_public_documentation_share_one_immutable_version():
    """A version bump must update every source-of-truth a registry consumer can see."""
    pyproject = tomllib.loads((_PACKAGE_ROOT / "pyproject.toml").read_text())
    manifest = json.loads((_PACKAGE_ROOT / "server.json").read_text())
    lock = tomllib.loads((_PACKAGE_ROOT / "uv.lock").read_text())
    package_lock = next(package for package in lock["package"] if package["name"] == "blackdome-mcp")

    assert pyproject["project"]["name"] == "blackdome-mcp"
    assert pyproject["project"]["version"] == _RELEASE_VERSION
    assert "mcp[cli]>=1.30.0,<2.0.0" in pyproject["project"]["dependencies"]
    assert "tomli>=2.0.0; python_version < '3.11'" in pyproject["project"]["optional-dependencies"]["test"]
    assert re.search(
        rf'^__version__ = "{re.escape(_RELEASE_VERSION)}"$',
        (_PACKAGE_ROOT / "src/blackdome_mcp/__init__.py").read_text(),
        flags=re.MULTILINE,
    )
    assert manifest["name"] == _CANONICAL_SERVER_NAME
    assert manifest["version"] == _RELEASE_VERSION
    assert manifest["packages"] == [
        {
            **manifest["packages"][0],
            "identifier": "blackdome-mcp",
            "version": _RELEASE_VERSION,
        }
    ]
    assert package_lock["version"] == _RELEASE_VERSION

    readme = (_PACKAGE_ROOT / "README.md").read_text()
    assert f"Canonical MCP server name: `{_CANONICAL_SERVER_NAME}`" in readme
    assert f"Package version: `{_RELEASE_VERSION}`" in readme


def test_mcp_initialize_advertises_the_canonical_package_version():
    """Initialize must identify BlackDome 0.4.0, not the FastMCP framework."""
    initialization = server.mcp._mcp_server.create_initialization_options()

    assert initialization.server_name == "BlackDome"
    assert initialization.server_version == _RELEASE_VERSION


def test_release_tool_contract_has_exactly_26_source_and_documented_tools():
    """The immutable 0.4.0 release must not gain, lose, or rename a tool."""
    assert _decorated_tool_names() == _RELEASE_TOOL_NAMES
    assert _readme_tool_names() == _README_TOOL_NAMES
    assert set(_README_TOOL_NAMES) == set(_RELEASE_TOOL_NAMES)
    assert len(_RELEASE_TOOL_NAMES) == 26


def _run_release_artifact_gate(
    *args: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    process_environment = os.environ.copy()
    if environment:
        process_environment.update(environment)
    return subprocess.run(
        [sys.executable, str(_RELEASE_GATE_SCRIPT), *args],
        cwd=_PACKAGE_ROOT,
        text=True,
        capture_output=True,
        env=process_environment,
        check=False,
    )


@pytest.mark.skipif(
    os.environ.get("BLACKDOME_RUN_RELEASE_ARTIFACT_GATE") != "1",
    reason="set BLACKDOME_RUN_RELEASE_ARTIFACT_GATE=1 to run the built-artifact release gate",
)
def test_release_artifact_gate_builds_and_smoke_tests_the_distributions(tmp_path):
    """A broken wheel, sdist, entry point, or tool registration must block release."""
    completed = _run_release_artifact_gate(environment={"TMPDIR": str(tmp_path)})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "release artifact gate passed" in completed.stdout
    assert not list(tmp_path.glob("blackdome-mcp-release-*"))


@pytest.mark.skipif(
    os.environ.get("BLACKDOME_RUN_MCP_FLOOR_SMOKE") != "1",
    reason="set BLACKDOME_RUN_MCP_FLOOR_SMOKE=1 to smoke the supported MCP floor",
)
def test_lowest_supported_mcp_runs_the_real_hosted_flow():
    """A floor that redirects or breaks the hosted MCP flow is not supported."""
    completed = _run_release_artifact_gate("--mcp-version", "1.30.0")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "mcp=1.30.0" in completed.stdout
    assert "hosted_flow=ok" in completed.stdout


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


# ---------------------------------------------------------------------------
# Customer Intelligence tools (read-only JSON-body operations)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_customer_intelligence_tools_use_read_only_json_posts_and_request_key():
    """Changing a POST route/body/key would misdirect a customer intelligence query."""

    def handler(request):
        return json_response({"ok": True})

    reset = server.set_request_api_key("customer-key")
    try:
        with mock_api(handler) as captured:
            await server.explain_ioc("ip", "1.2.3.4")
            await server.compare_samples("a" * 64, "b" * 64)
            await server.get_evidence_cluster("domain", "example.test", depth=2, max_nodes=4, max_edges=5, max_evidence=6)
            await server.get_reproducible_novelty("url", "https://example.test/path")
    finally:
        server._REQUEST_API_KEY.reset(reset)

    expected = [
        ("/api/v1/blackdome/intelligence/ioc/explain", {"indicator_type": "ip", "value": "1.2.3.4"}),
        ("/api/v1/blackdome/intelligence/samples/compare", {"left_sha256": "a" * 64, "right_sha256": "b" * 64}),
        ("/api/v1/blackdome/intelligence/genome/cluster", {"entity_kind": "domain", "value": "example.test", "depth": 2, "max_nodes": 4, "max_edges": 5, "max_evidence": 6}),
        ("/api/v1/blackdome/intelligence/genome/novelty", {"entity_kind": "url", "value": "https://example.test/path"}),
    ]
    assert len(captured) == len(expected)
    for request, (path, body) in zip(captured, expected, strict=True):
        assert request.method == "POST"
        assert request.url.path == path
        assert request.headers["Authorization"] == "Bearer customer-key"
        assert json.loads(request.content) == body


@pytest.mark.asyncio
async def test_threatdrop_tools_use_account_bound_summary_path_without_selector():
    """Changing the account-bound summary path or adding a selector would break tenant isolation."""

    def handler(request):
        return json_response({"id": 42, "verdict": "malicious", "counts": {}, "takedown_progress": {}})

    reset = server.set_request_api_key("customer-key")
    try:
        with mock_api(handler) as captured:
            await server.get_threatdrop_case(42)
            await server.get_takedown_status(42)
    finally:
        server._REQUEST_API_KEY.reset(reset)

    assert len(captured) == 2
    for request in captured:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/blackdome/threatdrop/submissions/42/mcp-summary"
        assert not request.url.params
        assert request.headers["Authorization"] == "Bearer customer-key"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args", "secret"),
    [
        ("explain_ioc", ("ip", " 1.2.3.4"), "1.2.3.4"),
        ("explain_ioc", ("url", "https://user:secret@example.test/"), "secret"),
        ("compare_samples", ("A" * 64, "b" * 64), "A" * 64),
        ("get_evidence_cluster", ("domain", "bad domain"), "bad domain"),
        ("get_reproducible_novelty", ("url", "ftp://example.test/"), "ftp://example.test"),
        ("get_threatdrop_case", (True,), "True"),
        ("get_takedown_status", ("42",), "42"),
    ],
)
async def test_customer_intelligence_invalid_input_does_not_call_http(tool, args, secret):
    """Removing strict local validation would send unsafe or malformed selectors to the API."""

    def handler(request):
        pytest.fail(f"unexpected HTTP request: {request.url}")

    with mock_api(handler) as captured:
        out = await getattr(server, tool)(*args)

    assert captured == []
    assert "Invalid request parameters." in out
    assert secret not in out


@pytest.mark.asyncio
async def test_customer_intelligence_rejects_non_integer_cluster_bounds_without_http():
    """Changing exact-integer validation would admit bool, floats, or numeric strings."""

    def handler(request):
        pytest.fail(f"unexpected HTTP request: {request.url}")

    invalid = [True, 1.0, "1"]
    with mock_api(handler) as captured:
        for value in invalid:
            out = await server.get_evidence_cluster("ip", "1.2.3.4", depth=value)
            assert "Invalid request parameters." in out
    assert captured == []


@pytest.mark.asyncio
async def test_customer_intelligence_clamps_cluster_bounds_to_product_caps():
    """Removing caps could ask the service for an unbounded graph response."""

    def handler(request):
        return json_response({"nodes": [], "edges": [], "evidence": []})

    with mock_api(handler) as captured:
        await server.get_evidence_cluster("ip", "1.2.3.4", depth=2, max_nodes=999, max_edges=999, max_evidence=999)

    assert json.loads(captured[0].content) == {
        "entity_kind": "ip",
        "value": "1.2.3.4",
        "depth": 2,
        "max_nodes": 100,
        "max_edges": 200,
        "max_evidence": 100,
    }


@pytest.mark.asyncio
async def test_takedown_status_returns_only_the_approved_case_subset():
    """Returning the original case would leak email and arbitrary analysis to MCP callers."""

    def handler(request):
        return json_response(
            {
                "id": 42,
                "message_id": "mail-42",
                "received_at": "2026-08-31T00:00:00Z",
                "verdict": "malicious",
                "confidence": 91,
                "risk_score": 88,
                "threat_level": "high",
                "detonation_status": "complete",
                "analysis_complete": True,
                "quarantined": False,
                "counts": {"urls_extracted": 2},
                "takedown_progress": {
                    "reports_total": 1,
                    "reports_sent": 1,
                    "sent_at": "2026-08-31T00:01:00Z",
                    "provider_reply": {"state": "acknowledged", "count": 1, "last_at": "2026-08-31T00:02:00Z"},
                    "outcome": {"state": "provider_confirmed", "evidence_level": "provider_confirmation", "decided_at": "2026-08-31T00:03:00Z", "last_checked_at": "2026-08-31T00:04:00Z"},
                    "timeline": [],
                },
                "submitter_email": "customer@example.test",
                "analysis_reasoning": "unrelated prose",
                "normalized_email": {"body": "secret body"},
            }
        )

    with mock_api(handler):
        out = await server.get_takedown_status(42)

    assert json.loads(out) == {
        "submission": {"id": 42, "message_id": "mail-42", "received_at": "2026-08-31T00:00:00Z"},
        "case_state": {
            "verdict": "malicious",
            "confidence": 91,
            "risk_score": 88,
            "threat_level": "high",
            "detonation_status": "complete",
            "analysis_complete": True,
            "quarantined": False,
        },
        "counts": {"urls_extracted": 2},
        "takedown_progress": {
            "reports_total": 1,
            "reports_sent": 1,
            "sent_at": "2026-08-31T00:01:00Z",
            "provider_reply": {"state": "acknowledged", "count": 1, "last_at": "2026-08-31T00:02:00Z"},
            "outcome": {"state": "provider_confirmed", "evidence_level": "provider_confirmation", "decided_at": "2026-08-31T00:03:00Z", "last_checked_at": "2026-08-31T00:04:00Z"},
            "timeline": [],
        },
    }


@pytest.mark.asyncio
async def test_takedown_status_drops_unknown_nested_email_evidence_and_outbound_fields():
    """Removing a nested allowlist could leak provider mail or evidence through an approved parent."""

    def handler(request):
        return json_response(
            {
                "id": 42,
                "counts": {
                    "urls_extracted": 2,
                    "urls_detonated": 1,
                    "abuse_reports_sent": 1,
                    "phone_reports_sent": 0,
                    "email_body": "secret body",
                    "evidence": {"raw": "do not expose"},
                },
                "takedown_progress": {
                    "reports_total": 3,
                    "reports_sent": 2,
                    "sent_at": "2026-08-31T00:01:00Z",
                    "provider_reply": {
                        "state": "actioned",
                        "count": 2,
                        "last_at": "2026-08-31T00:02:00Z",
                        "email_body": "provider mail",
                        "credentials": {"token": "secret"},
                    },
                    "outcome": {
                        "state": "provider_confirmed",
                        "evidence_level": "provider_confirmation",
                        "decided_at": "2026-08-31T00:03:00Z",
                        "last_checked_at": "2026-08-31T00:04:00Z",
                        "analysis_prose": "arbitrary text",
                    },
                    "timeline": [
                        {
                            "event": "provider_reply",
                            "occurred_at": "2026-08-31T00:02:00Z",
                            "summary": "Provider confirmed action.",
                            "state": "actioned",
                            "provider": "Example Provider",
                            "outbound_mail": "raw message",
                            "evidence": {"mail": "secret"},
                        },
                        {"event": "provider_reply", "email_body": "incomplete"},
                    ],
                    "outbound_mail": "raw message",
                },
            }
        )

    with mock_api(handler):
        out = await server.get_takedown_status(42)

    parsed = json.loads(out)
    assert parsed["counts"] == {
        "urls_extracted": 2,
        "urls_detonated": 1,
        "abuse_reports_sent": 1,
        "phone_reports_sent": 0,
    }
    assert parsed["takedown_progress"] == {
        "reports_total": 3,
        "reports_sent": 2,
        "sent_at": "2026-08-31T00:01:00Z",
        "provider_reply": {"state": "actioned", "count": 2, "last_at": "2026-08-31T00:02:00Z"},
        "outcome": {"state": "provider_confirmed", "evidence_level": "provider_confirmation", "decided_at": "2026-08-31T00:03:00Z", "last_checked_at": "2026-08-31T00:04:00Z"},
        "timeline": [{"event": "provider_reply", "occurred_at": "2026-08-31T00:02:00Z", "summary": "Provider confirmed action.", "state": "actioned", "provider": "Example Provider"}],
    }
    assert "secret body" not in out
    assert "provider mail" not in out
    assert "raw message" not in out


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_value", [{"nested": "secret"}, ["nested", "secret"]])
async def test_takedown_status_drops_object_and_list_values_for_every_approved_scalar_leaf(hostile_value):
    """Permitting containers under approved leaves would re-open the filtered response boundary."""

    def handler(request):
        return json_response(
            {
                "id": hostile_value,
                "message_id": hostile_value,
                "received_at": hostile_value,
                "verdict": hostile_value,
                "confidence": hostile_value,
                "risk_score": hostile_value,
                "threat_level": hostile_value,
                "detonation_status": hostile_value,
                "analysis_complete": hostile_value,
                "quarantined": hostile_value,
            }
        )

    with mock_api(handler):
        out = await server.get_takedown_status(42)

    parsed = json.loads(out)
    assert parsed["submission"] == {}
    assert parsed["case_state"] == {}
    assert "secret" not in out


@pytest.mark.asyncio
async def test_takedown_status_drops_boolean_values_for_integer_submission_and_case_leaves():
    """Treating bool as int would allow malformed identity or score values through the response."""

    def handler(request):
        return json_response(
            {
                "id": True,
                "message_id": "mail-42",
                "received_at": "2026-08-31T00:00:00Z",
                "verdict": "malicious",
                "confidence": True,
                "risk_score": False,
                "threat_level": "high",
                "detonation_status": "complete",
                "analysis_complete": True,
                "quarantined": False,
            }
        )

    with mock_api(handler):
        out = await server.get_takedown_status(42)

    assert json.loads(out) == {
        "submission": {"message_id": "mail-42", "received_at": "2026-08-31T00:00:00Z"},
        "case_state": {
            "verdict": "malicious",
            "threat_level": "high",
            "detonation_status": "complete",
            "analysis_complete": True,
            "quarantined": False,
        },
        "counts": {},
        "takedown_progress": {},
    }


@pytest.mark.asyncio
async def test_threatdrop_mcp_tools_request_and_enforce_bounded_case_summaries():
    """Changing either tool to fetch a full case could expose a case-sized payload."""

    def handler(request):
        return json_response(
            {
                "submission": {"id": 42, "message_id": "message-42"},
                "case_state": {"verdict": "phishing", "confidence": 90},
                "counts": {"urls_extracted": 21},
                "detonations": [
                    {"detonation_id": f"det-{number}", "verdict": "phishing"}
                    for number in range(11)
                ],
                "attachments": [
                    {"attachment_id": number, "verdict": "malicious"}
                    for number in range(11)
                ],
                "takedown_progress": {
                    "timeline": [
                        {
                            "event": "provider_reply",
                            "occurred_at": f"2026-08-31T01:{number:02d}:00Z",
                            "summary": "Provider replied.",
                            "raw_email": "SENTINEL_SECRET",
                        }
                        for number in range(21)
                    ]
                },
                "collection_meta": {
                    "detonations": {"returned": 11, "total": 50, "truncated": True},
                    "attachments": {"returned": 11, "total": 30, "truncated": True},
                    "takedown_timeline": {"returned": 21, "total": 99, "truncated": True},
                },
                "evidence_report": {"raw_email": "SENTINEL_SECRET"},
            }
        )

    with mock_api(handler) as captured:
        case_out = json.loads(await server.get_threatdrop_case(42))
        status_out = json.loads(await server.get_takedown_status(42))

    assert [request.url.path for request in captured] == [
        "/api/v1/blackdome/threatdrop/submissions/42/mcp-summary",
        "/api/v1/blackdome/threatdrop/submissions/42/mcp-summary",
    ]
    for payload in (case_out, status_out):
        assert payload["collection_meta"] == {
            "detonations": {"returned": 10, "total": 50, "truncated": True},
            "attachments": {"returned": 10, "total": 30, "truncated": True},
            "takedown_timeline": {"returned": 20, "total": 99, "truncated": True},
        }
        assert len(payload["detonations"]) == 10
        assert len(payload["attachments"]) == 10
        assert len(payload["takedown_progress"]["timeline"]) == 20
        assert "SENTINEL_SECRET" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_threatdrop_mcp_case_output_is_bounded_with_long_adversarial_scalars():
    """Removing scalar limits would make a nominally capped response arbitrarily large."""
    huge_secret = "SENTINEL_SECRET_" + ("x" * 20_000)
    huge_timestamp = "2026-08-31T01:00:00." + ("1" * 20_000) + "Z"

    def handler(request):
        return json_response(
            {
                "submission": {"id": 42, "message_id": huge_secret},
                "case_state": {"verdict": huge_secret},
                "detonations": [
                    {"detonation_id": f"det-{number}", "verdict": huge_secret}
                    for number in range(11)
                ],
                "attachments": [
                    {"attachment_id": number, "content_type": huge_secret}
                    for number in range(11)
                ],
                "takedown_progress": {
                    "timeline": [
                        {
                            "event": "provider_reply",
                            "occurred_at": huge_timestamp if number == 0 else f"2026-08-31T01:{number:02d}:00Z",
                            "summary": huge_secret,
                        }
                        for number in range(21)
                    ]
                },
            }
        )

    with mock_api(handler):
        output = await server.get_threatdrop_case(42)

    parsed = json.loads(output)
    assert len(parsed["detonations"]) == 10
    assert len(parsed["attachments"]) == 10
    assert len(parsed["takedown_progress"]["timeline"]) == 20
    assert len(output) < 20_000
    assert "SENTINEL_SECRET" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 503])
async def test_customer_intelligence_errors_remain_explicit_without_echoing_selector(status):
    """Using the generic API error formatter could echo a secret-bearing URL from a response."""

    secret_url = "https://user:very-secret@example.test/"

    def handler(request):
        return json_response({"detail": secret_url}, status=status)

    with mock_api(handler):
        out = await server.explain_ioc("url", "https://example.test/",)

    assert str(status) in out or status == 503
    assert "very-secret" not in out
    assert secret_url not in out
