"""Exercise the installed console entrypoint through a real MCP stdio client.

Only the external BlackDome API is replaced by a loopback HTTP fixture. These
cases catch wrong routes, parameters, auth forwarding, result transforms and
error handling without using customer credentials or private observations.
"""

import asyncio
import json
import os
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SHA = "a" * 64
OTHER_SHA = "b" * 64
BASE = "/api/v1/blackdome"
# name, arguments, method, path, exact query/body
CASES = [
    ("lookup_attacker_ip", {"ip": "192.0.2.7"}, "GET", "/api/blackdome/lookup/192.0.2.7", {}),
    ("top_attackers", {"days": 2, "limit": 3}, "GET", "/api/blackdome/top-attackers", {"days": "2", "limit": "3"}),
    ("attack_map", {"limit": 1}, "GET", "/api/blackdome/map/events", {"limit": "10"}),
    ("attack_heatmap", {"limit": 1}, "GET", "/api/blackdome/map/heatmap", {"limit": "5"}),
    ("credential_preview", {"limit": 99, "hours": 99}, "GET", "/api/blackdome/credentials/preview", {"limit": "25", "hours": "24"}),
    ("verify_sigil", {"sigil_id": "fixture-sigil"}, "GET", "/api/blackdome/audit/fixture-sigil", {}),
    ("recent_iocs", {"ioc_type": "ipv4", "severity": "high", "limit": 2}, "GET", "/api/blackdome/iocs/public", {"ioc_type": "ipv4", "severity": "high", "limit": "2"}),
    ("ioc_trends", {"days": 2}, "GET", "/api/blackdome/iocs/public/trends", {"days": "2"}),
    ("export_iocs", {}, "GET", BASE + "/threat-intel/feed/json", {"min_confidence": "50", "min_severity": "medium", "days": "30"}),
    ("search_credentials", {"username": "fixture-user", "cross_protocol": True, "limit": 2}, "GET", BASE + "/credentials/search", {"username": "fixture-user", "cross_protocol": "true", "limit": "2", "offset": "0"}),
    ("credential_stats", {"protocol": "ssh"}, "GET", BASE + "/credentials/stats", {"protocol": "ssh"}),
    ("list_payloads", {"limit": 2}, "GET", BASE + "/payloads", {"limit": "2"}),
    ("get_actor", {"risk": "high", "descending": False, "limit": 2}, "GET", BASE + "/actors", {"risk": "high", "descending": "false", "limit": "2"}),
    ("warboard", {"public": True}, "GET", BASE + "/warboard", {"public": "true", "limit": "5"}),
    ("list_notable_sessions", {"limit": 1000}, "GET", BASE + "/intel/sessions", {"min_commands": "3", "limit": "100"}),
    ("get_session_transcript", {"session_id": "fixture-session", "limit": 2000}, "GET", BASE + "/intel/sessions/fixture-session/transcript", {"limit": "1000", "offset": "0"}),
    ("list_detonations", {"limit": 1000}, "GET", BASE + "/intel/detonations", {"limit": "100"}),
    ("get_detonation_report", {"detonation_id": "fixture-job"}, "GET", BASE + "/intel/detonations/fixture-job", {}),
    ("get_artifact", {"sha256": SHA}, "GET", BASE + "/intel/artifacts/" + SHA, {}),
    ("whoami", {}, "GET", BASE + "/me", {}),
    ("explain_ioc", {"indicator_type": "domain", "indicator_value": "example.test"}, "POST", BASE + "/intelligence/ioc/explain", {"indicator_type": "domain", "value": "example.test"}),
    ("compare_samples", {"left_sha256": SHA, "right_sha256": OTHER_SHA}, "POST", BASE + "/intelligence/samples/compare", {"left_sha256": SHA, "right_sha256": OTHER_SHA}),
    ("get_evidence_cluster", {"entity_kind": "sha256", "value": SHA, "depth": 2, "max_nodes": 500, "max_edges": 500, "max_evidence": 500}, "POST", BASE + "/intelligence/genome/cluster", {"entity_kind": "sha256", "value": SHA, "depth": 2, "max_nodes": 100, "max_edges": 200, "max_evidence": 100}),
    ("get_reproducible_novelty", {"entity_kind": "domain", "value": "example.test"}, "POST", BASE + "/intelligence/genome/novelty", {"entity_kind": "domain", "value": "example.test"}),
    ("get_threatdrop_case", {"submission_id": 7}, "GET", BASE + "/threatdrop/submissions/7/mcp-summary", {}),
    ("get_takedown_status", {"submission_id": 7}, "GET", BASE + "/threatdrop/submissions/7/mcp-summary", {}),
    ("export_iocs", {"fmt": "csv"}, "GET", BASE + "/threat-intel/feed/csv", {"min_confidence": "50", "min_severity": "medium", "days": "30"}),
    ("export_iocs", {"fmt": "stix"}, "GET", BASE + "/threat-intel/feed/stix", {"min_confidence": "50", "min_severity": "medium", "days": "30"}),
    ("list_payloads", {"sha256": SHA}, "GET", BASE + "/payloads/" + SHA, {}),
    ("get_actor", {"actor_id": "fixture-actor"}, "GET", BASE + "/actors/fixture-actor/sessions", {"limit": "20"}),
    ("explain_ioc", {"indicator_type": "ip", "indicator_value": "192.0.2.7"}, "POST", BASE + "/intelligence/ioc/explain", {"indicator_type": "ip", "value": "192.0.2.7"}),
    ("explain_ioc", {"indicator_type": "url", "indicator_value": "https://example.test/x"}, "POST", BASE + "/intelligence/ioc/explain", {"indicator_type": "url", "value": "https://example.test/x"}),
]
PUBLIC = {case[0] for case in CASES[:9]}


def is_public(case):
    return case[0] in PUBLIC and case[1].get("fmt") != "stix"


def fixture_payload(name):
    if name in {"get_threatdrop_case", "get_takedown_status"}:
        return {"submission": {"id": 7, "received_at": "2026-11-01T00:00:00Z", "email": "PRIVATE_SENTINEL"},
                "case_state": {"verdict": "malicious", "analysis_complete": True},
                "counts": {"urls_extracted": 1}, "body": "PRIVATE_SENTINEL",
                "attachments": [{"attachment_id": 1, "content_type": "text/plain", "content": "PRIVATE_SENTINEL"}],
                "takedown_progress": {"status": "pending", "timeline": []}}
    if name == "lookup_attacker_ip":
        return {"fixture": name, "credentials_attempted": [{"username": "fixture", "password": "PASSWORD_SENTINEL"}]}
    return {"fixture": name, "items": [], "count": 0}


@contextmanager
def api_fixture(mode):
    state = {"case": None, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            case = state["case"]
            parsed = urlsplit(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            actual = {"method": self.command, "path": parsed.path,
                      "params": json.loads(body) if body else {k: v[0] for k, v in parse_qs(parsed.query).items()},
                      "authorization": self.headers.get("Authorization"), "accept": self.headers.get("Accept")}
            state["requests"].append(actual)
            status = 200
            if mode == "invalid-key":
                status = 401
            elif mode == "keyless" and not is_public(case):
                status = 401
            elif mode == "wrong-plan" and not is_public(case):
                status = 403
            elif mode in {"429", "404", "500"}:
                status = int(mode)
            if status != 200:
                payload = json.dumps({"detail": "fixture refusal"}).encode()
            elif mode == "malformed":
                payload = b"invalid-json"
            elif case[1].get("fmt") == "csv":
                payload = b"fixture,value\nexport_iocs,example.test\n"
            else:
                payload = json.dumps(fixture_payload(case[0])).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Retry-After", "11")
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("mode", ["keyed", "keyless", "invalid-key", "wrong-plan", "429", "404", "500", "malformed"])
def test_installed_stdio_all_tools(mode, tmp_path):
    async def run():
        python = Path(os.environ.get("BLACKDOME_TEST_PYTHON", sys.executable))
        executable = python.parent / ("blackdome-mcp.exe" if os.name == "nt" else "blackdome-mcp")
        override = os.environ.get("BLACKDOME_TEST_COMMAND_JSON")
        command = json.loads(override) if override else [str(executable)]
        if not override:
            assert executable.is_file(), "Install the built package before this protocol test"
        assert isinstance(command, list) and command and all(isinstance(s, str) for s in command)
        with api_fixture(mode) as (state, base):
            env = {"BLACKDOME_BASE_URL": base, "BLACKDOME_TIMEOUT": "3",
                   "BLACKDOME_API_KEY": "" if mode == "keyless" else "bd_fixture_" + mode}
            for key in ("UV_CACHE_DIR", "UV_PYTHON_DOWNLOADS", "HOME"):
                if os.environ.get(key):
                    env[key] = os.environ[key]
            params = StdioServerParameters(command=command[0], args=command[1:], env=env, cwd=tmp_path)
            with (tmp_path / "server.stderr").open("w") as stderr:
                async with stdio_client(params, errlog=stderr) as (read, write):
                    async with ClientSession(read, write) as client:
                        initialized = await client.initialize()
                        assert initialized.serverInfo.version == "0.4.0"
                        listed = await client.list_tools()
                        assert {t.name for t in listed.tools} == {case[0] for case in CASES}
                        assert len(listed.tools) == 26
                        for case in CASES:
                            state["case"] = case
                            state["requests"].clear()
                            result = await client.call_tool(case[0], case[1])
                            text = "\n".join(c.text for c in result.content if c.type == "text")
                            assert not result.isError, (mode, case[0], text)
                            assert len(state["requests"]) == 1, (mode, case[0], text)
                            request = state["requests"][0]
                            assert (request["method"], request["path"], request["params"]) == case[2:], (case, request)
                            assert request["authorization"] == (None if mode == "keyless" else "Bearer bd_fixture_" + mode)
                            assert request["accept"] == ("text/csv" if case[1].get("fmt") == "csv" else "application/json")
                            refused = mode == "invalid-key" or (mode in {"keyless", "wrong-plan"} and not is_public(case))
                            if refused or mode in {"429", "404", "500"}:
                                status = "401" if mode in {"invalid-key", "keyless"} else "403" if mode == "wrong-plan" else mode
                                if mode == "404" and case[0] in {"lookup_attacker_ip", "verify_sigil"}:
                                    assert json.loads(text)["found"] is False
                                else:
                                    assert status in text, (mode, case[0], text)
                                if mode == "429":
                                    assert "11" in text
                            elif mode == "malformed" and case[1].get("fmt") != "csv":
                                assert "Request failed:" in text or "unavailable" in text, (case[0], text)
                            elif case[1].get("fmt") == "csv":
                                assert text == ("invalid-json" if mode == "malformed" else "fixture,value\nexport_iocs,example.test\n")
                            elif case[0] in {"get_threatdrop_case", "get_takedown_status"}:
                                assert json.loads(text)["submission"]["id"] == 7
                                assert "PRIVATE_SENTINEL" not in text
                            else:
                                assert json.loads(text)["fixture"] == case[0]
                                if case[0] == "lookup_attacker_ip":
                                    assert "PASSWORD_SENTINEL" not in text
                                    assert json.loads(text)["credentials_attempted"][0]["password"] == "********"
                            assert "bd_fixture_" not in text
                        state["requests"].clear()
                        for name, arguments in [
                            ("explain_ioc", {"indicator_type": "url", "indicator_value": "file:///private"}),
                            ("compare_samples", {"left_sha256": "not-a-hash", "right_sha256": SHA}),
                            ("get_evidence_cluster", {"entity_kind": "sha256", "value": SHA, "depth": 3}),
                            ("get_reproducible_novelty", {"entity_kind": "invalid", "value": "secret"}),
                            ("get_threatdrop_case", {"submission_id": 0}),
                            ("get_takedown_status", {"submission_id": -1}),
                        ]:
                            result = await client.call_tool(name, arguments)
                            assert "Invalid request parameters." in result.content[0].text
                            assert state["requests"] == []

    asyncio.run(asyncio.wait_for(run(), timeout=90))
