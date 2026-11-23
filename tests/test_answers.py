"""Answers an assistant can use (full test 2026-11-21, 04-mcp findings 6-8, item D4).

- explain_ioc: a miss says "No evidence record for this indicator."; a hit says plainly what the indicator is,
  when and where it was seen and what it links to.
- Every list tool takes a limit with a default and a maximum, and says when there is more.
- Every timestamp is UTC with a Z.
No live calls: the API is an httpx.MockTransport.
"""

import asyncio
import json

import httpx
import pytest

import blackdome_mcp.server as server

_REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.fixture
def api(monkeypatch):
    """api(handler) routes the server's API calls to ``handler``; returns the captured requests."""
    monkeypatch.setattr(server, "API_KEY", "bd_fixture")
    captured = []

    def install(handler):
        def recording(request):
            captured.append(request)
            return handler(request)

        def _factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(recording)
            return _REAL_ASYNC_CLIENT(*args, **kwargs)

        monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
        return captured

    return install


def _run(coro):
    return asyncio.run(coro)


# --- explain_ioc -----------------------------------------------------------------------------------------------

# The shape the live route answered for a hit on 2026-11-21 (values invented).
HIT = {
    "found": True,
    "entity_key": "e" * 64,
    "entity": {"entity_key": "e" * 64, "entity_type": "indicator", "canonical_fact_digest": "d" * 64,
               "canonical_facts": {}, "first_evidence_key": "f" * 64, "created_at": "2026-11-12T12:16:21.882191+00:00"},
    "provenance": "external_observed",
    "evidence_references": [
        {"evidence_key": f"{i:064x}", "provenance": "external_observed",
         "observed_at": f"2026-11-{13 + i % 5:02d}T23:22:25.211730+00:00", "completed_at": None,
         "quality": {"a": 1, "b": 2}, "analysis": None,
         "provenance_label": "Seen from a real outside source, not a test or our own systems",
         "quality_label": "Not verified", "reason_label": "No complete, checked record",
         "analysis_label": "No file analysis is attached to this evidence"}
        for i in range(18)
    ],
    "linked_entities": [{"entity_key": "e" * 64, "entity_type": "indicator", "canonical_facts": {}}],
    "edges": [],
    "uncertainty": {"state": "insufficient_evidence", "reason_code": "authority_binding_unverified"},
    "completeness": {"state": "insufficient_evidence"},
    "provenance_label": "Seen from a real outside source, not a test or our own systems",
    "uncertainty_label": "Not verified",
    "uncertainty_reason_label": "No complete, checked record of the analysis run that produced it",
    "completeness_label": "Not enough verified evidence",
}


def test_explain_ioc_miss_is_a_plain_sentence_and_not_a_failure(api):
    api(lambda request: httpx.Response(404, json={"detail": "Customer intelligence entity was not found"}))
    assert _run(server.explain_ioc("ip", "192.0.2.7")) == "No evidence record for this indicator."
    result = _run(server._call_tool_with_limit_note(
        "explain_ioc", {"indicator_type": "ip", "indicator_value": "192.0.2.7"}))
    assert not getattr(result, "isError", False)


def test_explain_ioc_hit_says_what_where_when_and_links(api):
    api(lambda request: httpx.Response(200, json=HIT))
    text = _run(server.explain_ioc("domain", "bad.example"))
    record = json.loads(text)
    assert record["indicator"] == {"type": "domain", "value": "bad.example"}
    assert record["found"] is True
    assert record["first_seen"] == "2026-11-13T23:22:25Z" and record["last_seen"] == "2026-11-17T23:22:25Z"
    assert record["first_recorded_at"] == "2026-11-12T12:16:21Z"
    assert record["where_seen"] == ["Seen from a real outside source, not a test or our own systems"]
    assert record["evidence_count"] == 18 and len(record["evidence"]) == 10
    assert "Showing the newest 10 of 18 evidence records." in record["more"]
    assert record["links_to"] == [] and "links this indicator to nothing else" in record["links_note"]
    assert "e" * 64 not in text                       # graph keys are not evidence a reader can use
    assert len(text) < len(json.dumps(HIT, indent=2)) / 2


def test_threatdrop_miss_is_a_plain_sentence(api):
    api(lambda request: httpx.Response(404, json={"detail": "not found"}))
    assert _run(server.get_takedown_status(7)) == "No ThreatDrop submission with this id on this account."


# --- limits ----------------------------------------------------------------------------------------------------

LIST_TOOLS = {
    "top_attackers": "limit", "attack_map": "limit", "attack_heatmap": "limit", "credential_preview": "limit",
    "recent_iocs": "limit", "export_iocs": "limit", "search_credentials": "limit", "list_payloads": "limit",
    "get_actor": "limit", "list_notable_sessions": "limit",
    "get_session_transcript": "limit", "list_detonations": "limit", "get_detonation_report": "ioc_limit",
    "get_artifact": "ioc_limit", "list_catalogue_families": "limit", "get_catalogue_family": "timeline_limit",
    "search_catalogue": "limit", "recent_catalogue_specimens": "limit",
}


def test_every_list_tool_takes_a_limit_with_a_default_and_a_stated_maximum():
    tools = {tool.name: tool for tool in _run(server.mcp.list_tools())}
    for name, param in LIST_TOOLS.items():
        schema = tools[name].inputSchema["properties"]
        assert param in schema and isinstance(schema[param].get("default"), int), name
        assert schema[param]["default"] <= 100, name
        assert "at most" in tools[name].description or "1-" in tools[name].description, name


def test_export_iocs_json_is_cut_to_the_limit_and_says_there_is_more(api):
    iocs = [{"value": f"192.0.2.{i}", "first_seen": "2026-11-20T10:00:00+00:00"} for i in range(250)]
    api(lambda request: httpx.Response(200, json={"feed": "x", "count": 250, "iocs": iocs}))
    payload = json.loads(_run(server.export_iocs()))
    assert len(payload["iocs"]) == 100
    assert payload["more"] == "Showing 100 of 250 indicators. There are more: raise limit (at most 1000)."
    assert payload["iocs"][0]["first_seen"] == "2026-11-20T10:00:00Z"
    payload = json.loads(_run(server.export_iocs(limit=5000)))
    assert len(payload["iocs"]) == 250 and "more" not in payload


def test_export_iocs_csv_and_stix_are_cut_too(api):
    csv = "value,type\n" + "".join(f"192.0.2.{i},ipv4\n" for i in range(150))
    api(lambda request: httpx.Response(200, text=csv))
    out = _run(server.export_iocs(fmt="csv", limit=10))
    assert out.splitlines()[0] == "value,type" and len(out.splitlines()) == 12
    assert out.splitlines()[-1] == "# Showing 10 of 150 rows. There are more: raise limit (at most 1000)."
    bundle = {"type": "bundle", "id": "bundle--1",
              "objects": [{"type": "identity", "id": "identity--1"}]
              + [{"type": "indicator", "id": f"indicator--{i}"} for i in range(30)]}
    api(lambda request: httpx.Response(200, json=bundle))
    out = json.loads(_run(server.export_iocs(fmt="stix", limit=10)))
    assert [o["type"] for o in out["objects"]].count("indicator") == 10
    assert out["objects"][0]["type"] == "identity"
    assert out["x_blackdome_more"].startswith("Showing 10 of 30 indicators.")


def test_a_full_page_says_there_may_be_more(api):
    api(lambda request: httpx.Response(200, json={"detonations": [{"id": i} for i in range(20)], "count": 20}))
    payload = json.loads(_run(server.list_detonations()))
    assert payload["more"] == "Showing 20 detonations. There may be more: raise limit (at most 100)."
    captured = api(lambda request: httpx.Response(200, json={"detonations": [], "count": 0}))
    payload = json.loads(_run(server.list_detonations(limit=5000)))
    assert "more" not in payload and captured[-1].url.params["limit"] == "100"


def test_a_paged_answer_says_where_the_next_page_starts(api):
    api(lambda request: httpx.Response(200, json={"credentials": [{}] * 20, "total": 95, "has_more": True,
                                                  "next_offset": 20}))
    payload = json.loads(_run(server.search_credentials()))
    assert payload["more"] == ("Showing 20 of 95 credentials. There are more: raise limit (at most 100) or "
                               "pass offset=20 for the next page.")


def test_detonation_report_iocs_and_family_timeline_are_bounded(api):
    api(lambda request: httpx.Response(200, json={"detonation_id": "x", "iocs": [{"v": i} for i in range(96)]}))
    payload = json.loads(_run(server.get_detonation_report("x")))
    assert len(payload["iocs"]) == 25 and payload["more"].startswith("Showing 25 of 96 iocs.")
    family = {"family": {"key": "k"}, "members": {"items": [{}] * 3, "total": 3},
              "timeline": {"events": [{"at": "2026-11-01T00:00:00+00:00"}] * 128}}
    api(lambda request: httpx.Response(200, json=family))
    payload = json.loads(_run(server.get_catalogue_family("mozi-007ba229e43c", member_limit=3)))
    assert len(payload["timeline"]["events"]) == 20
    assert payload["more"].startswith("Showing 20 of 128 timeline events.")


# --- time ------------------------------------------------------------------------------------------------------

def test_every_time_is_utc_with_z(api):
    # get_actor's *_str fields came in the API host's local time with no zone (an hour ahead of UTC).
    api(lambda request: httpx.Response(200, json={"items": [{
        "actor_id": "a", "last_seen": 1795253665, "last_seen_str": "2026-11-21 10:34:25",
        "first_seen": "2026-11-21T11:00:00+01:00", "note": "not a time", "count": 1795253665,
    }], "count": 1}))
    item = json.loads(_run(server.get_actor()))["items"][0]
    assert item["last_seen_str"] == "2026-11-21T09:34:25Z"
    assert item["first_seen"] == "2026-11-21T10:00:00Z"
    assert item["note"] == "not a time" and item["last_seen"] == 1795253665
