"""Every tool names the plan that opens it and what that costs, in the offer's own words (full test 2026-11-21, D1).

The prices and trials are read from docs/blackdome/OFFER.md section 2 (the card headings and their trial lines),
the same text the site's offer guard checks app/lib/offer.ts against. In the public package repository, which does
not carry the offer document, the price test is skipped; the table test still runs.
"""

import asyncio
import re
from pathlib import Path

import httpx
import pytest

import blackdome_mcp.server as server
from blackdome_mcp import plans

_REAL_ASYNC_CLIENT = httpx.AsyncClient
OFFER = Path(__file__).resolve().parents[3] / "docs" / "blackdome" / "OFFER.md"


def _offer_cards():
    """{plan name: (monthly US$, trial days or None)} from OFFER.md section 2's card headings."""
    text = OFFER.read_text()
    section = text.split("## 2. The offer", 1)[1].split("## 3.", 1)[0]
    cards = {}
    current = None
    for line in section.splitlines():
        heading = re.match(r"^\*\*(.+?): US\$([\d,]+) a month\b.*\*\*$", line)
        if heading:
            current = heading.group(1)
            cards[current] = [int(heading.group(2).replace(",", "")), None]
            continue
        if line.startswith("**"):
            current = None
        elif current:
            trial = re.match(r"^- (\d+)-day free trial$", line)
            if trial:
                cards[current][1] = int(trial.group(1))
    return {name: tuple(value) for name, value in cards.items()}


def _tool_names():
    return [tool.name for tool in asyncio.run(server.mcp.list_tools())]


def test_every_tool_has_a_plan_in_the_table_and_nothing_else_is_in_it():
    names = set(_tool_names())
    assert len(names) == 29
    assert "warboard" not in names
    in_table = {name.split(":")[0] for name in plans.TOOL_ACCESS}
    assert names == in_table
    for access in plans.TOOL_ACCESS.values():
        assert access in (plans.FREE, plans.ANY_KEY, plans.NONE) or all(p in plans.PLANS for p in access)


@pytest.mark.skipif(not OFFER.is_file(), reason="the offer document lives in the monorepo only")
def test_the_plan_names_prices_and_trials_are_the_offers():
    cards = _offer_cards()
    for plan in plans.PLANS.values():
        assert plan.name in cards, plan.name
        assert (plan.monthly_usd, plan.trial_days) == cards[plan.name], plan.name


@pytest.mark.parametrize("tool", sorted(plans.TOOL_ACCESS))
def test_each_refusal_names_the_plan_price_and_pricing_page(tool):
    access = plans.TOOL_ACCESS[tool]
    for situation in ("no_key", "bad_key", "plan"):
        for hosted in (True, False):
            sentence = plans.refusal(tool, situation, hosted=hosted)
            if access not in (plans.FREE,):
                assert "https://blackdome.ai/pricing" in sentence, (tool, situation)
            if isinstance(access, tuple):
                assert plans.PLANS[access[0]].priced() in sentence
            if hosted:
                assert "BLACKDOME_API_KEY" not in sentence, (tool, situation)
    assert "BLACKDOME_API_KEY=<key>" in plans.refusal(tool, "no_key", hosted=False)
    assert "Authorization: Bearer" in plans.refusal(tool, "no_key", hosted=True)


def test_the_example_sentence():
    assert plans.plan_sentence("list_payloads") == (
        "list_payloads needs Threat Intel Analyst (US$99 a month, 14-day free trial) or higher. "
        "See https://blackdome.ai/pricing.")
    assert plans.plan_sentence("get_takedown_status") == (
        "get_takedown_status needs ThreatDrop API (US$49 a month). See https://blackdome.ai/pricing.")


def _call(tool_coro, status, *, key, hosted, monkeypatch, detail="Missing or invalid API key"):
    monkeypatch.setattr(server, "API_KEY", key)
    monkeypatch.setattr(server, "_hosted", lambda: hosted)
    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(status, json={"detail": detail}))
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(server.httpx, "AsyncClient", _factory)
    return asyncio.run(tool_coro())


@pytest.mark.parametrize("hosted", [True, False])
@pytest.mark.parametrize("tool_coro,tool", [
    (lambda: server.list_payloads(), "list_payloads"),
    (lambda: server.explain_ioc("domain", "example.test"), "explain_ioc"),
    (lambda: server.list_catalogue_families(), "list_catalogue_families"),
    (lambda: server.get_takedown_status(7), "get_takedown_status"),
])
def test_the_tools_say_it(monkeypatch, hosted, tool_coro, tool):
    no_key = _call(tool_coro, 401, key="", hosted=hosted, monkeypatch=monkeypatch)
    assert no_key.startswith("Authentication failed (401): ") and plans.plan_sentence(tool) in no_key
    assert ("BLACKDOME_API_KEY" in no_key) is (not hosted)
    bad_key = _call(tool_coro, 401, key="bd_wrong", hosted=hosted, monkeypatch=monkeypatch)
    assert "was not accepted" in bad_key and plans.plan_sentence(tool) in bad_key
    wrong_plan = _call(tool_coro, 403, key="bd_other_plan", hosted=hosted, monkeypatch=monkeypatch,
                       detail="Feature requires a higher plan")
    assert f"Your plan does not include {tool}. {plans.plan_sentence(tool)}" in wrong_plan


def test_stix_export_names_threat_intel_pro(monkeypatch):
    out = _call(lambda: server.export_iocs(fmt="stix"), 403, key="", hosted=True, monkeypatch=monkeypatch,
                detail="Feature 'stix_export' requires a higher plan")
    assert "export_iocs with fmt stix needs Threat Intel Pro (US$299 a month, 14-day free trial)" in out
