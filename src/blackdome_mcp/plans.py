"""Which plan opens each tool, and the one sentence a refused caller is told (2026-11-21).

The plans, prices and trials are the words of docs/blackdome/OFFER.md section 2 (the offer is law; a test checks
these numbers against it). Full test 2026-11-21 (04-mcp finding 1): refusals named no plan and no price, 11 tools
named the stdio environment variable to hosted users, and 10 said only "Authentication failed (401)".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

PRICING_URL = "https://blackdome.ai/pricing"


@dataclass(frozen=True)
class Plan:
    name: str
    monthly_usd: int
    trial_days: Optional[int]

    def priced(self) -> str:
        """'Threat Intel Analyst (US$99 a month, 14-day free trial)'."""
        trial = f", {self.trial_days}-day free trial" if self.trial_days else ""
        return f"{self.name} (US${self.monthly_usd:,} a month{trial})"


PLANS = {
    "analyst": Plan("Threat Intel Analyst", 99, 14),
    "pro": Plan("Threat Intel Pro", 299, 14),
    "credential": Plan("Credential Intelligence", 199, 14),
    "threatdrop": Plan("ThreatDrop API", 49, None),
}

# Access classes: FREE needs no key; ANY_KEY needs any BlackDome key (a free BlackDome Free account has one);
# NONE is on no plan on sale; otherwise the plan ids that include the tool, cheapest first.
FREE = "free"
ANY_KEY = "any_key"
NONE = "none"

TOOL_ACCESS: dict[str, object] = {
    # Free MCP tools, no API key needed (BlackDome Free card).
    "lookup_attacker_ip": FREE,
    "top_attackers": FREE,
    "attack_map": FREE,
    "attack_heatmap": FREE,
    "credential_preview": FREE,
    "verify_sigil": FREE,
    "recent_iocs": FREE,
    "ioc_trends": FREE,
    "export_iocs": FREE,            # json and csv; STIX is "export_iocs:stix" below
    "whoami": ANY_KEY,
    # Threat Intel Analyst ("API access: indicators, attackers, payloads ..."; "An evidence record ...").
    "list_payloads": ("analyst", "pro"),
    "get_actor": ("analyst", "pro"),
    "explain_ioc": ("analyst", "pro"),
    "list_notable_sessions": ("analyst", "pro"),
    # Threat Intel Pro (catalogue, detonation reports, sample comparison and novelty, STIX).
    "export_iocs:stix": ("pro",),
    "list_detonations": ("pro",),
    "get_detonation_report": ("pro",),
    "get_artifact": ("pro",),
    "compare_samples": ("pro",),
    "get_evidence_cluster": ("pro",),
    "get_reproducible_novelty": ("pro",),
    "list_catalogue_families": ("pro",),
    "get_catalogue_family": ("pro",),
    "get_catalogue_specimen": ("pro",),
    "search_catalogue": ("pro",),
    "recent_catalogue_specimens": ("pro",),
    # Credential Intelligence.
    "search_credentials": ("credential",),
    "credential_stats": ("credential",),
    # ThreatDrop API ("MCP tools for case and takedown status").
    "get_threatdrop_case": ("threatdrop",),
    "get_takedown_status": ("threatdrop",),
    # On no plan on sale (OFFER.md section 11, 2026-11-20; session_intel is on no card).
    "get_session_transcript": NONE,
}


def _label(tool: str) -> str:
    return "export_iocs with fmt stix" if tool == "export_iocs:stix" else tool


def plan_sentence(tool: str) -> str:
    """Which plan opens ``tool`` and what it costs, with the pricing link."""
    access = TOOL_ACCESS.get(tool)
    label = _label(tool)
    if access == FREE:
        return f"{label} is free and works with no API key at all."
    if access == ANY_KEY:
        return f"{label} works with any BlackDome API key, including a free BlackDome Free account. See {PRICING_URL}."
    if access == NONE or access is None:
        return f"{label} is not part of any plan on sale. See {PRICING_URL} for what is."
    plans = [PLANS[plan_id] for plan_id in access]
    if [plan.name for plan in plans] == ["Threat Intel Analyst", "Threat Intel Pro"]:
        needs = f"{plans[0].priced()} or higher"
    else:
        needs = " or ".join(plan.priced() for plan in plans)
    return f"{label} needs {needs}. See {PRICING_URL}."


def _how_to_send_a_key(hosted: bool) -> str:
    if hosted:
        return "Send your key on every request as the header Authorization: Bearer <key>."
    return ("Set BLACKDOME_API_KEY=<key> in this MCP server's environment, for example "
            "claude mcp add blackdome -e BLACKDOME_API_KEY=<key> -- uvx blackdome-mcp.")


def refusal(tool: str, situation: str, *, hosted: bool) -> str:
    """The sentence for a refused call. situation: 'no_key', 'bad_key' or 'plan'."""
    label = _label(tool)
    if situation == "no_key":
        carried = "This request carried no API key." if hosted else "No API key is set."
        return f"{label} needs an API key. {carried} {plan_sentence(tool)} {_how_to_send_a_key(hosted)}"
    if situation == "bad_key":
        where = "" if hosted else " Check BLACKDOME_API_KEY."
        if TOOL_ACCESS.get(tool) == FREE:
            return ("The API key sent was not accepted (it is wrong, revoked or deleted), so nothing was answered. "
                    f"{plan_sentence(tool)} Remove the key to use the free tools, or fix it.{where}")
        return f"The API key sent was not accepted (it is wrong, revoked or deleted).{where} {plan_sentence(tool)}"
    if situation == "plan":
        return f"Your plan does not include {label}. {plan_sentence(tool)}"
    raise ValueError(situation)
