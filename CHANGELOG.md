# Changelog

## 0.5.1 - 2026-11-16

- No tool was added, removed or renamed, and no request sent to the service
  changed. Tool descriptions, error texts and the README now name the plans
  on sale (Threat Intel Analyst, Threat Intel Pro, Credential Intelligence,
  ThreatDrop API) and which plan each tool needs. The earlier "candidate
  Enterprise/OEM pilot" and "Pro or higher" wording is gone; Enterprise is
  "talk to us".
- `list_payloads`, `get_actor` and `warboard` need Threat Intel Analyst or
  Pro. The service now checks this: API access on another plan no longer
  unlocks them.
- The session tools (`list_notable_sessions`, `get_session_transcript`) are
  described as needing `session_intel`, which no plan on sale includes.
- A rate-limit error states a retry time only when the service sent one
  (it used to print "Retry after ? seconds"). On the general tools it also
  repeats the service's own sentence, which names the limit of your plan.
- An access-denied error says when the cause is an expired key, an inactive
  account or a missing scope instead of always blaming the plan.
- Error details from the service are shortened to one line of at most 300
  characters.
- The README states the request limits for each plan, that a cancelled or
  unpaid account continues as BlackDome Free, and that `export_iocs` is the
  keyless tool with a request cap.

## 0.5.0 - 2026-11-15

- Add five read-only specimen catalogue tools (Pro: `genome_clusters`):
  `list_catalogue_families`, `get_catalogue_family`, `get_catalogue_specimen`,
  `search_catalogue` and `recent_catalogue_specimens`. They read the shared
  honeypot catalogue of captured malware: families, build history, public
  tools, indicators (hosts, pools, wallets, control endpoints), related
  families and lineage. Sample files are never returned. The package now
  exposes 31 tools.
- Validate catalogue selectors locally (family names, lowercase SHA-256,
  4-120 character search text, integer paging) before any request; send
  selectors only in JSON bodies; cap page sizes at the service limits.
- Catalogue errors say why access was refused (plan, inactive subscription,
  missing read scope, expired key or inactive account) without relaying the
  server's text, and report a rejected request as invalid rather than
  unavailable.

## 0.4.0 - 2026-11-07

- Fix fresh installs by requiring MCP SDK 1.30 or later within the v1 line.
  SDK v2 uses a different API; SDK 1.20 fails with current Pydantic releases.
- Add six read-only tools: IOC explanations, deterministic sample comparison,
  evidence clusters, reproducible novelty, ThreatDrop case summaries and
  takedown-workflow status. The package now exposes26tools.
- Bound and sanitize ThreatDrop summaries; retain API-key and product gates.
- Advertise the package version in MCP initialization.
- Validate built wheel/source artifacts in isolated environments. Exercise all
  tools through the installed stdio entrypoint, including keyless/keyed calls,
  authentication failures, plan refusal, rate limits, not-found/server errors,
  malformed responses and privacy checks on Python3.10,3.12and3.13.
