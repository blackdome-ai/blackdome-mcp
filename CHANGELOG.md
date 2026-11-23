# Changelog

## 0.5.3 - 2026-11-23

One tool was removed: the warboard tool (the warboard was retired on 20 November 2026 and its API route now answers 410). No other tool was added, removed or renamed (30 tools). What a tool answers changed:

- Refusals name the plan and its price. A tool your key's plan does not include,
  a call with no key, or a key the service does not accept is answered with one
  sentence naming the plan that includes the tool, its monthly price, its free
  trial and https://blackdome.ai/pricing, for example "list_payloads needs
  Threat Intel Analyst (US$99 a month, 14-day free trial) or higher." The hosted
  server says to send the key as a header; the local package says how to set
  `BLACKDOME_API_KEY`. An expired key, an inactive account or a missing scope
  still says so instead.
- Failures are failures: a refusal, an error from the service, a timeout or an
  invalid argument is a failed tool call (`isError: true`), not a result.
- A wrong key is refused on every tool, the free ones included; it never
  quietly gets the free answers. Remove the key to use the free tools.
- Timeouts: one answer is waited for up to 45 seconds (was 15), and a timeout
  says "The BlackDome API did not answer within 45 seconds. Try again."
- Evidence records: `explain_ioc` gives the indicator, when it was first and
  last seen, where it was seen, what it links to and its newest evidence
  records; a miss says "No evidence record for this indicator." (not a failure).
- Every list tool takes a `limit` with a default and a maximum and says when
  there is more (`export_iocs` gains `limit`; `get_detonation_report` and
  `get_artifact` take `ioc_limit`; `get_catalogue_family` takes
  `timeline_limit`). Every time leaves in UTC with a `Z`.
- Corrected the plan wording for `list_notable_sessions` and
  `get_session_transcript`. The indicator tool describes its answer as an
  evidence record.
- An id placed in a request path (sigil, actor, session, detonation, sha256)
  must be a plain id; anything else is refused with no request made.
- Hosted server (https://api.blackdome.ai/mcp, `blackdome-mcp-http`): each tool
  call uses the key on the HTTP request that carried it (never one remembered
  from the session); a keyless request on a session begun with a key is refused
  (401, carrying the request's JSON-RPC id); the daily-limit numbers are passed
  on as RateLimit-* headers and, when a tenth or less is left, as a note in the
  result; it calls the API on the same machine, so each caller without a key
  is counted as itself.
- If you run `blackdome-mcp-http` yourself, set
  `BLACKDOME_BASE_URL=https://api.blackdome.ai`: that entry point now defaults
  to `http://127.0.0.1:7860` (the stdio `blackdome-mcp` still defaults to
  `https://api.blackdome.ai`).

## 0.5.2 - 2026-11-17

- No tool was added, removed or renamed, and no request sent to the service
  changed. Tool descriptions follow what the service returns since 2026-11-16
  and 2026-11-17.
- `lookup_attacker_ip`: the service answers for the busiest attackers again (it
  used to time out on them). For such an address the answer carries
  `total_events_is_minimum: true` and `sampled_events`: the total is then a
  lower bound, and the protocol and sensor breakdown describe its newest events.
- Sessions: the service records honeypot sessions again since 2026-11-17, from
  the first command an attacker types or the first file dropped. There are none
  for 2026-10-12 to 2026-11-16. An actor id of a session recorded since then
  stands for one attacker address. This is what `get_actor` (sessions) and the
  session tools return; the tools themselves are unchanged.
- `lookup_attacker_ip`: the API now names the city of each sensor that saw the
  address (as on blackdome.ai/sensors), not the sensor's internal name.
- Detonation tools describe the new report shape. `get_detonation_report`
  returns `report` (a fixed set of fields: what the file did) instead of
  `metadata` and `report_body`; names of our sensors, server paths and
  addresses read `[sensor]`, `[sandbox-path]` and `[redacted]`.
  `list_detonations` returns `sandbox_kind` instead of `vm_type`; its
  `vm_type` argument is still sent, but the service ignores it. Only
  docstrings changed; no request changed.
- `credential_search`: credential records no longer carry `edge_id` (the
  sensor that captured them).
- `list_notable_sessions` and `get_session_transcript`: no `edge_id`; `ip` is
  the attacker's public address or null; transcript text has our sensor
  names, server paths and addresses replaced.
- Indicator tags and STIX labels no longer include `edge:<sensor>` or any
  other tag that names a sensor, job, run, capture or path.
- `list_payloads` now describes what the API returns since 2026-11-16: the shared
  honeypot corpus (it returned an empty list for every customer before), no
  outside reputation lookup, 404 for a hash that is not a honeypot capture, and
  detonation status and verdict on Threat Intel Pro only.
- Rate limits in the README: Threat Intel Analyst 5,000 requests a day, Threat
  Intel Pro 50,000.

## 0.5.1 - 2026-11-16

- No tool was added, removed or renamed, and no request sent to the service
  changed. Tool descriptions, error texts and the README now name the plans
  on sale (Threat Intel Analyst, Threat Intel Pro, Credential Intelligence,
  ThreatDrop API) and which plan each tool needs. The earlier "candidate
  Enterprise/OEM pilot" and "Pro or higher" wording is gone; Enterprise is
  "talk to us".
- `list_payloads` and `get_actor` need Threat Intel Analyst or Pro.
  The service checks the plan for both tools.
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
