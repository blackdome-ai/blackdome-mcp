# Changelog

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
