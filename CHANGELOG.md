# Changelog

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
