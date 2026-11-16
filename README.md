<!-- mcp-name: io.github.blackdome-ai/blackdome-mcp -->

# BlackDome MCP Server

Canonical MCP server name: `io.github.blackdome-ai/blackdome-mcp`

Package version: `0.5.1`

Give your AI agents direct access to **read-only observed threat intelligence**. Look up attacker IPs, browse indicators of compromise (IOCs), inspect captured credentials and malware payloads, compare samples deterministically, inspect bounded evidence clusters, and retrieve authenticated ThreatDrop case and workflow status — all from Claude, Cursor, or any MCP-compatible client.

Community tools are **free and need no API key**. The tool table identifies the product features required for paid intelligence.

## Quick Start

### Option 1 — Separately hosted streamable-HTTP MCP (recommended, no install)

One hosted streamable-HTTP endpoint for compatible remote MCP clients (Claude Desktop, the claude.ai web app, mobile, Cursor):

```
https://api.blackdome.ai/mcp
```

Free tools work with no key. To unlock the paid tiers (credential intelligence, payloads, actors, warboard, STIX export), get an API key at **[https://blackdome.ai/pricing](https://blackdome.ai/pricing)** and add it as an `Authorization` header:

```json
{
  "mcpServers": {
    "blackdome-cloud": {
      "url": "https://api.blackdome.ai/mcp",
      "headers": {
        "Authorization": "Bearer bd_your_key_here"
      }
    }
  }
}
```

### Option 2 — Run locally

Use `uvx` (part of [uv](https://docs.astral.sh/uv/)) to fetch and run the server on demand:

```bash
uvx blackdome-mcp
```

For a fixed install, use `pip install blackdome-mcp`.

The free community tools use **no API key**. To unlock paid tiers, get a key at **[https://blackdome.ai/pricing](https://blackdome.ai/pricing)**.

#### Claude Desktop

Merge this into `claude_desktop_config.json` — `~/Library/Application Support/Claude/` on macOS, `%APPDATA%\Claude\` on Windows — then restart Claude:

```json
{
  "mcpServers": {
    "blackdome": {
      "command": "uvx",
      "args": ["blackdome-mcp"],
      "env": {
        "BLACKDOME_API_KEY": "bd_your_key_here"
      }
    }
  }
}
```

> The `env` block is optional — omit `BLACKDOME_API_KEY` to run free public tools only.

#### Claude Code

One command — the key is stored in the MCP config, so there are no shell exports to maintain (a plain `export BLACKDOME_API_KEY=...` only lasts for that terminal session, and your paid tools would stop working in the next one):

```bash
claude mcp add blackdome -e BLACKDOME_API_KEY=bd_your_key_here -- uvx blackdome-mcp
```

For free tools only:

```bash
claude mcp add blackdome -- uvx blackdome-mcp
```

#### Cursor

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per project):

```json
{
  "blackdome": {
    "command": "uvx",
    "args": ["blackdome-mcp"],
    "env": {
      "BLACKDOME_API_KEY": "bd_your_key_here"
    }
  }
}
```

## API Key Behavior

- **No key:** free community tools work; paid tools return an explicit `401`.
- **Invalid key:** paid tools (and `whoami`) fail loudly with `401 Invalid API key` — there is **no silent fallback** to free-tier results. Free tools keep working regardless of key validity, except `export_iocs`, which refuses a bad key with `401` instead of treating the call as keyless.
- **Expired key:** `403 API key has expired`.
- **Cancelled, lapsed or unpaid plan:** the account continues as BlackDome Free, so a paid tool returns an explicit `403` and the free tools keep working.
- **Suspended account:** `403 Tenant account is inactive`.
- **Valid key, wrong plan:** a tool your plan does not include returns an explicit `403`; check your plan and its features any time with `whoami`. A feature name alone does not settle it: `api_access` on a ThreatDrop API or Credential Intelligence key covers that product's own endpoints, while payloads, actors, the warboard and explanations also need a Threat Intel plan (Analyst or Pro).
- **Key without the `read` scope:** gated tools return `403`.
- **A key on a plan without the indicator feed** (ThreatDrop API only): `export_iocs` returns `403`. Call it without a key for the keyless export.

If a paid tool returns less than expected, run `whoami` first — it reports your plan, features, and live quota.

## Available Tools

Free tools work with no key. Paid tools require an API key whose plan includes the listed feature.

| Tool | Tier | Description |
|------|------|-------------|
| `lookup_attacker_ip` | **Free** | Full dossier for one attacker IP — events, protocols, credentials (passwords masked), MITRE, edge nodes |
| `top_attackers` | **Free** | Most active attacker IPs over a window — pick one to drill into |
| `attack_map` | **Free** | Recent geolocated attack events for a live map (limit ≥ 10) |
| `attack_heatmap` | **Free** | Country-aggregated attack heatmap with centroids (limit ≥ 5) |
| `credential_preview` | **Free** | Sample of recent credentials (masked server-side) + teaser totals |
| `verify_sigil` | **Free** | Verify a BlackDome Sigil / audit record by id |
| `recent_iocs` | **Free** | Browse recent redacted IOCs — type/severity filters (72h community delay, 25-row cap) |
| `ioc_trends` | **Free** | Aggregated IOC trends — totals, breakdowns, daily new, top MITRE |
| `export_iocs` | **Free** (json/csv) · **Pro** (stix) | Export the IOC feed; STIX bundle needs the `stix_export` feature |
| `search_credentials` | **Credential Intelligence** (`credential_intel` or `realtime_credential_feed`) | Search the global credential corpus with PLAINTEXT passwords |
| `credential_stats` | **Credential Intelligence** (`credential_intel` or `realtime_credential_feed`) | Aggregate credential stats — top usernames/passwords, breakdowns |
| `list_payloads` | **Analyst or Pro** (`api_access` on a Threat Intel plan) | List captured malware payloads, or fetch one by sha256 (VT/MB intel) |
| `get_actor` | **Analyst or Pro** (`api_access` on a Threat Intel plan) | List clustered threat actors, or fetch one actor's sessions |
| `warboard` | **Analyst or Pro** (`api_access` on a Threat Intel plan) | Sigil leaderboard with intrusion narratives + attacker command tails |
| `list_notable_sessions` | **Not on sale** (`session_intel`; no plan on sale includes it) | Ranked hand-keyed attacker sessions surfaced out of botnet noise |
| `get_session_transcript` | **Not on sale** (`session_intel`; no plan on sale includes it) | Structured command/output transcript for one attacker session |
| `list_detonations` | **Pro** (`detonation_intel`) | Malware detonation list with verdicts, Magika labels and IOC counts |
| `get_detonation_report` | **Pro** (`detonation_intel`) | Full detonation report with behavior, IOCs, artifact classification and report availability |
| `get_artifact` | **Pro** (`detonation_intel`) | Artifact dossier with linked detonation, IOCs and session identifiers only |
| `explain_ioc` | **Analyst or Pro** (`ioc_explanation`) | Observed evidence for an IP, domain, or URL |
| `compare_samples` | **Pro** (`sample_compare`) | Deterministic comparison of two SHA-256 samples |
| `get_evidence_cluster` | **Pro** (`genome_clusters`) | Bounded evidence cluster for a SHA-256, IP, domain, or URL |
| `get_reproducible_novelty` | **Pro** (`reproducible_novelty`) | Reproducible behavior assessment for a SHA-256, IP, domain, or URL |
| `get_threatdrop_case` | **ThreatDrop API** only (`api_access` on that plan) | Authenticated account's sanitized case state; separate ThreatDrop product entitlement |
| `get_takedown_status` | **ThreatDrop API** only (`api_access` on that plan) | Authenticated account's public case counts and takedown workflow status, including replies, outcome, and timeline |
| `list_catalogue_families` | **Pro** (`genome_clusters`) | Malware specimen families in the shared honeypot catalogue, newest first, paged |
| `get_catalogue_family` | **Pro** (`genome_clusters`) | One family: members, build history, public tools fetched, indicators, related families and why |
| `get_catalogue_specimen` | **Pro** (`genome_clusters`) | One specimen: kind, processor, size, traits, indicators, family and lineage (never the file itself) |
| `search_catalogue` | **Pro** (`genome_clusters`) | Search specimens by SHA-256 prefix or host/pool/wallet/control text, and families by key or name |
| `recent_catalogue_specimens` | **Pro** (`genome_clusters`) | The most recently seen specimens, optionally by kind (script, program, archive, other) |
| `whoami` | **Any key** | Check your tenant, plan, features and live quota |

**Feature gates:** tool availability is enforced by the returned plan features, including `api_access`, `stix_export`, `credential_intel` or `realtime_credential_feed`, `detonation_intel`, `session_intel`, `ioc_explanation`, `sample_compare`, `genome_clusters`, and `reproducible_novelty`. ThreatDrop tools require a separate ThreatDrop product entitlement. See [pricing](https://blackdome.ai/pricing).

## Example Prompts

Once connected, try asking your AI assistant:

- *"Who are the top attackers hitting the honeypots this month?"*
- *"Look up attacker IP 176.65.139.56 and summarize what they tried."*
- *"Show me the latest malicious sha256 IOCs from the last week."*
- *"What are the IOC trends — which MITRE techniques are spiking?"*
- *"Render a heatmap of where attacks are coming from."*
- *"Export the IOC feed as CSV so I can load it into my SIEM."*
- *"What plan am I on and which features do I have?"* (runs `whoami`)
- *"Search captured SSH credentials for the username root."* (paid)
- *"Pull the detonation report for sha256 a6713518f2e26745683d33ded61b465d0645d7af850464c559fba8bb84e68398."* (Pro)
- *"Explain the observed evidence for domain example.test."* (Analyst or Pro)
- *"Compare these two SHA-256 samples deterministically."* (Pro)
- *"Show the bounded evidence cluster for this IOC."* (Pro)
- *"What reproducible novelty does this URL show?"* (Pro)
- *"Show the ThreatDrop case state and takedown workflow status for submission 42."* (ThreatDrop)

## Environment Variables

The package runs locally over stdio; the separately hosted streamable-HTTP endpoint takes the key as an `Authorization: Bearer` header instead. The registry manifest declares only the package's stdio transport.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BLACKDOME_API_KEY` | No | — | Bearer API key. Free tools work without it; paid tools require it |
| `BLACKDOME_BASE_URL` | No | `https://api.blackdome.ai` | API base URL |
| `BLACKDOME_TIMEOUT` | No | `15` | Request timeout in seconds |

## Rate Limits

Without an API key, the indicator export (`export_iocs`) is capped at about **30 requests a minute** and **100 a day**. With a key the limits are your plan's: BlackDome Free 60 a minute and 100 a day; Threat Intel Analyst 60 a minute and 200 a day; Threat Intel Pro, Credential Intelligence and ThreatDrop API 300 a minute and 5,000 a day. `whoami` returns the limits of your key. Indicators are **72 hours behind live** without a key and on BlackDome Free; Threat Intel Analyst, Threat Intel Pro and Credential Intelligence get the feed without that delay through `export_iocs`. `recent_iocs` and `ioc_trends` are the public preview and are always 72 hours behind. Enterprise: talk to us (sales@blackdome.ai). When you hit a limit the server returns a `429` error that names the limit of your plan.

## Troubleshooting

- **"command not found" in a GUI client:** GUI apps don't load your shell PATH. Use `"command": "uvx", "args": ["blackdome-mcp"]` as shown above. For a pip installation, run `which blackdome-mcp` (macOS/Linux) or `where blackdome-mcp` (Windows) and use the full path as the `command`.
- **Paid tools return 401/403:** see [API Key Behavior](#api-key-behavior) — errors are explicit, and `whoami` tells you exactly what your key grants.

## Security

- **Read-only.** Tools use GET or semantically read-only JSON-body POST requests; none mutates BlackDome data.
- **Keyless free tier.** Public tools require no API key and expose only community-tier data.
- **Masked credentials.** The free `lookup_attacker_ip` tool masks captured passwords to `********` before returning them; `credential_preview` is masked server-side. Plaintext passwords are returned **only** by the paid `search_credentials` tool, which requires `credential_intel` or `realtime_credential_feed`.
- **Secrets stay local.** Your API key is read from the environment and sent only to the BlackDome API over HTTPS. No data is stored by the MCP server — it proxies directly to BlackDome.
- **Customer intelligence.** Retrieve observed evidence, deterministic comparisons, reproducible behavior assessments, case state and takedown-workflow status.

## License

MIT
