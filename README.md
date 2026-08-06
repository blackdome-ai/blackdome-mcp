<!-- mcp-name: io.github.blackdome-ai/blackdome-mcp -->

# BlackDome MCP Server

Give your AI agents direct access to **live honeypot threat intelligence**. Look up attacker IPs, browse indicators of compromise (IOCs), inspect captured credentials and malware payloads, profile threat actors, and render a real-time global attack map — all from Claude, Cursor, or any MCP-compatible client.

Most tools are **free and need no API key** (the public community tier). A subset of high-value intelligence requires a paid plan.

## Quick Start

### Install

```bash
pip install blackdome-mcp
```

### Configure

The free public tools work with **no API key**. To unlock the paid tiers (credential intelligence, payloads, actors, warboard, STIX export), get an API key at **[https://blackdome.ai/pricing](https://blackdome.ai/pricing)**.

#### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blackdome": {
      "command": "blackdome-mcp",
      "env": {
        "BLACKDOME_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

> The `env` block is optional — omit `BLACKDOME_API_KEY` to run free public tools only.

#### Claude Code

```bash
claude mcp add blackdome -- blackdome-mcp
# Optional — only needed for paid tools:
export BLACKDOME_API_KEY="your-api-key-here"
```

#### Cursor

Add to your MCP settings:

```json
{
  "blackdome": {
    "command": "blackdome-mcp",
    "env": {
      "BLACKDOME_API_KEY": "your-api-key-here"
    }
  }
}
```

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
| `search_credentials` | **Enterprise** (`credential_intel`) | Search the global credential corpus with PLAINTEXT passwords |
| `credential_stats` | **Enterprise** (`credential_intel`) | Aggregate credential stats — top usernames/passwords, breakdowns |
| `list_payloads` | **Pro** (`api_access`) | List captured malware payloads, or fetch one by sha256 (VT/MB intel) |
| `get_actor` | **Pro** (`api_access`) | List clustered threat actors, or fetch one actor's sessions |
| `warboard` | **Pro** (`api_access`) | Sigil leaderboard with intrusion narratives + attacker command tails |
| `list_notable_sessions` | **Enterprise** (`session_intel`) | Ranked hand-keyed attacker sessions surfaced out of botnet noise |
| `get_session_transcript` | **Enterprise** (`session_intel`) | Structured command/output transcript for one attacker session |
| `list_detonations` | **Pro** (`detonation_intel`) | Malware detonation list with verdicts, Magika labels and IOC counts |
| `get_detonation_report` | **Pro** (`detonation_intel`) | Full detonation report with behavior, IOCs, artifact classification and report availability |
| `get_artifact` | **Pro** (`detonation_intel`) | Artifact dossier with linked detonation, IOCs and session identifiers only |
| `whoami` | **Any key** | Check your tenant, plan, features and live quota |

**Plans:** Community (free) → Pro ($299, adds `stix_export`, `api_access`, `detonation_intel`) → Enterprise ($2000, adds `credential_intel`, `bulk_api`, `session_intel`) → OEM ($5000). See [pricing](https://blackdome.ai/pricing).

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
- *"Show me the most active hand-keyed attacker sessions this week."* (Enterprise)
- *"Pull the detonation report for sha256 a6713518f2e26745683d33ded61b465d0645d7af850464c559fba8bb84e68398."* (Pro)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BLACKDOME_API_KEY` | No | — | Bearer API key. Free tools work without it; paid tools require it |
| `BLACKDOME_BASE_URL` | No | `https://api.blackdome.ai` | API base URL |
| `BLACKDOME_TIMEOUT` | No | `15` | Request timeout in seconds |

## Rate Limits

The free community tier is capped at roughly **30 requests/minute** and **100 requests/day**, and community IOC data carries a **72-hour freshness delay**. Paid plans raise these limits substantially (Enterprise: 1000 req/min, 50,000 req/day). When you hit a limit the server returns a clear `429` error with retry timing. Use `whoami` to see your live quota.

## Security

- **Read-only.** Every tool is a GET request — the server never mutates BlackDome data.
- **Keyless free tier.** Public tools require no API key and expose only community-tier data.
- **Masked credentials.** The free `lookup_attacker_ip` tool masks captured passwords to `********` before returning them; `credential_preview` is masked server-side. Plaintext passwords are returned **only** by the paid `search_credentials` tool, which requires the `credential_intel` feature.
- **Secrets stay local.** Your API key is read from the environment and sent only to the BlackDome API over HTTPS. No data is stored by the MCP server — it proxies directly to BlackDome.

## License

MIT
