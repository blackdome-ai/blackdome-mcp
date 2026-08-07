"""BlackDome MCP Server.

Gives AI agents direct access to live honeypot threat intelligence — attacker
IPs, captured credentials, indicators of compromise (IOCs), malware payloads,
threat actors, and a global attack map sourced from the BlackDome edge fleet.

Most tools are FREE and work with NO API key (the public community tier).
A subset of high-value intelligence (credential search, payloads, actors,
warboard, STIX export) requires an API key tied to a paid plan. Get a key at
https://blackdome.ai/pricing.

Authenticates against the BlackDome API with a Bearer token when one is set.
"""

import json
import os
import sys
from contextvars import ContextVar
from typing import Any, Optional
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# API key is OPTIONAL — the free public tools work with NO key at all.
# A key only unlocks the paid tiers (credential intel, payloads, actors, etc.).
API_KEY = os.environ.get("BLACKDOME_API_KEY", "")
BASE_URL = os.environ.get(
    "BLACKDOME_BASE_URL", "https://api.blackdome.ai"
).rstrip("/")
TIMEOUT = int(os.environ.get("BLACKDOME_TIMEOUT", "15"))

# Hosted (streamable-HTTP) deployments serve many customers from one process:
# each request's Authorization/X-API-Key header is captured into this var by
# the ASGI middleware in blackdome_mcp.http_server and takes precedence over
# the process-wide BLACKDOME_API_KEY env var. Stdio mode never sets it.
_REQUEST_API_KEY: ContextVar[str] = ContextVar("blackdome_mcp_request_api_key", default="")


def set_request_api_key(key: str) -> Any:
    """Set the per-request API key (hosted mode). Returns a reset token."""
    return _REQUEST_API_KEY.set(key or "")


def current_api_key() -> str:
    """Per-request key (hosted mode) falling back to the env-var key (stdio)."""
    return _REQUEST_API_KEY.get() or API_KEY

mcp = FastMCP(
    "BlackDome",
    instructions=(
        "BlackDome provides live threat intelligence harvested from a global "
        "fleet of honeypots and edge sensors. Use these tools to look up "
        "attacker IPs, browse indicators of compromise (IOCs), inspect captured "
        "credentials and malware payloads, profile threat actors, and render a "
        "real-time global attack map. Free public tools require no API key; "
        "credential, payload, actor, warboard and STIX-export tools require a "
        "paid plan key. Captured passwords from the free attacker lookup are "
        "masked; the paid credential tools return the full intelligence."
    ),
)

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _headers() -> dict[str, str]:
    """Build request headers.

    Always advertises JSON. Adds a Bearer Authorization header ONLY when an API
    key is configured — the public/community tools must work key-less, so we
    never send an empty/blank Authorization header. In hosted mode the key is
    per-request (contextvar); in stdio mode it is the env var.
    """
    headers = {"Accept": "application/json"}
    key = current_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Make a GET request to the BlackDome API and return the JSON payload.

    BlackDome returns FLAT response objects (no top-level "data" envelope), so we
    return the body as-is — a legitimate top-level "data" field (e.g. on some
    feeds) must not be silently unwrapped.
    """
    url = f"{BASE_URL}{path}"
    # Strip None values from params
    if params:
        params = {k: v for k, v in params.items() if v is not None}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url, headers=_headers(), params=params)
        resp.raise_for_status()
        return resp.json()


def _format_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except Exception:
            detail = exc.response.text
        if status == 401:
            return (
                "Authentication failed (401): bad or missing API key. "
                "This tool requires a valid BLACKDOME_API_KEY. "
                "Get one at https://blackdome.ai/pricing. "
                f"Server said: {detail}"
            )
        if status == 403:
            return (
                "Access denied (403): your plan does not include the feature "
                "this tool needs. credential search/stats require the Credential "
                "Intelligence or Threat Intel Enterprise plan; session intel "
                "requires Enterprise/OEM; detonation intel and STIX export "
                "require Pro or higher. Upgrade at https://blackdome.ai/pricing. "
                f"Server said: {detail}"
            )
        if status == 429:
            retry = exc.response.headers.get("Retry-After", "?")
            return (
                f"Rate limited (429). The free community tier is capped at ~30 "
                f"requests/min and 100 requests/day. Retry after {retry} seconds, "
                "or upgrade your plan for a higher limit."
            )
        return f"API error {status}: {detail}"
    return f"Request failed: {exc}"


# Password-like keys redacted from keyless tool output (defense-in-depth: catches
# credentials_attempted[].password today and any future password field, wherever
# it sits in the response). password_hash is intentionally NOT masked (it's a hash).
_PASSWORD_KEYS = {"password", "password_plain", "passwd", "plaintext", "secret"}


def _mask_credentials(payload: Any) -> Any:
    """Recursively mask plaintext passwords in a public (keyless) payload.

    The keyless /api/blackdome/lookup/{ip} endpoint returns PLAINTEXT passwords
    in credentials_attempted[]. The free public tool MUST NOT leak the raw
    credential dataset, so we walk the whole structure and overwrite every
    password-like value with a fixed mask while preserving usernames/hashes/
    metadata. The PAID search_credentials tool intentionally keeps plaintext and
    does NOT call this.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in _PASSWORD_KEYS and isinstance(value, str):
                payload[key] = "********"
            else:
                _mask_credentials(value)
    elif isinstance(payload, list):
        for item in payload:
            _mask_credentials(item)
    return payload


# ---------------------------------------------------------------------------
# Public tools (no API key required)
# ---------------------------------------------------------------------------


@mcp.tool()
async def lookup_attacker_ip(ip: str) -> str:
    """Look up a single attacker IP — events, protocols, credentials, MITRE (free, passwords masked).

    Returns the full honeypot dossier for an IP present in the event store:
    session/event counts, first/last seen, protocols, a daily timeline,
    credentials attempted (passwords MASKED to '********'), MITRE ATT&CK
    techniques, the edge nodes that saw it, and recent events. A 404 means the
    IP has no recorded events.

    Args:
        ip: The attacker IP address to look up (e.g. "176.65.139.56")
    """
    try:
        payload = await _get(f"/api/blackdome/lookup/{quote(ip, safe='')}")
        # SECURITY: mask plaintext passwords before returning — the keyless
        # lookup endpoint leaks raw credentials, the MCP tool must not.
        payload = _mask_credentials(payload)
        return json.dumps(payload, indent=2, default=str)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return json.dumps(
                {"found": False, "ip": ip, "detail": "No recorded events for this IP"},
                indent=2,
            )
        return _format_error(exc)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def top_attackers(days: int = 30, limit: int = 5) -> str:
    """List the most active attacker IPs over a window — pick a busy IP to drill into (free).

    Returns ranked attackers with event counts, protocols, and first/last seen,
    plus a summary of total events / unique attackers. Feed a returned IP into
    lookup_attacker_ip for the full dossier.

    Args:
        days: Lookback period in days (default 30)
        limit: Max attackers to return (default 5)
    """
    try:
        payload = await _get("/api/blackdome/top-attackers", {
            "days": min(days, 30),   # API caps at 30
            "limit": min(limit, 100),  # API caps at 100
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def attack_map(limit: int = 10) -> str:
    """Get recent geolocated attack events for a live global attack map (free).

    Returns individual attack events with source IP, protocol, country/city and
    latitude/longitude, plus a 24h summary. Unlike the aggregate tools, this
    endpoint DOES populate geo. NOTE: limit minimum is 10 (lower values return
    422), so the default is 10.

    Args:
        limit: Max events to return (minimum 10, default 10)
    """
    try:
        payload = await _get("/api/blackdome/map/events", {
            "limit": max(limit, 10),
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def attack_heatmap(limit: int = 5) -> str:
    """Get a country-aggregated attack heatmap with lat/lon centroids (free).

    Returns per-country attack and unique-IP counts with centroid coordinates,
    plus a 7-day summary. NOTE: limit minimum is 5 (lower values return 422).

    Args:
        limit: Max countries to return (minimum 5, default 5)
    """
    try:
        payload = await _get("/api/blackdome/map/heatmap", {
            "limit": max(limit, 5),
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def credential_preview(limit: int = 5, hours: int = 24) -> str:
    """Preview recently captured credentials with aggregate teaser counts (free, masked server-side).

    Returns a small sample of recently captured credentials (passwords already
    masked to '****' server-side) plus aggregate totals (recent_total,
    total_captured, protocol_count). Use search_credentials (paid) for the full
    plaintext corpus.

    Args:
        limit: Max sample credentials to return (default 5)
        hours: Lookback window in hours (default 24)
    """
    try:
        # NOTE: passwords are ALREADY masked server-side on this endpoint ('****'),
        # so we do NOT re-mask here.
        payload = await _get("/api/blackdome/credentials/preview", {
            "limit": min(limit, 25),  # API caps at 25
            "hours": min(hours, 24),  # API caps at 24
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def verify_sigil(sigil_id: str) -> str:
    """Verify a BlackDome Sigil / audit record by its id (free).

    Returns the sigil/audit verification record when the id exists. An unknown
    or invalid id returns a clean "Sigil not found" — the tool reports that as
    not-found rather than an error.

    Args:
        sigil_id: The sigil id to verify (e.g. "SIGIL-EEEB0646")
    """
    try:
        payload = await _get(f"/api/blackdome/audit/{quote(sigil_id, safe='')}")
        return json.dumps(payload, indent=2, default=str)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return json.dumps(
                {"found": False, "sigil_id": sigil_id, "detail": "Sigil not found / invalid"},
                indent=2,
            )
        return _format_error(exc)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def recent_iocs(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20,
) -> str:
    """Browse recent indicators of compromise (IOCs) from the honeypot fleet (free).

    Returns redacted IOCs (sha256/ipv4/domain/url/...) with confidence, severity,
    verdict, MITRE tactics/techniques, tags, and sighting counts from the public
    community preview. Values are redacted and the feed carries a 72h freshness
    delay; up to 25 rows per request. Filters: ioc_type and severity only —
    value search, verdict/confidence/MITRE filtering, and pagination require a
    paid plan key (https://blackdome.ai/pricing).

    Args:
        ioc_type: Filter by IOC type (e.g. "sha256", "ipv4", "domain", "url")
        severity: Filter by severity (e.g. "high", "medium", "low")
        limit: Max IOCs to return (default 20, capped at 25)
    """
    try:
        # Public redacted preview. /api/blackdome/iocs is the KEYED customer
        # feed; /api/blackdome/threat-intel/iocs is its external twin.
        payload = await _get("/api/blackdome/iocs/public", {
            "ioc_type": ioc_type,
            "severity": severity,
            "limit": limit,
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def ioc_trends(days: int = 7) -> str:
    """Get aggregated IOC trends — totals, by-type/severity, daily new, top MITRE (free).

    Returns trend aggregates over the window: total IOCs, high-severity and
    malicious counts, breakdowns by type and severity, daily new-IOC counts and
    the top MITRE techniques. Bounded by the same 72h community freshness delay
    as recent_iocs.

    Args:
        days: Lookback period in days (default 7, max 90 on this endpoint)
    """
    try:
        # Public aggregate trends (no indicator values), 72h community delay.
        # /api/v1/blackdome/threat-intel/trends is the keyed customer twin.
        payload = await _get("/api/blackdome/iocs/public/trends", {
            "days": days,
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


# ---------------------------------------------------------------------------
# Community-free / tiered export
# ---------------------------------------------------------------------------


@mcp.tool()
async def export_iocs(
    fmt: str = "json",
    ioc_type: Optional[str] = None,
    min_confidence: int = 50,
    min_severity: str = "medium",
    days: int = 30,
) -> str:
    """Export the IOC threat-intel feed as json, csv (free) or stix (Pro+).

    Branches on format: json returns a flat {feed, generated_at, count, iocs[]}
    object; csv returns the raw CSV text body; stix returns a STIX 2.1 bundle
    (requires the stix_export feature — Pro plan or higher). json and csv work
    on the free community tier. The feed is tenant-scoped when authenticated.

    Args:
        fmt: Output format — "json", "csv", or "stix" (default "json")
        ioc_type: Filter by IOC type (e.g. "sha256", "ipv4")
        min_confidence: Minimum confidence 0-100 (default 50; pass 0 for full set)
        min_severity: Minimum severity (default "medium")
        days: Lookback period in days, 1-365 (default 30)
    """
    fmt = (fmt or "json").lower()
    if fmt not in ("json", "csv", "stix"):
        return "Invalid fmt: choose one of 'json', 'csv', 'stix'."
    url = f"{BASE_URL}/api/v1/blackdome/threat-intel/feed/{fmt}"
    params = {
        "ioc_type": ioc_type,
        "min_confidence": min_confidence,
        "min_severity": min_severity,
        "days": days,
    }
    params = {k: v for k, v in params.items() if v is not None}
    # CSV is a text/csv body; json and stix are application/json. Set Accept
    # accordingly and read resp.text vs resp.json() per branch.
    headers = _headers()
    headers["Accept"] = "text/csv" if fmt == "csv" else "application/json"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            if fmt == "csv":
                # csv branch -> raw text body, returned verbatim.
                return resp.text
            # json and stix branches -> structured JSON (flat feed object or
            # a STIX 2.1 bundle).
            return json.dumps(resp.json(), indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


# ---------------------------------------------------------------------------
# Keyed tools (require an API key + plan feature)
# ---------------------------------------------------------------------------


@mcp.tool()
async def search_credentials(
    q: Optional[str] = None,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    protocol: Optional[str] = None,
    since: Optional[str] = None,
    cross_protocol: Optional[bool] = None,
    limit: int = 20,
    offset: int = 0,
) -> str:
    """Search the global captured-credential corpus with PLAINTEXT passwords (paid: credential_intel).

    Returns credential records (username, password_hash, password_plain,
    protocol, source_ip, edge, session, first/last seen, attempt counts) from
    the shared global dataset. Requires the credential_intel feature
    (Enterprise/OEM or the standalone Credential Intelligence plan). Plaintext
    is intentionally returned here — it is NOT masked.

    Args:
        q: Free-text query across credentials
        username: Filter by username
        ip: Filter by source IP
        protocol: Filter by protocol (e.g. "ssh", "http", "smtp")
        since: ISO timestamp lower bound
        cross_protocol: Only credentials seen across multiple protocols
        limit: Max records (default 20)
        offset: Pagination offset (default 0)
    """
    try:
        # PAID tier — plaintext passwords are intentionally returned and NOT
        # masked here (unlike the public lookup/preview tools).
        payload = await _get("/api/v1/blackdome/credentials/search", {
            "q": q,
            "username": username,
            "ip": ip,
            "protocol": protocol,
            "since": since,
            "cross_protocol": cross_protocol,
            "limit": limit,
            "offset": offset,
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def credential_stats(
    since: Optional[str] = None,
    protocol: Optional[str] = None,
) -> str:
    """Get aggregate credential statistics — top usernames/passwords, protocol breakdown (paid: credential_intel).

    Returns totals (unique credentials/ips/usernames), cross-protocol counts and
    top usernames/passwords from the shared global dataset. Requires the
    credential_intel feature (Enterprise/OEM or the Credential Intelligence plan).

    Args:
        since: ISO timestamp lower bound
        protocol: Scope stats to a single protocol (e.g. "ssh")
    """
    try:
        payload = await _get("/api/v1/blackdome/credentials/stats", {
            "since": since,
            "protocol": protocol,
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def list_payloads(sha256: Optional[str] = None, limit: int = 20) -> str:
    """List captured malware payloads, or fetch one payload's full record by sha256 (paid: api_access).

    With no sha256 this lists payload artifacts with summary stats. With a
    sha256 it returns that artifact's full envelope (artifact + detonation +
    VirusTotal/MalwareBazaar intel + actor); a live VT/MB lookup runs so an
    unknown hash still returns a structured record. Reference hashes are
    discoverable free via recent_iocs ioc_value.

    Args:
        sha256: Optional payload sha256 — when given, returns that payload's detail
        limit: Max payloads in list mode (default 20)
    """
    try:
        if sha256:
            # detail mode -> /payloads/{sha256} (different envelope from list).
            payload = await _get(f"/api/v1/blackdome/payloads/{quote(sha256, safe='')}")
        else:
            payload = await _get("/api/v1/blackdome/payloads", {"limit": limit})
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def get_actor(
    actor_id: Optional[str] = None,
    limit: int = 20,
    risk: Optional[str] = None,
    sort: Optional[str] = None,
    descending: Optional[bool] = None,
) -> str:
    """List threat actors with risk/geo enrichment, or fetch one actor's sessions (paid: api_access).

    With no actor_id this lists clustered actors (risk level/score, geo,
    techniques, sophistication, event counts). With an actor_id it returns that
    actor's session list. Actor clustering is only surfaced on this keyed
    endpoint (the free lookup returns actor_id=null).

    Args:
        actor_id: Optional actor id — when given, returns that actor's sessions
        limit: Max actors/sessions to return (default 20)
        risk: Filter by risk level (e.g. "medium")
        sort: Sort field (e.g. "risk")
        descending: Sort descending
    """
    try:
        if actor_id:
            # sessions sub-resource -> /actors/{actor_id}/sessions
            payload = await _get(f"/api/v1/blackdome/actors/{quote(actor_id, safe='')}/sessions", {
                "limit": limit,
            })
        else:
            payload = await _get("/api/v1/blackdome/actors", {
                "limit": limit,
                "risk": risk,
                "sort": sort,
                "descending": descending,
            })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def warboard(
    limit: int = 5,
    threat: Optional[str] = None,
    public: Optional[bool] = None,
) -> str:
    """Get the warboard leaderboard of earned Sigils with intrusion narratives (paid: api_access).

    Returns sigils with threat level, sophistication, persona stage, geo, MITRE
    chain glyphs, proof packs and a tail of the attacker's real shell commands.
    The 'public' flag is a content filter, not an auth bypass — the endpoint
    still requires a valid key.

    Args:
        limit: Max sigils to return (default 5)
        threat: Filter by threat level (e.g. "low", "high")
        public: Restrict to publicly shareable sigils
    """
    try:
        payload = await _get("/api/v1/blackdome/warboard", {
            "limit": limit,
            "threat": threat,
            "public": public,
        })
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def list_notable_sessions(
    min_commands: int = 3,
    since: Optional[str] = None,
    service: Optional[str] = None,
    technique: Optional[str] = None,
    human_likely: Optional[bool] = None,
    actor_id: Optional[str] = None,
    limit: int = 100,
) -> str:
    """List rare hand-keyed attacker sessions ranked by score (paid: Enterprise session_intel).

    Returns a flat object with count and sessions[]. Each session includes
    session_id, actor_id, ip, geo, command_count, distinct_techniques,
    primary_tactic, persona_stage, persona_score, score, first_ts, last_ts,
    novelty, dropped_artifact_count, edge_id and human_likely. Use this to
    surface the most interesting hands-on-keyboard intrusions out of botnet
    probe noise. Requires the session_intel feature (Enterprise/OEM).

    Args:
        min_commands: Minimum command count (default 3)
        since: ISO timestamp lower bound
        service: Filter by service (e.g. "ssh")
        technique: Filter by MITRE technique id (e.g. "T1059")
        human_likely: Only return sessions matching the human-likely heuristic
        actor_id: Filter by actor id
        limit: Max sessions to return (default 100, capped at 100)
    """
    try:
        payload = await _get(
            "/api/v1/blackdome/intel/sessions",
            {
                "min_commands": min_commands,
                "since": since,
                "service": service,
                "technique": technique,
                "human_likely": human_likely,
                "actor_id": actor_id,
                "limit": min(limit, 100),
            },
        )
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def get_session_transcript(
    session_id: str,
    limit: int = 500,
    offset: int = 0,
) -> str:
    """Get a structured attacker session transcript (paid: Enterprise session_intel).

    Returns {session, steps, total_steps, truncated}. The session object includes
    session_id, actor_id, ip, geo, edge_id, primary_tactic, start_ts, end_ts,
    persona_stage, persona_score and dropped_artifacts. Each step includes seq,
    ts, command, output_preview, exit_code, cwd, latency_ms, techniques and
    guard_triggered. Requires the session_intel feature (Enterprise/OEM).

    Args:
        session_id: Session id returned by list_notable_sessions
        limit: Max transcript steps to return (default 500, capped at 1000)
        offset: Pagination offset
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/sessions/{quote(session_id, safe='')}/transcript",
            {
                "limit": min(limit, 1000),
                "offset": offset,
            },
        )
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def list_detonations(
    verdict: Optional[str] = None,
    vm_type: Optional[str] = None,
    sha256: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
) -> str:
    """List malware detonation reports with IOC counts and file classification (paid: Pro detonation_intel).

    Returns a flat object with count and detonations[]. Each detonation includes
    detonation_id, sha256, verdict, finished_at, vm_type, magika_label and
    ioc_count. Requires the detonation_intel feature (Pro/Enterprise/OEM).

    Args:
        verdict: Filter by verdict (e.g. "malware", "benign", "suspicious")
        vm_type: Filter by sandbox VM type
        sha256: Filter by artifact sha256
        since: ISO timestamp lower bound
        limit: Max detonations to return (default 100, capped at 100)
    """
    try:
        payload = await _get(
            "/api/v1/blackdome/intel/detonations",
            {
                "verdict": verdict,
                "vm_type": vm_type,
                "sha256": sha256,
                "since": since,
                "limit": min(limit, 100),
            },
        )
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def get_detonation_report(detonation_id: str) -> str:
    """Get a full malware detonation report (paid: Pro detonation_intel).

    Returns detonation_id, sha256, verdict, started_at, finished_at, metadata,
    report_available, report_unavailable_reason, report_body, iocs[] and
    artifact classification fields. report_available=false is returned when a
    report file is missing, absent or too large. Requires the detonation_intel
    feature (Pro/Enterprise/OEM).

    Args:
        detonation_id: Detonation id returned by list_detonations
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/detonations/{quote(detonation_id, safe='')}"
        )
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def get_artifact(sha256: str) -> str:
    """Get an artifact dossier with linked detonation, IOCs and session reference (paid: Pro detonation_intel).

    Returns artifact classification fields, linked detonation summary, iocs[],
    and dropped_by_session identifiers/counts only. It does not request or
    return transcript command text or output_preview fields. Requires the
    detonation_intel feature (Pro/Enterprise/OEM).

    Args:
        sha256: Artifact sha256 to inspect
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/artifacts/{quote(sha256, safe='')}"
        )
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


@mcp.tool()
async def whoami() -> str:
    """Check your BlackDome tenant identity, plan, features and live quota (any valid key).

    Returns your tenant/slug, plan and status, the features[] your plan grants
    (the authoritative gate list — e.g. presence of 'credential_intel' or
    'stix_export'), and live quota (rate_limit, api_requests_day, requests_today).
    Requires ANY valid key but no specific feature; ideal for self-checking your
    tier before calling a gated tool.
    """
    try:
        payload = await _get("/api/v1/blackdome/me")
        return json.dumps(payload, indent=2, default=str)
    except Exception as exc:
        return _format_error(exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Run the BlackDome MCP server (stdio transport)."""
    if not API_KEY:
        # A key is OPTIONAL — the free public tools still work. Warn (on stderr,
        # never stdout — stdout is the MCP transport) that paid tools will fail.
        print(
            "WARNING: BLACKDOME_API_KEY is not set. Free public tools "
            "(lookup_attacker_ip, top_attackers, attack_map, attack_heatmap, "
            "credential_preview, verify_sigil, recent_iocs, ioc_trends, and "
            "json/csv export_iocs) will work, but paid tools "
            "(search_credentials, credential_stats, list_payloads, get_actor, "
            "warboard, list_notable_sessions, get_session_transcript, "
            "list_detonations, get_detonation_report, get_artifact, whoami, "
            "and stix export) will return 401. "
            "Get a key at https://blackdome.ai/pricing.",
            file=sys.stderr,
        )
    mcp.run()


if __name__ == "__main__":
    main()
