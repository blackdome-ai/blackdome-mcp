"""BlackDome MCP Server.

Gives AI agents direct access to live honeypot threat intelligence — attacker
IPs, captured credentials, indicators of compromise (IOCs), malware payloads,
threat actors, and a global attack map sourced from the BlackDome edge fleet.

Community tools are FREE and work with NO API key.
Additional intelligence (credential search, payloads, actors,
evidence records, STIX export) requires an API key tied to a paid plan. Get a key at
https://blackdome.ai/pricing.

Authenticates against the BlackDome API with a Bearer token when one is set.
"""

import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from collections import OrderedDict
from contextvars import ContextVar
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import httpx
from mcp.server.fastmcp import FastMCP

from blackdome_mcp import __version__, plans

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# API key is OPTIONAL — the free public tools work with NO key at all.
# A key only unlocks the paid tiers (credential intel, payloads, actors, etc.).
API_KEY = os.environ.get("BLACKDOME_API_KEY", "")
BASE_URL = os.environ.get(
    "BLACKDOME_BASE_URL", "https://api.blackdome.ai"
).rstrip("/")
# Seconds to wait for one BlackDome API answer. 45 (2026-11-21, full test 04 finding 2): the slowest API calls took
# 12-31 s cold (attack_map, list_notable_sessions, credential_stats) and failed at the old 15. 45 stays under the
# 60 s nginx gives a call through the public API host (proxy_read_timeout default on api.blackdome.ai
# /api/v1/blackdome/), which a stdio install goes through. The hosted server calls the API on loopback (no proxy
# between them, see http_server.HOSTED_BASE_URL); what bounds it there is the hosted /mcp location's 600 s
# proxy_read_timeout in front of this server, far above 45.
TIMEOUT = int(os.environ.get("BLACKDOME_TIMEOUT", "45"))

# Hosted (streamable-HTTP) deployments serve many customers from one process:
# each request's Authorization/X-API-Key header is captured into this var by
# the ASGI middleware in blackdome_mcp.http_server and takes precedence over
# the process-wide BLACKDOME_API_KEY env var. Stdio mode never sets it.
_REQUEST_API_KEY: ContextVar[str] = ContextVar("blackdome_mcp_request_api_key", default="")


def set_request_api_key(key: str) -> Any:
    """Set the per-request API key (hosted mode). Returns a reset token."""
    return _REQUEST_API_KEY.set(key or "")


def key_from_headers(pairs: Any) -> str:
    """The API key a request carries: ``Authorization: Bearer <key>`` (or a bare value), else ``X-API-Key``.

    ``pairs`` is a list of (name, value) as ASGI gives them (bytes) or as strings."""
    authorization = ""
    x_api_key = ""
    for raw_name, raw_value in pairs or []:
        name = raw_name.decode("latin-1") if isinstance(raw_name, bytes) else str(raw_name)
        value = raw_value.decode("latin-1") if isinstance(raw_value, bytes) else str(raw_value)
        name, value = name.lower(), value.strip()
        if name == "authorization":
            authorization = value
        elif name == "x-api-key":
            x_api_key = value
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if authorization:
        return authorization
    return x_api_key


def _key_of_this_http_request() -> Optional[str]:
    """Hosted mode: the key on the HTTP request that carried THIS tool call ("" when it carried none).

    None outside an HTTP request (stdio). The SDK's request context names the very request: in a stateful
    session the tool runs in the session's own task, which keeps the context of the request that opened the
    session (initialize), so a contextvar set per request is not seen there (sweep 2026-11-21: a call made
    with key B was sent upstream with the initialize request's key A)."""
    try:
        from mcp.server.lowlevel.server import request_ctx

        request = getattr(request_ctx.get(), "request", None)
    except Exception:
        return None
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict) or scope.get("type") != "http":
        return None
    return key_from_headers(scope.get("headers"))


def current_api_key() -> str:
    """Hosted mode: the key of the request that carried this call, and nothing else (no remembered key and
    no process key). Stdio: the per-request contextvar, else the env-var key."""
    per_request = _key_of_this_http_request()
    if per_request is not None:
        return per_request
    return _REQUEST_API_KEY.get() or API_KEY

mcp = FastMCP(
    "BlackDome",
    instructions=(
        "BlackDome provides live threat intelligence harvested from a global "
        "fleet of honeypots and edge sensors. Use these tools to look up "
        "attacker IPs, browse indicators of compromise (IOCs), inspect captured "
        "credentials and malware payloads, profile threat actors, and render a "
        "real-time global attack map. Free public tools require no API key; "
        "credential, payload, actor, evidence-record and STIX-export tools require a "
        "paid plan key. The specimen catalogue tools need Threat Intel Pro "
        "(feature genome_clusters) and never return sample files. "
        "Captured passwords from the free attacker lookup are masked; the paid "
        "credential tools return the full intelligence."
    ),
)
# ---------------------------------------------------------------------------
# The daily request limit, passed on to the client (2026-11-21)
# ---------------------------------------------------------------------------
#
# Every BlackDome API answer to a keyed request carries the key's DAILY limit as RateLimit-Limit,
# RateLimit-Remaining and RateLimit-Reset (seconds to 00:00 UTC), plus its RateLimit-Policy. A daily
# 429 says so in one sentence ("Daily request limit reached: <plan> allows <n> requests a day."). The MCP server
# passes them on in two ways:
#   - in every tool result, a short note when the limit is near (at most a tenth of it left) or reached, with
#     the numbers in the note's _meta under "blackdome.ai/daily_limit";
#   - on the hosted HTTP transport, the same four headers on the HTTP answer to the tool call
#     (blackdome_mcp.http_server.LimitHeaders).

LIMIT_HEADERS = ("RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "RateLimit-Policy")
LIMIT_META_KEY = "blackdome.ai/daily_limit"
# Where the hosted transport's middleware leaves a dict for this HTTP request's limit (scope["state"][...]).
LIMIT_STATE_KEY = "blackdome_daily_limit"
# The limit seen during the current tool call (set by _call_tool_with_limit_note).
_CALL_LIMIT: ContextVar[Optional[dict]] = ContextVar("blackdome_mcp_call_limit", default=None)


def _limit_from_response(resp: Any) -> Optional[dict]:
    """The daily limit an API answer states, or None when it states none (a keyless or public answer)."""
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    values = {name: str(headers.get(name, "")).strip() for name in LIMIT_HEADERS}
    if not values["RateLimit-Limit"].isdigit() or not values["RateLimit-Remaining"].isdigit():
        return None
    info: dict[str, Any] = {"headers": {k: v for k, v in values.items() if v}}
    info["limit"] = int(values["RateLimit-Limit"])
    info["remaining"] = int(values["RateLimit-Remaining"])
    info["reset_seconds"] = int(values["RateLimit-Reset"]) if values["RateLimit-Reset"].isdigit() else None
    if getattr(resp, "status_code", 200) == 429 and info["remaining"] == 0:
        try:
            detail = resp.json().get("detail")
        except Exception:
            detail = None
        info["detail"] = " ".join(str(detail).split())[:300] if detail else None
    return info


def _keep_lowest(holder: Optional[dict], info: dict) -> None:
    if holder is None:
        return
    current = holder.get("info")
    if current is None or info["remaining"] <= current["remaining"] or info.get("detail"):
        holder["info"] = info


def _request_limit_holder() -> Optional[dict]:
    """The hosted transport's dict for this HTTP request (via the SDK's request context), else None."""
    try:
        from mcp.server.lowlevel.server import request_ctx

        request = getattr(request_ctx.get(), "request", None)
        state = getattr(request, "scope", {}).get("state") if request is not None else None
        holder = state.get(LIMIT_STATE_KEY) if isinstance(state, dict) else None
        return holder if isinstance(holder, dict) else None
    except Exception:
        return None


def _record_limit(resp: Any) -> None:
    """Note the daily limit an API answer states, for the tool result and the hosted HTTP answer."""
    info = _limit_from_response(resp)
    if info is None:
        return
    _keep_lowest(_CALL_LIMIT.get(), info)
    _keep_lowest(_request_limit_holder(), info)


def _limit_note_text(info: dict) -> Optional[str]:
    limit, remaining = info["limit"], info["remaining"]
    reset = info.get("reset_seconds")
    when = "The count starts again at 00:00 UTC"
    if reset is not None:
        hours, minutes = divmod(max(0, reset) // 60, 60)
        when += f" (in {hours} h {minutes} min)"
    if remaining <= 0:
        who = "this key allows" if current_api_key() else "use without an account allows"
        sentence = info.get("detail") or f"Daily request limit reached: {who} {limit} requests a day."
        return f"{sentence} {when}."
    if remaining <= max(1, limit // 10):
        return f"Daily request limit nearly reached: {remaining} of {limit} requests left today. {when}."
    return None


def _limit_note(info: Optional[dict]) -> Any:
    """The note for a tool result, or None when the limit is not near."""
    if not info:
        return None
    text = _limit_note_text(info)
    if text is None:
        return None
    from mcp.types import TextContent

    meta = {
        "state": "reached" if info["remaining"] <= 0 else "near",
        "limit": info["limit"],
        "remaining": info["remaining"],
        "reset_seconds": info.get("reset_seconds"),
    }
    return TextContent(type="text", text=text, _meta={LIMIT_META_KEY: meta})


def _with_limit_note(result: Any, info: Optional[dict]) -> Any:
    note = _limit_note(info)
    if note is None:
        return result
    from mcp.types import CallToolResult, TextContent

    if isinstance(result, CallToolResult):
        return result.model_copy(update={"content": [*result.content, note]})
    if isinstance(result, tuple) and len(result) == 2:
        return [*result[0], note], result[1]
    if isinstance(result, dict):
        return [TextContent(type="text", text=json.dumps(result, indent=2)), note], result
    return [*result, note]


# A tool that refuses or fails returns its sentence through _fail(), which marks the current call as failed; the
# tools/call handler then answers with isError true (2026-11-21, full test 04 finding 5: every refusal, upstream
# error and timeout came back as a successful result). A tool called directly (tests) still returns the sentence.
_CALL_FAILED: ContextVar[Optional[dict]] = ContextVar("blackdome_mcp_call_failed", default=None)


def _fail(text: str) -> str:
    """The sentence of a refusal or failure, with the current tool call marked as failed (isError true)."""
    state = _CALL_FAILED.get()
    if state is not None:
        state["failed"] = True
    return text


def _as_error_result(result: Any) -> Any:
    from mcp.types import CallToolResult, TextContent

    if isinstance(result, CallToolResult):
        return result.model_copy(update={"isError": True})
    structured = None
    if isinstance(result, tuple) and len(result) == 2:
        content, structured = list(result[0]), result[1]
    elif isinstance(result, dict):
        content, structured = [TextContent(type="text", text=json.dumps(result, indent=2))], result
    else:
        content = list(result)
    return CallToolResult(content=content, structuredContent=structured, isError=True)


async def _call_tool_with_limit_note(name: str, arguments: dict[str, Any]) -> Any:
    holder: dict = {}
    failed: dict = {}
    token = _CALL_LIMIT.set(holder)
    failed_token = _CALL_FAILED.set(failed)
    try:
        result = await FastMCP.call_tool(mcp, name, arguments)
    finally:
        _CALL_FAILED.reset(failed_token)
        _CALL_LIMIT.reset(token)
    result = _with_limit_note(result, holder.get("info"))
    return _as_error_result(result) if failed.get("failed") else result


# Replaces FastMCP's own tools/call handler (registered in its constructor) with the same call plus the note.
mcp._mcp_server.call_tool(validate_input=False)(_call_tool_with_limit_note)

# FastMCP 1.x does not expose a product-version constructor argument; its
# protocol server reads this value into initialize.serverInfo.version.
mcp._mcp_server.version = __version__

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
    client_address = _client_address_from_nginx()
    if client_address and _base_url_is_loopback():
        headers["X-Real-IP"] = client_address
    return headers


def _base_url_is_loopback() -> bool:
    try:
        return ipaddress.ip_address(urlsplit(BASE_URL).hostname or "").is_loopback
    except ValueError:
        return (urlsplit(BASE_URL).hostname or "").lower() == "localhost"


def _client_address_from_nginx() -> Optional[str]:
    """Hosted mode: the MCP client's own address as nginx gave it on this request (X-Real-IP), else None.

    The hosted server listens on 127.0.0.1 behind nginx, whose /mcp location sets X-Real-IP to the connection's
    address. That address is passed to the API, so a keyless caller is counted as itself and not in one bucket
    with every other keyless MCP user. It is sent only when the API is called on a loopback address
    (BLACKDOME_BASE_URL such as http://127.0.0.1:7860): through the public address nginx replaces it with this
    server's own address anyway. Taken only from a loopback peer (or the peer uvicorn took from nginx's
    X-Forwarded-For, which nginx sets from the same address)."""
    try:
        from mcp.server.lowlevel.server import request_ctx

        request = getattr(request_ctx.get(), "request", None)
    except Exception:
        return None
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict) or scope.get("type") != "http":
        return None
    real_ip = ""
    for raw_name, raw_value in scope.get("headers") or []:
        if bytes(raw_name).lower() == b"x-real-ip":
            real_ip = bytes(raw_value).decode("latin-1").strip()
    try:
        address = ipaddress.ip_address(real_ip)
        peer_host = (scope.get("client") or ("",))[0] or ""
        peer = ipaddress.ip_address(peer_host)
    except ValueError:
        return None
    if address.is_loopback or not (peer.is_loopback or peer == address):
        return None
    return str(address)


class _KeyNotAccepted(Exception):
    """The caller sent an API key that the BlackDome API does not accept (checked before a free public route)."""


# A wrong key must be refused, never quietly served the free data (2026-11-21, full test 04 finding 9, item D5).
# The free tools' public routes (/api/blackdome/...) do not reject a bad key; they answer as for no key. So when a
# key is sent, it is first checked once on /api/v1/blackdome/me (which 401s a key it does not accept). /me counts
# as a request on the key's daily total, so the outcome is remembered per key digest (never the key itself) for
# _KEY_CHECK_TTL seconds, at most _KEY_CHECK_MAX keys. Only a 401 refuses: any other answer (403, 429, 5xx, a
# timeout) says nothing about the key being wrong, and the call goes ahead as before.
_KEY_CHECK_TTL = 600.0
_KEY_CHECK_MAX = 4096
_KEY_CHECKS: "OrderedDict[str, tuple[float, bool]]" = OrderedDict()
_PUBLIC_ROUTE_PREFIX = "/api/blackdome/"


async def _require_accepted_key() -> None:
    key = current_api_key()
    if not key:
        return
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    now = time.monotonic()
    seen = _KEY_CHECKS.get(digest)
    if seen is not None and now - seen[0] < _KEY_CHECK_TTL:
        accepted = seen[1]
    else:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{BASE_URL}/api/v1/blackdome/me", headers=_headers())
        except httpx.HTTPError:
            return
        _record_limit(resp)
        accepted = resp.status_code != 401
        _KEY_CHECKS[digest] = (now, accepted)
        _KEY_CHECKS.move_to_end(digest)
        while len(_KEY_CHECKS) > _KEY_CHECK_MAX:
            _KEY_CHECKS.popitem(last=False)
    if not accepted:
        raise _KeyNotAccepted()


# Every path a tool calls (2026-11-21, item D6). The hosted server calls the API on loopback (http://127.0.0.1:7860),
# where nginx's allowlist for api.blackdome.ai does not stand in front of it, so the tools hold the same allowlist:
# a path is a fixed string, or a fixed string with one caller value that _path_segment checked (letters, digits,
# ".", "_", "-" and ":"; never "", "." or ".."; never "/", "?", "#" or "%"). _api_path refuses anything else before
# any request is made. These are exactly the locations api.blackdome.ai exposes (nginx: ^~ /api/v1/blackdome/ and
# ~ ^/api/blackdome/(lookup|top-attackers|map|credentials/preview|audit|iocs)(/|$)), so the loopback API is
# asked for nothing the public host would not pass.
_ALLOWED_PATH_RE = re.compile(
    r"^(?:/api/v1/blackdome/|/api/blackdome/(?:lookup|top-attackers|map|credentials/preview|audit|iocs)(?:/|$))"
)
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ENCODED_SEGMENT_RE = re.compile(r"^(?:[A-Za-z0-9._-]|%3A)+$")


def _path_segment(value: object) -> str:
    """One caller value placed in a path (an id, a sha256, an IP), percent-encoded; refused unless it is plain."""
    if type(value) is not str or not _PATH_SEGMENT_RE.fullmatch(value):
        raise _CustomerIntelligenceValidationError
    return quote(value, safe="")


def _api_path(path: str) -> str:
    """``path`` if the tools may call it, else refused (no request is made)."""
    segments = path.split("/")[1:]
    if (not _ALLOWED_PATH_RE.match(path)
            or any(not _ENCODED_SEGMENT_RE.fullmatch(segment) or segment.startswith(".") for segment in segments)):
        raise _CustomerIntelligenceValidationError
    return path


async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Make a GET request to the BlackDome API and return the JSON payload.

    BlackDome returns FLAT response objects (no top-level "data" envelope), so we
    return the body as-is — a legitimate top-level "data" field (e.g. on some
    feeds) must not be silently unwrapped.
    """
    path = _api_path(path)
    if path.startswith(_PUBLIC_ROUTE_PREFIX):
        await _require_accepted_key()
    url = f"{BASE_URL}{path}"
    # Strip None values from params
    if params:
        params = {k: v for k, v in params.items() if v is not None}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url, headers=_headers(), params=params)
        _record_limit(resp)
        resp.raise_for_status()
        return resp.json()


async def _post(path: str, body: dict[str, Any]) -> Any:
    """Make a read-only JSON-body request to the BlackDome API."""
    headers = _headers()
    headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(f"{BASE_URL}{_api_path(path)}", headers=headers, json=body)
        _record_limit(resp)
        resp.raise_for_status()
        return resp.json()


def _retry_hint(response: httpx.Response) -> str:
    """A retry time, only when the service sent one (per-minute limits do; the daily limit does not)."""
    retry = response.headers.get("Retry-After", "")
    return f" Retry after {retry} seconds." if retry.isdigit() else ""


def _hosted() -> bool:
    """True inside a hosted (streamable-HTTP) request, False in stdio."""
    return _key_of_this_http_request() is not None


def _not_a_plan_problem(detail: str) -> Optional[str]:
    """A 403 that a plan does not cure (expired key, inactive account, missing scope), in plain words, else None."""
    lowered = detail.lower()
    if "expired" in lowered:
        return "this API key has expired. Create a new key in your BlackDome dashboard."
    if "subscription inactive" in lowered:
        return "the subscription on this key's account is not active. Check billing in your BlackDome dashboard."
    if "inactive" in lowered:
        return "this BlackDome account is inactive."
    if "scope" in lowered:
        return "this API key does not have the scope this tool needs (most tools need `read`)."
    return None


def _denied_reason(detail: str, tool: str) -> str:
    """Why a 403 was returned: an expired key or an inactive account is not a plan problem; otherwise the plan
    that opens this tool and its price (blackdome_mcp.plans)."""
    return _not_a_plan_problem(detail) or plans.refusal(tool, "plan", hosted=_hosted())


def _unauthenticated(tool: str) -> str:
    """The 401 sentence: no key sent, or a key the service did not accept, and the plan that opens the tool."""
    situation = "bad_key" if current_api_key() else "no_key"
    return "Authentication failed (401): " + plans.refusal(tool, situation, hosted=_hosted())


def _transport_failure(exc: Exception) -> Optional[str]:
    """What went wrong when no usable answer came back (a timeout, no connection, an unreadable body), else None."""
    if isinstance(exc, httpx.TimeoutException):
        return f"The BlackDome API did not answer within {TIMEOUT} seconds. Try again."
    if isinstance(exc, httpx.TransportError):
        return "The BlackDome API could not be reached. Try again."
    if isinstance(exc, ValueError):   # json.JSONDecodeError: a body that is not the JSON the API sends
        return "The BlackDome API sent an answer that could not be read. Try again."
    return None


def _format_error(exc: Exception, tool: str) -> str:
    return _fail(_format_error_text(exc, tool))


def _format_error_text(exc: Exception, tool: str) -> str:
    if isinstance(exc, _CustomerIntelligenceValidationError):
        return "Invalid request parameters."
    if isinstance(exc, _KeyNotAccepted):
        return _unauthenticated(tool)
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except Exception:
            detail = exc.response.text
        # One short line: the service's reasons are short sentences, and a proxy's error page
        # must not be pasted into an assistant's context.
        detail = " ".join(str(detail).split())[:300]
        if status == 401:
            return _unauthenticated(tool)
        if status == 403:
            return f"Access denied (403): {_denied_reason(detail, tool)} Server said: {detail}"
        if status == 429:
            # The server's message names this account's own limit.
            return f"Rate limited (429): {detail}" + _retry_hint(exc.response)
        return f"API error {status}: {detail}"
    return _transport_failure(exc) or f"Request failed: {exc.__class__.__name__}."


class _CustomerIntelligenceValidationError(ValueError):
    """Raised for invalid local customer-intelligence tool input."""


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]{2,63}$",
    re.IGNORECASE,
)
_MAX_INDICATOR_LENGTH = 2048
_CLUSTER_MAX_NODES = 100
_CLUSTER_MAX_EDGES = 200
_CLUSTER_MAX_EVIDENCE = 100
_THREATDROP_MCP_DETONATION_LIMIT = 10
_THREATDROP_MCP_ATTACHMENT_LIMIT = 10
_THREATDROP_MCP_TIMELINE_LIMIT = 20
_THREATDROP_MCP_TEXT_LIMIT = 256


def _validation_error() -> str:
    return _fail("Invalid request parameters.")


def _has_unsafe_text(value: str) -> bool:
    return (
        not value
        or len(value) > _MAX_INDICATOR_LENGTH
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _validate_sha256(value: object) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise _CustomerIntelligenceValidationError
    return value


def _validate_ip(value: object) -> str:
    if type(value) is not str or _has_unsafe_text(value):
        raise _CustomerIntelligenceValidationError
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise _CustomerIntelligenceValidationError from exc
    return value


def _validate_domain(value: object) -> str:
    if type(value) is not str or _has_unsafe_text(value) or not _DOMAIN_RE.fullmatch(value):
        raise _CustomerIntelligenceValidationError
    return value


def _validate_url(value: object) -> str:
    if type(value) is not str or _has_unsafe_text(value):
        raise _CustomerIntelligenceValidationError
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise _CustomerIntelligenceValidationError
        if parsed.username is not None or parsed.password is not None:
            raise _CustomerIntelligenceValidationError
        _ = parsed.port
        host = parsed.hostname
        try:
            _validate_ip(host)
        except _CustomerIntelligenceValidationError:
            _validate_domain(host)
    except (ValueError, _CustomerIntelligenceValidationError) as exc:
        raise _CustomerIntelligenceValidationError from exc
    return value


def _validate_selector(kind: object, value: object) -> tuple[str, str]:
    if type(kind) is not str:
        raise _CustomerIntelligenceValidationError
    validators = {
        "sha256": _validate_sha256,
        "ip": _validate_ip,
        "domain": _validate_domain,
        "url": _validate_url,
    }
    validator = validators.get(kind)
    if validator is None:
        raise _CustomerIntelligenceValidationError
    return kind, validator(value)


def _validate_positive_int(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise _CustomerIntelligenceValidationError
    return value


def _validate_submission_id(value: object) -> int:
    return _validate_positive_int(value)


def _format_customer_intelligence_error(exc: Exception, tool: str) -> str:
    return _fail(_format_customer_intelligence_error_text(exc, tool))


def _fixed_403_detail(response: httpx.Response) -> str:
    """The service's 403 reason when it is one of its fixed strings (never a selector), else ""."""
    try:
        detail = response.json().get("detail")
    except Exception:
        return ""
    return detail if isinstance(detail, str) and detail in _FIXED_403_DETAILS else ""


def _format_customer_intelligence_error_text(exc: Exception, tool: str) -> str:
    """Return an explicit but selector-safe customer intelligence error (the server's text is never relayed)."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 401:
            return _unauthenticated(tool)
        if status == 403:
            return "Access denied (403): " + _denied_reason(_fixed_403_detail(exc.response), tool)
        if status == 429:
            # No server text on this path; a retry time only when the service sent one.
            return "Rate limited (429): the request limit of your plan is reached." + _retry_hint(exc.response)
        return f"Customer intelligence request unavailable ({status})."
    if isinstance(exc, _CustomerIntelligenceValidationError):
        return "Invalid request parameters."
    return _transport_failure(exc) or "Customer intelligence request unavailable."


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
# Answers an assistant can use (2026-11-21, full test 04 findings 6-8, item D4)
# ---------------------------------------------------------------------------
#
# - Every list tool takes a limit with a default and a maximum, and the answer says in "more" when there is more.
# - Every timestamp leaves in UTC with a Z: ISO strings with an offset are converted, and a "<name>_str" field
#   that sits beside a "<name>" epoch number is rewritten from that number (get_actor's *_str fields were the
#   API host's local time with no zone, an hour off UTC).

_ISO_WITH_ZONE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$"
)
_LIST_KEYS = ("items", "detonations", "sessions", "credentials", "countries", "events", "steps", "iocs",
              "objects", "families", "specimens")


def _utc_text(value: Any) -> Optional[str]:
    """An ISO timestamp with a zone, or an epoch number, as UTC 'YYYY-MM-DDTHH:MM:SSZ'; None when it is neither."""
    from datetime import datetime, timezone

    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            if not 1_000_000_000 <= value <= 10_000_000_000:
                return None
            moment = datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str) and _ISO_WITH_ZONE_RE.fullmatch(value):
            moment = datetime.fromisoformat(value.replace("Z", "+00:00").replace(" ", "T", 1))
        elif hasattr(value, "tzinfo") and getattr(value, "tzinfo", None) is not None:
            moment = value
        else:
            return None
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def _in_utc(payload: Any) -> Any:
    """The payload with every zoned timestamp in UTC with a Z (see above)."""
    if isinstance(payload, dict):
        out = {}
        for key, value in payload.items():
            if isinstance(key, str) and key.endswith("_str") and key[:-4] in payload:
                epoch = _utc_text(payload[key[:-4]]) if isinstance(payload[key[:-4]], (int, float)) else None
                if epoch is not None:
                    out[key] = epoch
                    continue
            out[key] = _in_utc(value)
        return out
    if isinstance(payload, list):
        return [_in_utc(item) for item in payload]
    if isinstance(payload, str) or hasattr(payload, "tzinfo"):
        converted = _utc_text(payload)
        return converted if converted is not None else payload
    return payload


def _dump(payload: Any) -> str:
    """The JSON text of a tool answer, timestamps in UTC."""
    return json.dumps(_in_utc(payload), indent=2, default=str)


def _main_list(payload: Any) -> tuple[Optional[str], Optional[list]]:
    if isinstance(payload, dict):
        for key in _LIST_KEYS:
            if isinstance(payload.get(key), list):
                return key, payload[key]
    return None, None


def _add_more(payload: Any, sentence: str) -> None:
    if isinstance(payload, dict):
        existing = payload.get("more")
        payload["more"] = f"{existing} {sentence}" if isinstance(existing, str) and existing else sentence


def _say_if_more(payload: Any, limit: int, maximum: int, *, param: str = "limit", offset_param: Optional[str] = None,
                 offset: int = 0) -> Any:
    """Add a "more" sentence when the answer's list may not be all there is."""
    key, items = _main_list(payload)
    if key is None:
        return payload
    shown = len(items)
    total = payload.get("total") if isinstance(payload.get("total"), int) else None
    has_more = payload.get("has_more") is True or isinstance(payload.get("next_offset"), int) or (
        total is not None and total > offset + shown)
    if not has_more and (total is not None or shown < limit):
        return payload
    how = f"raise {param} (at most {maximum})" if limit < maximum else ""
    if offset_param:
        page = f"pass {offset_param}={offset + shown} for the next page"
        how = f"{how} or {page}" if how else page
    counted = f"{shown} of {total} {key}" if total is not None else f"{shown} {key}"
    sure = "There are more" if has_more else "There may be more"
    _add_more(payload, f"Showing {counted}. {sure}" + (f": {how}." if how else "."))
    return payload


def _cap_list(container: Any, key: str, limit: int, *, label: str, param: str, maximum: int,
              holder: Any = None) -> None:
    """Shorten container[key] to ``limit`` items, saying so in holder["more"] (holder defaults to container)."""
    if not isinstance(container, dict) or not isinstance(container.get(key), list):
        return
    items = container[key]
    if len(items) <= limit:
        return
    container[key] = items[:limit]
    how = f": raise {param} (at most {maximum})" if limit < maximum else ""
    _add_more(holder if holder is not None else container,
              f"Showing {limit} of {len(items)} {label}. There are more{how}.")


def _clamp(value: int, lowest: int, highest: int) -> int:
    try:
        return max(lowest, min(int(value), highest))
    except (TypeError, ValueError):
        return lowest


# ---------------------------------------------------------------------------
# Public tools (no API key required)
# ---------------------------------------------------------------------------


@mcp.tool()
async def lookup_attacker_ip(ip: str) -> str:
    """Look up a single attacker IP — events, protocols, credentials, MITRE (free, passwords masked).

    Returns the full honeypot dossier for an IP present in the event store:
    session/event counts, first/last seen, protocols, a daily timeline,
    credentials attempted (passwords MASKED to '********'), MITRE ATT&CK
    techniques, the cities of the sensors that saw it, and recent events. A 404 means the
    IP has no recorded events.

    For an address with more events than one read takes (the busiest attackers send
    over 100,000 a day), `total_events_is_minimum` is true: `total_events` is then at
    least that many, and the protocol and sensor breakdown and `total_sessions`
    describe only its newest `sampled_events` events.

    Args:
        ip: The attacker IP address to look up (e.g. "176.65.139.56")
    """
    try:
        payload = await _get(f"/api/blackdome/lookup/{quote(_validate_ip(ip), safe='')}")
        # SECURITY: mask plaintext passwords before returning — the keyless
        # lookup endpoint leaks raw credentials, the MCP tool must not.
        payload = _mask_credentials(payload)
        return _dump(payload)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return json.dumps(
                {"found": False, "ip": ip, "detail": "No recorded events for this IP"},
                indent=2,
            )
        return _format_error(exc, "lookup_attacker_ip")
    except Exception as exc:
        return _format_error(exc, "lookup_attacker_ip")


@mcp.tool()
async def top_attackers(days: int = 30, limit: int = 5) -> str:
    """List the most active attacker IPs over a window — pick a busy IP to drill into (free).

    Returns ranked attackers with event counts, protocols, and first/last seen,
    plus a summary of total events / unique attackers. Feed a returned IP into
    lookup_attacker_ip for the full dossier.

    Args:
        days: Lookback period in days (default 30)
        limit: Max attackers to return (default 5, at most 100)
    """
    try:
        limit = _clamp(limit, 1, 100)  # API caps at 100
        payload = await _get("/api/blackdome/top-attackers", {
            "days": min(days, 30),   # API caps at 30
            "limit": limit,
        })
        return _dump(_say_if_more(payload, limit, 100))
    except Exception as exc:
        return _format_error(exc, "top_attackers")


@mcp.tool()
async def attack_map(limit: int = 10) -> str:
    """Get recent geolocated attack events for a live global attack map (free).

    Returns individual attack events with source IP, protocol, country/city and
    latitude/longitude, plus a 24h summary. Unlike the aggregate tools, this
    endpoint DOES populate geo. NOTE: limit minimum is 10 (lower values return
    422), so the default is 10.

    Args:
        limit: Max events to return (minimum 10, default 10, at most 100)
    """
    try:
        limit = _clamp(limit, 10, 100)
        payload = await _get("/api/blackdome/map/events", {
            "limit": limit,
        })
        return _dump(_say_if_more(payload, limit, 100))
    except Exception as exc:
        return _format_error(exc, "attack_map")


@mcp.tool()
async def attack_heatmap(limit: int = 5) -> str:
    """Get a country-aggregated attack heatmap with lat/lon centroids (free).

    Returns per-country attack and unique-IP counts with centroid coordinates,
    plus a 7-day summary. NOTE: limit minimum is 5 (lower values return 422).

    Args:
        limit: Max countries to return (minimum 5, default 5, at most 50)
    """
    try:
        limit = _clamp(limit, 5, 50)
        payload = await _get("/api/blackdome/map/heatmap", {
            "limit": limit,
        })
        return _dump(_say_if_more(payload, limit, 50))
    except Exception as exc:
        return _format_error(exc, "attack_heatmap")


@mcp.tool()
async def credential_preview(limit: int = 5, hours: int = 24) -> str:
    """Preview recently captured credentials with aggregate teaser counts (free, masked server-side).

    Returns a small sample of recently captured credentials (passwords already
    masked to '****' server-side) plus aggregate totals (recent_total,
    total_captured, protocol_count). Use search_credentials (paid) for the full
    plaintext corpus.

    Args:
        limit: Max sample credentials to return (default 5, at most 25)
        hours: Lookback window in hours (default 24)
    """
    try:
        # NOTE: passwords are ALREADY masked server-side on this endpoint ('****'),
        # so we do NOT re-mask here.
        limit = _clamp(limit, 1, 25)  # API caps at 25
        payload = await _get("/api/blackdome/credentials/preview", {
            "limit": limit,
            "hours": min(hours, 24),  # API caps at 24
        })
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "credential_preview")


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
        payload = await _get(f"/api/blackdome/audit/{_path_segment(sigil_id)}")
        return _dump(payload)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return json.dumps(
                {"found": False, "sigil_id": sigil_id, "detail": "Sigil not found / invalid"},
                indent=2,
            )
        return _format_error(exc, "verify_sigil")
    except Exception as exc:
        return _format_error(exc, "verify_sigil")


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
        limit: Max IOCs to return (default 20, at most 25)
    """
    try:
        # Public redacted preview. /api/blackdome/iocs is the KEYED customer
        # feed; /api/blackdome/threat-intel/iocs is its external twin.
        limit = _clamp(limit, 1, 25)
        payload = await _get("/api/blackdome/iocs/public", {
            "ioc_type": ioc_type,
            "severity": severity,
            "limit": limit,
        })
        return _dump(_say_if_more(payload, limit, 25))
    except Exception as exc:
        return _format_error(exc, "recent_iocs")


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
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "ioc_trends")


# ---------------------------------------------------------------------------
# Community-free / tiered export
# ---------------------------------------------------------------------------


_EXPORT_MAX = 1000


def _cap_csv(text: str, limit: int) -> str:
    lines = text.splitlines(keepends=True)
    if len(lines) - 1 <= limit:
        return text
    kept = "".join(lines[: limit + 1])
    if not kept.endswith("\n"):
        kept += "\n"
    return kept + (f"# Showing {limit} of {len(lines) - 1} rows. There are more: raise limit "
                   f"(at most {_EXPORT_MAX}).\n" if limit < _EXPORT_MAX else
                   f"# Showing {limit} of {len(lines) - 1} rows. There are more: narrow days or ioc_type.\n")


def _cap_stix(bundle: Any, limit: int) -> None:
    """Keep the first ``limit`` indicator objects of a STIX bundle (and every non-indicator object)."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        return
    objects = bundle["objects"]
    indicators = [o for o in objects if isinstance(o, dict) and o.get("type") == "indicator"]
    if len(indicators) <= limit:
        return
    keep = {id(o) for o in indicators[:limit]}
    bundle["objects"] = [o for o in objects if not (isinstance(o, dict) and o.get("type") == "indicator") or id(o) in keep]
    how = f": raise limit (at most {_EXPORT_MAX})" if limit < _EXPORT_MAX else ": narrow days or ioc_type"
    # A custom bundle property (STIX 2.1 names custom properties x_...), so a STIX reader still accepts it.
    bundle["x_blackdome_more"] = f"Showing {limit} of {len(indicators)} indicators. There are more{how}."


@mcp.tool()
async def export_iocs(
    fmt: str = "json",
    ioc_type: Optional[str] = None,
    min_confidence: int = 50,
    min_severity: str = "medium",
    days: int = 30,
    limit: int = 100,
) -> str:
    """Export the IOC threat-intel feed as json, csv (free) or stix (Threat Intel Pro).

    Branches on format: json returns a flat {feed, generated_at, count, iocs[]}
    object; csv returns the raw CSV text body; stix returns a STIX 2.1 bundle
    (requires the stix_export feature — Threat Intel Pro). json and csv work
    on the free community tier. The feed is tenant-scoped when authenticated.

    Args:
        fmt: Output format — "json", "csv", or "stix" (default "json")
        ioc_type: Filter by IOC type (e.g. "sha256", "ipv4")
        min_confidence: Minimum confidence 0-100 (default 50; pass 0 for full set)
        min_severity: Minimum severity (default "medium")
        days: Lookback period in days, 1-365 (default 30)
        limit: Max indicators returned (default 100, at most 1000); the answer says when there are more
    """
    fmt = (fmt or "json").lower()
    limit = _clamp(limit, 1, _EXPORT_MAX)
    if fmt not in ("json", "csv", "stix"):
        return _fail("Invalid fmt: choose one of 'json', 'csv', 'stix'.")
    url = f"{BASE_URL}{_api_path(f'/api/v1/blackdome/threat-intel/feed/{fmt}')}"
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
            _record_limit(resp)
            resp.raise_for_status()
            if fmt == "csv":
                # csv branch -> the raw text body, cut to the header and `limit` rows.
                return _cap_csv(resp.text, limit)
            # json and stix branches -> structured JSON (flat feed object or
            # a STIX 2.1 bundle), cut to `limit` indicators.
            payload = resp.json()
            if fmt == "json":
                _cap_list(payload, "iocs", limit, label="indicators", param="limit", maximum=_EXPORT_MAX)
            else:
                _cap_stix(payload, limit)
            return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "export_iocs:stix" if fmt == "stix" else "export_iocs")


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
    protocol, source_ip, source_country, session_id, first/last seen,
    cross_protocol, attempt_count) from the shared global dataset. Which
    sensor captured a credential is not returned. Requires the Credential Intelligence plan
    (feature realtime_credential_feed or credential_intel). Plaintext
    is intentionally returned here — it is NOT masked.

    Args:
        q: Free-text query across credentials
        username: Filter by username
        ip: Filter by source IP
        protocol: Filter by protocol (e.g. "ssh", "http", "smtp")
        since: ISO timestamp lower bound
        cross_protocol: Only credentials seen across multiple protocols
        limit: Max records (default 20, at most 100)
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
            "limit": _clamp(limit, 1, 100),
            "offset": offset,
        })
        return _dump(_say_if_more(payload, _clamp(limit, 1, 100), 100, offset_param="offset", offset=offset))
    except Exception as exc:
        return _format_error(exc, "search_credentials")


@mcp.tool()
async def credential_stats(
    since: Optional[str] = None,
    protocol: Optional[str] = None,
) -> str:
    """Get aggregate credential statistics — top usernames/passwords, protocol breakdown (paid: credential_intel).

    Returns totals (unique credentials/ips/usernames), cross-protocol counts and
    top usernames/passwords from the shared global dataset. Requires the
    Credential Intelligence plan (feature realtime_credential_feed or credential_intel).

    Args:
        since: ISO timestamp lower bound
        protocol: Scope stats to a single protocol (e.g. "ssh")
    """
    try:
        payload = await _get("/api/v1/blackdome/credentials/stats", {
            "since": since,
            "protocol": protocol,
        })
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "credential_stats")


@mcp.tool()
async def list_payloads(sha256: Optional[str] = None, limit: int = 20) -> str:
    """List files attackers delivered to the honeypots, or fetch one file's record by sha256 (Threat Intel Analyst or Pro).

    With no sha256 this lists the newest captured files (hash, the attacker's
    file name, download URL, size, type, first and last seen, whether it was
    detonated) with summary stats. With a sha256 it returns that file's
    record, the actor where known, and any VirusTotal/MalwareBazaar reputation
    BlackDome already holds; no outside lookup is made, and a hash that is not
    a honeypot capture answers 404. Threat Intel Pro also gets the detonation's
    status, verdict and times; report content is under list_detonations.
    Reference hashes are discoverable free via recent_iocs ioc_value.

    Args:
        sha256: Optional payload sha256 — when given, returns that payload's detail
        limit: Max payloads in list mode (default 20, at most 100)
    """
    try:
        limit = _clamp(limit, 1, 100)
        if sha256:
            # detail mode -> /payloads/{sha256} (different envelope from list).
            payload = await _get(f"/api/v1/blackdome/payloads/{_path_segment(sha256)}")
        else:
            payload = _say_if_more(await _get("/api/v1/blackdome/payloads", {"limit": limit}), limit, 100)
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "list_payloads")


@mcp.tool()
async def get_actor(
    actor_id: Optional[str] = None,
    limit: int = 20,
    risk: Optional[str] = None,
    sort: Optional[str] = None,
    descending: Optional[bool] = None,
) -> str:
    """List threat actors with risk/geo enrichment, or fetch one actor's sessions (Threat Intel Analyst or Pro).

    With no actor_id this lists clustered actors (risk level/score, geo,
    techniques, sophistication, event counts). With an actor_id it returns that
    actor's session list. Actor clustering is only surfaced on this keyed
    endpoint (the free lookup returns actor_id=null).

    Args:
        actor_id: Optional actor id — when given, returns that actor's sessions
        limit: Max actors/sessions to return (default 20, at most 100)
        risk: Filter by risk level (e.g. "medium")
        sort: Sort field (e.g. "risk")
        descending: Sort descending
    """
    try:
        limit = _clamp(limit, 1, 100)
        if actor_id:
            # sessions sub-resource -> /actors/{actor_id}/sessions
            payload = await _get(f"/api/v1/blackdome/actors/{_path_segment(actor_id)}/sessions", {
                "limit": limit,
            })
        else:
            payload = await _get("/api/v1/blackdome/actors", {
                "limit": limit,
                "risk": risk,
                "sort": sort,
                "descending": descending,
            })
        return _dump(_say_if_more(payload, limit, 100))
    except Exception as exc:
        return _format_error(exc, "get_actor")


@mcp.tool()
async def list_notable_sessions(
    min_commands: int = 3,
    since: Optional[str] = None,
    service: Optional[str] = None,
    technique: Optional[str] = None,
    human_likely: Optional[bool] = None,
    actor_id: Optional[str] = None,
    limit: int = 20,
) -> str:
    """List notable honeypot sessions. Requires Threat Intel Analyst or Pro.

    Returns a flat object with count and sessions[]. Each session includes
    session_id, actor_id, ip, geo, command_count, distinct_techniques,
    primary_tactic, persona_stage, persona_score, score, first_ts, last_ts,
    novelty, dropped_artifact_count and human_likely. The list shows public
    attacker addresses.

    Args:
        min_commands: Minimum command count (default 3)
        since: ISO timestamp lower bound within the last two days
        service: Filter by service (e.g. "ssh")
        technique: Filter by MITRE technique id (e.g. "T1059")
        human_likely: Only return sessions matching the human-likely heuristic
        actor_id: Filter by actor id
        limit: Max sessions to return (default 20, at most 100)
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
                "limit": _clamp(limit, 1, 100),
            },
        )
        return _dump(_say_if_more(payload, _clamp(limit, 1, 100), 100))
    except Exception as exc:
        return _format_error(exc, "list_notable_sessions")


@mcp.tool()
async def get_session_transcript(
    session_id: str,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """Get a structured attacker session transcript (session_intel; no plan on sale includes it).

    Returns {session, steps, total_steps, truncated}. The session object includes
    session_id, actor_id, ip, geo, primary_tactic, start_ts, end_ts,
    persona_stage, persona_score and dropped_artifacts. Each step includes seq,
    ts, command, output_preview, exit_code, cwd, latency_ms, techniques and
    guard_triggered. Names of our sensors, our server paths and our addresses
    in command, output_preview and cwd read [sensor], [sandbox-path] and
    [redacted]. Requires the session_intel feature, which no plan on sale includes.

    Args:
        session_id: Session id returned by list_notable_sessions
        limit: Max transcript steps to return (default 100, at most 1000)
        offset: Pagination offset
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/sessions/{_path_segment(session_id)}/transcript",
            {
                "limit": _clamp(limit, 1, 1000),
                "offset": offset,
            },
        )
        if isinstance(payload, dict) and isinstance(payload.get("total_steps"), int):
            payload.setdefault("total", payload["total_steps"])
        return _dump(_say_if_more(payload, _clamp(limit, 1, 1000), 1000, offset_param="offset", offset=offset))
    except Exception as exc:
        return _format_error(exc, "get_session_transcript")


@mcp.tool()
async def list_detonations(
    verdict: Optional[str] = None,
    vm_type: Optional[str] = None,
    sha256: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 20,
) -> str:
    """List malware detonation reports with IOC counts and file classification (paid: Pro detonation_intel).

    Returns a flat object with count and detonations[]. Each detonation includes
    detonation_id, sha256, verdict, finished_at, sandbox_kind
    (virtual_machine, container, not_run or static_analysis), magika_label and
    ioc_count. Only files attackers delivered to a BlackDome honeypot are
    listed. Requires the detonation_intel feature (Threat Intel Pro).

    Args:
        verdict: Filter by verdict (e.g. "malware", "benign", "suspicious")
        vm_type: Ignored by the service since 2026-11-16 (still accepted and
            sent, so existing calls keep working). Read sandbox_kind instead.
        sha256: Filter by artifact sha256
        since: ISO timestamp lower bound
        limit: Max detonations to return (default 20, at most 100)
    """
    try:
        payload = await _get(
            "/api/v1/blackdome/intel/detonations",
            {
                "verdict": verdict,
                "vm_type": vm_type,
                "sha256": sha256,
                "since": since,
                "limit": _clamp(limit, 1, 100),
            },
        )
        return _dump(_say_if_more(payload, _clamp(limit, 1, 100), 100))
    except Exception as exc:
        return _format_error(exc, "list_detonations")


@mcp.tool()
async def get_detonation_report(detonation_id: str, ioc_limit: int = 25) -> str:
    """Get a full malware detonation report (paid: Pro detonation_intel).

    Returns detonation_id, sha256, verdict, started_at, finished_at,
    report_available, report_unavailable_reason, report, iocs[] and artifact
    classification fields. report is what the file did, as a fixed set of
    fields: status, verdict, risk_score, reason_codes, verdicts (heuristic,
    model), file (hashes, size, type), archive (members), static (format,
    markers), sandbox (kind, executed, timed_out, exit_code, skip_reason),
    behaviour (processes_started, files_created, files_deleted,
    network_connections, dns_lookups, downloads, persistence,
    suspicious_behaviors, syscall_counts) and findings. Names of our sensors,
    the sample's own file name, our server paths and our addresses read
    [sensor], [sample], [sandbox-path] and [redacted]. report is null and
    report_available false when no report could be built. Requires the
    detonation_intel feature (Threat Intel Pro).

    Args:
        detonation_id: Detonation id returned by list_detonations
        ioc_limit: Max rows of iocs[] to return (default 25, at most 500)
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/detonations/{_path_segment(detonation_id)}"
        )
        _cap_list(payload, "iocs", _clamp(ioc_limit, 1, 500), label="iocs", param="ioc_limit", maximum=500)
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "get_detonation_report")


@mcp.tool()
async def get_artifact(sha256: str, ioc_limit: int = 25) -> str:
    """Get an artifact dossier with linked detonation, IOCs and session reference (paid: Pro detonation_intel).

    Returns artifact classification fields, linked detonation summary, iocs[],
    and dropped_by_session identifiers/counts only (null unless the file came
    from a honeypot session of an attacker). It does not request or
    return transcript command text or output_preview fields. Requires the
    detonation_intel feature (Threat Intel Pro).

    Args:
        sha256: Artifact sha256 to inspect
        ioc_limit: Max rows of iocs[] to return (default 25, at most 500)
    """
    try:
        payload = await _get(
            f"/api/v1/blackdome/intel/artifacts/{_path_segment(sha256)}"
        )
        _cap_list(payload, "iocs", _clamp(ioc_limit, 1, 500), label="iocs", param="ioc_limit", maximum=500)
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "get_artifact")


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
        return _dump(payload)
    except Exception as exc:
        return _format_error(exc, "whoami")


# ---------------------------------------------------------------------------
# Customer Intelligence tools (keyed, read-only)
# ---------------------------------------------------------------------------


NO_EVIDENCE_RECORD = "No evidence record for this indicator."
_EVIDENCE_SHOWN = 10
_LINKS_SHOWN = 25


def _label_of(item: Any, *keys: str) -> Optional[str]:
    for key in keys:
        value = item.get(key) if isinstance(item, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def _evidence_record(indicator_type: str, value: str, payload: Any) -> dict[str, Any]:
    """The API's evidence record, said plainly: the indicator, where and when it was seen, what it links to.

    Full test 2026-11-21 (finding 6): a hit was 14 KB of hashes with the indicator itself not echoed, so it did
    not show where we saw it or what it links to. Hashes that only key the graph are left out."""
    payload = payload if isinstance(payload, dict) else {}
    entity = payload.get("entity") if isinstance(payload.get("entity"), dict) else {}
    references = [r for r in payload.get("evidence_references") or [] if isinstance(r, dict)]
    seen_times = sorted(t for t in (_utc_text(r.get("observed_at")) for r in references) if t)
    where = sorted({w for w in (_label_of(r, "provenance_label", "provenance") for r in references) if w})
    evidence = [
        {
            "seen_at": r.get("observed_at"),
            "where": _label_of(r, "provenance_label", "provenance"),
            "verified": _label_of(r, "quality_label"),
            "why_not_verified": _label_of(r, "reason_label"),
            "file_analysis": _label_of(r, "analysis_label"),
        }
        for r in sorted(references, key=lambda r: str(r.get("observed_at") or ""), reverse=True)[:_EVIDENCE_SHOWN]
    ]
    own_key = entity.get("entity_key") or payload.get("entity_key")
    linked = [
        {k: e[k] for k in ("entity_type", "canonical_facts") if e.get(k) not in (None, {}, [])}
        for e in payload.get("linked_entities") or []
        if isinstance(e, dict) and e.get("entity_key") != own_key
    ]
    edges = [e for e in payload.get("edges") or [] if isinstance(e, dict)]
    record: dict[str, Any] = {
        "indicator": {"type": indicator_type, "value": value},
        "found": True,
        "first_recorded_at": entity.get("created_at"),
        "first_seen": seen_times[0] if seen_times else None,
        "last_seen": seen_times[-1] if seen_times else None,
        "where_seen": where or [_label_of(payload, "provenance_label", "provenance")],
        "evidence_count": len(references),
        "verified": _label_of(payload, "uncertainty_label"),
        "why_not_verified": _label_of(payload, "uncertainty_reason_label"),
        "completeness": _label_of(payload, "completeness_label"),
        "facts": entity.get("canonical_facts") or {},
        "links_to": linked[:_LINKS_SHOWN],
        "links": edges[:_LINKS_SHOWN],
        "evidence": evidence,
    }
    if not linked and not edges:
        record["links_note"] = "The malware graph links this indicator to nothing else yet."
    if len(references) > _EVIDENCE_SHOWN:
        _add_more(record, f"Showing the newest {_EVIDENCE_SHOWN} of {len(references)} evidence records.")
    if len(linked) > _LINKS_SHOWN or len(edges) > _LINKS_SHOWN:
        _add_more(record, f"Showing {_LINKS_SHOWN} links of {max(len(linked), len(edges))}.")
    return record


@mcp.tool()
async def explain_ioc(indicator_type: str, indicator_value: str) -> str:
    """An evidence record for an indicator in our malware graph (an IP, domain or URL): where and when we saw it,
    and what it links to (Threat Intel Analyst or Pro; plan feature `ioc_explanation`).

    Returns the indicator, first and last time seen, where it was seen, whether the evidence is verified, the
    entities it links to and the newest evidence records. Most indicators in the feed are not in the malware
    graph, and then the answer is "No evidence record for this indicator."

    Args:
        indicator_type: "ip", "domain" or "url"
        indicator_value: The indicator, e.g. "203.0.113.7", "example.com" or "https://example.com/x"
    """
    try:
        if indicator_type not in {"ip", "domain", "url"}:
            raise _CustomerIntelligenceValidationError
        validators = {"ip": _validate_ip, "domain": _validate_domain, "url": _validate_url}
        value = validators[indicator_type](indicator_value)
        payload = await _post(
            "/api/v1/blackdome/intelligence/ioc/explain",
            {"indicator_type": indicator_type, "value": value},
        )
        return _dump(_evidence_record(indicator_type, value, payload))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return NO_EVIDENCE_RECORD
        return _format_customer_intelligence_error(exc, "explain_ioc")
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "explain_ioc")


@mcp.tool()
async def compare_samples(left_sha256: str, right_sha256: str) -> str:
    """Compare two samples deterministically (Pro: sample_compare)."""
    try:
        left, right = _validate_sha256(left_sha256), _validate_sha256(right_sha256)
        payload = await _post(
            "/api/v1/blackdome/intelligence/samples/compare",
            {"left_sha256": left, "right_sha256": right},
        )
        return _dump(payload)
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "compare_samples")


@mcp.tool()
async def get_evidence_cluster(
    entity_kind: str,
    value: str,
    depth: int = 1,
    max_nodes: int = 25,
    max_edges: int = 50,
    max_evidence: int = 50,
) -> str:
    """Get a bounded evidence cluster (Pro: genome_clusters)."""
    try:
        entity_kind, value = _validate_selector(entity_kind, value)
        depth = _validate_positive_int(depth)
        if depth not in {1, 2}:
            raise _CustomerIntelligenceValidationError
        max_nodes = min(_validate_positive_int(max_nodes), _CLUSTER_MAX_NODES)
        max_edges = min(_validate_positive_int(max_edges), _CLUSTER_MAX_EDGES)
        max_evidence = min(_validate_positive_int(max_evidence), _CLUSTER_MAX_EVIDENCE)
        payload = await _post(
            "/api/v1/blackdome/intelligence/genome/cluster",
            {
                "entity_kind": entity_kind,
                "value": value,
                "depth": depth,
                "max_nodes": max_nodes,
                "max_edges": max_edges,
                "max_evidence": max_evidence,
            },
        )
        return _dump(payload)
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "get_evidence_cluster")


@mcp.tool()
async def get_reproducible_novelty(entity_kind: str, value: str) -> str:
    """Get a reproducible novelty assessment (Pro: reproducible_novelty)."""
    try:
        entity_kind, value = _validate_selector(entity_kind, value)
        payload = await _post(
            "/api/v1/blackdome/intelligence/genome/novelty",
            {"entity_kind": entity_kind, "value": value},
        )
        return _dump(payload)
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "get_reproducible_novelty")


NO_THREATDROP_SUBMISSION = "No ThreatDrop submission with this id on this account."


@mcp.tool()
async def get_threatdrop_case(submission_id: int) -> str:
    """Get an account-bound sanitized ThreatDrop case (ThreatDrop API access)."""
    try:
        submission_id = _validate_submission_id(submission_id)
        payload = await _get(
            f"/api/v1/blackdome/threatdrop/submissions/{submission_id}/mcp-summary"
        )
        return _dump(_threatdrop_mcp_summary_subset(payload))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return NO_THREATDROP_SUBMISSION
        return _format_customer_intelligence_error(exc, "get_threatdrop_case")
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "get_threatdrop_case")


_TAKEDOWN_SUBMISSION_SCALAR_TYPES = {
    "id": (int,),
    "message_id": (str, type(None)),
    "received_at": (str, type(None)),
}
_TAKEDOWN_CASE_STATE_SCALAR_TYPES = {
    "verdict": (str,),
    "confidence": (int,),
    "risk_score": (int,),
    "threat_level": (str, type(None)),
    "detonation_status": (str,),
    "analysis_complete": (bool,),
    "quarantined": (bool,),
}


def _typed_takedown_fields(source: dict[str, Any], schema: dict[str, tuple[type, ...]]) -> dict[str, Any]:
    """Copy only approved scalar leaves with their exact public types."""
    return {
        key: source[key]
        for key, allowed_types in schema.items()
        if key in source and type(source[key]) in allowed_types
    }


def _takedown_status_subset(payload: Any) -> dict[str, Any]:
    # The dedicated endpoint is bounded server-side. Keep this local projection
    # as a defence-in-depth contract in case a proxy or older server returns an
    # unexpected field.
    if type(payload) is dict and type(payload.get("submission")) is dict:
        return _threatdrop_mcp_summary_subset(payload)
    if type(payload) is not dict:
        return {"submission": {}, "case_state": {}, "counts": {}, "takedown_progress": {}}

    raw_counts = payload.get("counts")
    counts = {
        key: raw_counts[key]
        for key in (
            "urls_extracted",
            "urls_detonated",
            "abuse_reports_sent",
            "phone_reports_sent",
        )
        if type(raw_counts) is dict and type(raw_counts.get(key)) is int
    }

    raw_progress = payload.get("takedown_progress")
    progress: dict[str, Any] = {}
    if type(raw_progress) is dict:
        for key in ("status", "reason", "sent_at"):
            if raw_progress.get(key) is None or type(raw_progress.get(key)) is str:
                if key in raw_progress:
                    progress[key] = raw_progress[key]
        for key in ("reports_total", "reports_sent"):
            if raw_progress.get(key) is None or type(raw_progress.get(key)) is int:
                if key in raw_progress:
                    progress[key] = raw_progress[key]

        raw_reply = raw_progress.get("provider_reply")
        if type(raw_reply) is dict:
            provider_reply = {
                key: raw_reply[key]
                for key in ("state", "last_at")
                if key in raw_reply and (raw_reply[key] is None or type(raw_reply[key]) is str)
            }
            if "count" in raw_reply and (raw_reply["count"] is None or type(raw_reply["count"]) is int):
                provider_reply["count"] = raw_reply["count"]
            progress["provider_reply"] = provider_reply

        raw_outcome = raw_progress.get("outcome")
        if type(raw_outcome) is dict:
            progress["outcome"] = {
                key: raw_outcome[key]
                for key in ("state", "evidence_level", "decided_at", "last_checked_at")
                if key in raw_outcome and (raw_outcome[key] is None or type(raw_outcome[key]) is str)
            }

        raw_timeline = raw_progress.get("timeline")
        if type(raw_timeline) is list:
            timeline = []
            for raw_item in raw_timeline:
                if type(raw_item) is not dict:
                    continue
                if not all(type(raw_item.get(key)) is str for key in ("event", "occurred_at", "summary")):
                    continue
                item = {key: raw_item[key] for key in ("event", "occurred_at", "summary")}
                for key in ("state", "provider"):
                    if type(raw_item.get(key)) is str:
                        item[key] = raw_item[key]
                timeline.append(item)
            progress["timeline"] = timeline

    return {
        "submission": _typed_takedown_fields(payload, _TAKEDOWN_SUBMISSION_SCALAR_TYPES),
        "case_state": _typed_takedown_fields(payload, _TAKEDOWN_CASE_STATE_SCALAR_TYPES),
        "counts": counts,
        "takedown_progress": progress,
    }


_THREATDROP_MCP_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_THREATDROP_MCP_ID_RE = re.compile(r"^[a-z0-9-]{1,128}$")
_THREATDROP_MCP_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_THREATDROP_MCP_CONTENT_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")


def _safe_summary_string(key: str, value: str) -> str | None:
    if len(value) > _THREATDROP_MCP_TEXT_LIMIT:
        return None
    if key in {
        "received_at", "started_at", "finished_at", "sent_at", "last_at",
        "decided_at", "last_checked_at", "occurred_at",
    }:
        return value if _THREATDROP_MCP_TIMESTAMP_RE.fullmatch(value) else None
    if key == "detonation_id":
        return value if _THREATDROP_MCP_ID_RE.fullmatch(value) else None
    if key == "content_type":
        return value if _THREATDROP_MCP_CONTENT_TYPE_RE.fullmatch(value) else None
    if key in {
        "verdict", "threat_level", "detonation_status", "scan_result", "status",
        "state", "evidence_level", "event",
    }:
        return value if _THREATDROP_MCP_TOKEN_RE.fullmatch(value) else None
    return None


def _summary_scalar_subset(source: Any, schema: dict[str, tuple[type, ...]]) -> dict[str, Any]:
    if type(source) is not dict:
        return {}
    result: dict[str, Any] = {}
    for key, allowed_types in schema.items():
        value = source.get(key)
        if type(value) in allowed_types:
            if type(value) is str:
                safe_value = _safe_summary_string(key, value)
                if safe_value is not None:
                    result[key] = safe_value
            else:
                result[key] = value
    return result


def _bounded_collection(
    source: Any,
    *,
    schema: dict[str, tuple[type, ...]],
    limit: int,
    sort_key: Any,
    required_strings: tuple[str, ...] = (),
    reverse: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_items = source if type(source) is list else []
    items = []
    for raw_item in raw_items:
        if type(raw_item) is not dict:
            continue
        if any(type(raw_item.get(key)) is not str for key in required_strings):
            continue
        item = _summary_scalar_subset(raw_item, schema)
        if any(key not in item for key in required_strings):
            continue
        items.append(item)
    items.sort(key=sort_key, reverse=reverse)
    returned = items[:limit]
    return returned, {
        "returned": len(returned),
        "total": len(raw_items),
        "truncated": len(raw_items) > len(returned),
    }


def _upstream_collection_meta(payload: dict[str, Any], key: str, observed: int, returned: int) -> dict[str, Any]:
    """Keep an API-supplied exact total only when it cannot weaken local bounds."""
    raw_meta = payload.get("collection_meta")
    candidate = raw_meta.get(key) if type(raw_meta) is dict else None
    total = candidate.get("total") if type(candidate) is dict else None
    if type(total) is not int or total < observed:
        total = observed
    return {"returned": returned, "total": total, "truncated": total > returned}


def _threatdrop_mcp_summary_subset(payload: Any) -> dict[str, Any]:
    """Enforce the fixed, capped document-free ThreatDrop MCP response shape."""
    if type(payload) is not dict:
        payload = {}
    submission = _summary_scalar_subset(
        payload.get("submission"),
        {"id": (int,), "received_at": (str, type(None))},
    )
    case_state = _summary_scalar_subset(
        payload.get("case_state"),
        {
            "verdict": (str,), "confidence": (int,), "risk_score": (int,),
            "threat_level": (str, type(None)), "detonation_status": (str,),
            "analysis_complete": (bool,), "quarantined": (bool,),
        },
    )
    counts = _summary_scalar_subset(
        payload.get("counts"),
        {
            "urls_extracted": (int,), "urls_detonated": (int,),
            "abuse_reports_sent": (int,), "phone_reports_sent": (int,),
        },
    )
    detonations, detonations_meta = _bounded_collection(
        payload.get("detonations"),
        schema={
            "detonation_id": (str,), "started_at": (str, type(None)),
            "finished_at": (str, type(None)), "verdict": (str, type(None)),
            "risk_score": (int, type(None)), "quarantined": (bool,),
        },
        limit=_THREATDROP_MCP_DETONATION_LIMIT,
        sort_key=lambda item: (
            str(item.get("started_at") or ""), str(item.get("detonation_id") or ""),
        ),
        required_strings=("detonation_id",),
        reverse=True,
    )
    attachments, attachments_meta = _bounded_collection(
        payload.get("attachments"),
        schema={
            "attachment_id": (int,), "content_type": (str, type(None)),
            "size_bytes": (int, type(None)), "scan_result": (str, type(None)),
            "verdict": (str, type(None)), "risk_score": (int, type(None)),
        },
        limit=_THREATDROP_MCP_ATTACHMENT_LIMIT,
        sort_key=lambda item: int(item.get("attachment_id") or -1),
    )
    raw_progress = payload.get("takedown_progress")
    raw_progress = raw_progress if type(raw_progress) is dict else {}
    progress = _summary_scalar_subset(
        raw_progress,
        {
            "status": (str, type(None)),
            "sent_at": (str, type(None)), "reports_total": (int, type(None)),
            "reports_sent": (int, type(None)),
        },
    )
    provider_reply = _summary_scalar_subset(
        raw_progress.get("provider_reply"),
        {"state": (str, type(None)), "count": (int, type(None)), "last_at": (str, type(None))},
    )
    if provider_reply:
        progress["provider_reply"] = provider_reply
    outcome = _summary_scalar_subset(
        raw_progress.get("outcome"),
        {
            "state": (str, type(None)), "evidence_level": (str, type(None)),
            "decided_at": (str, type(None)), "last_checked_at": (str, type(None)),
        },
    )
    if outcome:
        progress["outcome"] = outcome
    timeline, timeline_meta = _bounded_collection(
        raw_progress.get("timeline"),
        schema={
            "event": (str,), "occurred_at": (str,), "state": (str,),
        },
        limit=_THREATDROP_MCP_TIMELINE_LIMIT,
        sort_key=lambda item: (item["occurred_at"], item["event"]),
        required_strings=("event", "occurred_at"),
    )
    progress["timeline"] = timeline
    return {
        "submission": submission,
        "case_state": case_state,
        "counts": counts,
        "detonations": detonations,
        "attachments": attachments,
        "takedown_progress": progress,
        "collection_meta": {
            "detonations": _upstream_collection_meta(
                payload, "detonations", detonations_meta["total"], detonations_meta["returned"]
            ),
            "attachments": _upstream_collection_meta(
                payload, "attachments", attachments_meta["total"], attachments_meta["returned"]
            ),
            "takedown_timeline": _upstream_collection_meta(
                payload, "takedown_timeline", timeline_meta["total"], timeline_meta["returned"]
            ),
        },
    }


@mcp.tool()
async def get_takedown_status(submission_id: int) -> str:
    """Get account-bound ThreatDrop case state and takedown-workflow status."""
    try:
        submission_id = _validate_submission_id(submission_id)
        payload = await _get(
            f"/api/v1/blackdome/threatdrop/submissions/{submission_id}/mcp-summary"
        )
        return _dump(_takedown_status_subset(payload))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return NO_THREATDROP_SUBMISSION
        return _format_customer_intelligence_error(exc, "get_takedown_status")
    except Exception as exc:
        return _format_customer_intelligence_error(exc, "get_takedown_status")


# ---------------------------------------------------------------------------
# Specimen catalogue tools (keyed, read-only; Pro: genome_clusters)
#
# The shared honeypot catalogue of captured malware specimens: families, builds,
# indicators and lineage. Never returns the files themselves. Selectors (family,
# sha256, search text) travel only in JSON bodies, never in URLs.
# ---------------------------------------------------------------------------

_CATALOGUE_FAMILY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{1,62}$")
_CATALOGUE_KINDS = {"script", "program", "archive", "other"}
_CATALOGUE_FAMILY_PAGE_MAX = 100
_CATALOGUE_MEMBER_PAGE_MAX = 200
_CATALOGUE_RECENT_MAX = 100
_CATALOGUE_SEARCH_MAX = 50
_CATALOGUE_OFFSET_MAX = 10_000


def _validate_offset(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _CATALOGUE_OFFSET_MAX:
        raise _CustomerIntelligenceValidationError
    return value


def _validate_family(value: object) -> str:
    if type(value) is not str or not _CATALOGUE_FAMILY_RE.fullmatch(value):
        raise _CustomerIntelligenceValidationError
    return value


def _validate_catalogue_query(value: object) -> str:
    if type(value) is not str or not 4 <= len(value) <= 120 or value != value.strip() or not value.isprintable():
        raise _CustomerIntelligenceValidationError
    return value


# The service's 403 reasons on the customer-intelligence and catalogue paths are fixed strings, raised before the
# request body is read, so they can never contain a selector. Only these are read (to tell an expired key or an
# inactive account from a plan problem); the server's text itself is never relayed.
_FIXED_403_DETAILS = frozenset({
    "Feature requires a higher plan",
    "Subscription inactive",
    "Insufficient scope: requires 'read'",
    "API key has expired",
    "Tenant account is inactive",
})


def _format_catalogue_error(exc: Exception, tool: str) -> str:
    return _fail(_format_catalogue_error_text(exc, tool))


def _format_catalogue_error_text(exc: Exception, tool: str) -> str:
    """Explicit status, never the server's own message (which could echo a selector)."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 400:
            return "Invalid request (400): the service rejected these parameters."
        if status == 403:
            return "Access denied (403): " + _denied_reason(_fixed_403_detail(exc.response), tool)
        if status == 404:
            return "Not found (404): nothing in the specimen catalogue matches."
        if status == 503:
            return "Specimen catalogue unavailable (503). Try again shortly."
    return _format_customer_intelligence_error_text(exc, tool)


@mcp.tool()
async def list_catalogue_families(limit: int = 25, offset: int = 0) -> str:
    """List malware specimen families in the shared honeypot catalogue, newest first (Pro: genome_clusters).

    Each family groups captured scripts and programs that share code or were
    delivered together, with its tools, behaviour patterns and MITRE techniques.
    Sample files are never returned.

    Args:
        limit: Families per page (1-100, default 25)
        offset: Families to skip (0-10000)
    """
    try:
        limit = min(_validate_positive_int(limit), _CATALOGUE_FAMILY_PAGE_MAX)
        offset = _validate_offset(offset)
        payload = await _get(
            "/api/v1/blackdome/intelligence/catalogue/families",
            {"limit": limit, "offset": offset},
        )
        return _dump(_say_if_more(payload, limit, _CATALOGUE_FAMILY_PAGE_MAX, offset_param="offset", offset=offset))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_catalogue_error(exc, "list_catalogue_families")


@mcp.tool()
async def get_catalogue_family(
    family: str, member_limit: int = 20, member_offset: int = 0, timeline_limit: int = 20
) -> str:
    """Get one specimen family: members, build history, tools, indicators and related families (Pro: genome_clusters).

    Related families share a wallet or control server (same operator) or a
    download host (same infrastructure); each comes with what they share.
    Sample files are never returned.

    Args:
        family: Family key (12 hex), name (e.g. "mozi-007ba229e43c") or a key
            prefix that matches exactly one family
        member_limit: Members per page (1-200, default 20)
        member_offset: Members to skip (0-10000)
        timeline_limit: Newest timeline events to return (1-500, default 20)
    """
    try:
        family = _validate_family(family)
        member_limit = min(_validate_positive_int(member_limit), _CATALOGUE_MEMBER_PAGE_MAX)
        member_offset = _validate_offset(member_offset)
        payload = await _post(
            "/api/v1/blackdome/intelligence/catalogue/family",
            {"family": family, "member_limit": member_limit, "member_offset": member_offset},
        )
        if isinstance(payload, dict):
            _cap_list(payload.get("timeline"), "events", _clamp(timeline_limit, 1, 500), label="timeline events",
                      param="timeline_limit", maximum=500, holder=payload)
            members = payload.get("members")
            if isinstance(members, dict) and isinstance(members.get("items"), list):
                total = members.get("total") if isinstance(members.get("total"), int) else None
                shown = len(members["items"])
                if (total is not None and total > member_offset + shown) or (total is None and shown >= member_limit):
                    _add_more(payload, f"Showing {shown} members{f' of {total}' if total is not None else ''}. "
                                       f"Pass member_offset={member_offset + shown} for the next page.")
        return _dump(payload)
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_catalogue_error(exc, "get_catalogue_family")


@mcp.tool()
async def get_catalogue_specimen(sha256: str) -> str:
    """Get one catalogued specimen: kind, traits, indicators, family and lineage (Pro: genome_clusters).

    Lineage covers the command that fetched it and the hosts that command named
    or reached, what it fetched, the build it replaced and later builds. The
    file itself is never returned.

    Args:
        sha256: Lowercase SHA-256 of the specimen
    """
    try:
        sha256 = _validate_sha256(sha256)
        payload = await _post("/api/v1/blackdome/intelligence/catalogue/specimen", {"sha256": sha256})
        return _dump(payload)
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_catalogue_error(exc, "get_catalogue_specimen")


@mcp.tool()
async def search_catalogue(query: str, limit: int = 20) -> str:
    """Search the specimen catalogue by hash prefix, indicator or family (Pro: genome_clusters).

    Matches a SHA-256 prefix (6+ hex digits), any download host, mining pool,
    wallet or control endpoint containing the text, and family keys and names.
    Sample files are never returned.

    Args:
        query: 4-120 characters
        limit: Maximum specimens and families returned (1-50, default 20)
    """
    try:
        query = _validate_catalogue_query(query)
        limit = min(_validate_positive_int(limit), _CATALOGUE_SEARCH_MAX)
        payload = await _post(
            "/api/v1/blackdome/intelligence/catalogue/search",
            {"query": query, "limit": limit},
        )
        return _dump(_say_if_more(payload, limit, _CATALOGUE_SEARCH_MAX))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_catalogue_error(exc, "search_catalogue")


@mcp.tool()
async def recent_catalogue_specimens(limit: int = 20, offset: int = 0, kind: Optional[str] = None) -> str:
    """List the most recently seen specimens in the shared catalogue (Pro: genome_clusters).

    Each entry gives the specimen's hash, kind, processor, size, first and last
    seen, family and the file names it was saved as.
    Sample files are never returned.

    Args:
        limit: Specimens per page (1-100, default 20)
        offset: Specimens to skip (0-10000)
        kind: Optional filter: script, program, archive or other
    """
    try:
        limit = min(_validate_positive_int(limit), _CATALOGUE_RECENT_MAX)
        offset = _validate_offset(offset)
        if kind is not None and kind not in _CATALOGUE_KINDS:
            raise _CustomerIntelligenceValidationError
        payload = await _get(
            "/api/v1/blackdome/intelligence/catalogue/recent",
            {"limit": limit, "offset": offset, "kind": kind},
        )
        return _dump(_say_if_more(payload, limit, _CATALOGUE_RECENT_MAX, offset_param="offset", offset=offset))
    except _CustomerIntelligenceValidationError:
        return _validation_error()
    except Exception as exc:
        return _format_catalogue_error(exc, "recent_catalogue_specimens")


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
            "explain_ioc, list_notable_sessions, get_session_transcript, "
            "list_detonations, get_detonation_report, get_artifact, whoami, "
            "the specimen catalogue tools, and stix export) will return 401. "
            "Get a key at https://blackdome.ai/pricing.",
            file=sys.stderr,
        )
    mcp.run()


if __name__ == "__main__":
    main()
