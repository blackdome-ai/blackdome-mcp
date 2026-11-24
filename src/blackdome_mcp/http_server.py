"""Streamable-HTTP transport for hosted BlackDome MCP deployments.

Runs the same toolset as the stdio package (`blackdome-mcp`) over HTTP so
customers can connect with a single URL instead of a local install:

    https://api.blackdome.ai/mcp

Per-request authentication: each HTTP request may carry the customer's API key
as `Authorization: Bearer bd_...` (or `X-API-Key: bd_...`). Each tool call is
made with the key on the HTTP request that carried it (never a key remembered
from an earlier request of the session), so one process serves many tenants;
requests without a key still work for the free community tools, except on a
session that began with a key, where a keyless request is refused (401).

Assumption (2026-11-21): nginx's `location ^~ /mcp` on api.blackdome.ai sets X-Real-IP $remote_addr, and this
server binds loopback only (BLACKDOME_MCP_HOST 127.0.0.1), so the X-Real-IP it passes on to the API is nginx's
(scripts/blackdome/check_nginx_real_ip.py checks every location that proxies to port 8901).

Environment:
    BLACKDOME_MCP_HOST  bind address  (default 127.0.0.1; put nginx in front)
    BLACKDOME_MCP_PORT  bind port     (default 8901)
    BLACKDOME_MCP_PATH  URL path      (default /mcp)
    BLACKDOME_BASE_URL  upstream API  (default http://127.0.0.1:7860 for this hosted entry point; the stdio
                        package keeps https://api.blackdome.ai)

Upstream on loopback (2026-11-21, full test 04 finding 4, item D6): through the public host every keyless caller
reached the API as this server's own address, so all keyless hosted users shared one daily allowance. On loopback
the server passes on the caller's address (X-Real-IP from nginx) and each keyless caller is counted as itself.
The tools call only the paths api.blackdome.ai exposes (blackdome_mcp.server._api_path).
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict

from mcp.server.transport_security import TransportSecuritySettings

from blackdome_mcp import server as _server
from blackdome_mcp.server import LIMIT_STATE_KEY, key_from_headers, mcp, set_request_api_key

# The API on this machine. BLACKDOME_BASE_URL, when set, wins.
HOSTED_BASE_URL = "http://127.0.0.1:7860"


def _use_hosted_upstream() -> None:
    """The hosted server calls the API on loopback unless BLACKDOME_BASE_URL says otherwise."""
    configured = os.environ.get("BLACKDOME_BASE_URL", "").strip()
    _server.BASE_URL = (configured or HOSTED_BASE_URL).rstrip("/")

# Hosts/origins allowed by the streamable-HTTP DNS-rebinding protection.
# Override for private deployments.
DEFAULT_ALLOWED_HOSTS = (
    "api.blackdome.ai,blackdome.ai,www.blackdome.ai,localhost,127.0.0.1,test"
)


def _extract_key(scope: dict) -> str:
    """Pull the customer API key from ASGI scope headers, if present."""
    return key_from_headers(scope.get("headers"))


def _header(scope: dict, name: bytes) -> str:
    for raw_name, raw_value in scope.get("headers") or []:
        if bytes(raw_name).lower() == name:
            return bytes(raw_value).decode("latin-1").strip()
    return ""


# Sessions that began with a key (initialize carried one): mcp-session-id -> True. A later request on such a
# session that carries no key is refused as unauthenticated; it is never served on the key the session began with.
# Bounded: the oldest entries go first (an evicted session's keyless requests are then served keyless, i.e. with
# the free tools only, never with a remembered key).
_KEYED_SESSIONS: "OrderedDict[str, bool]" = OrderedDict()
_KEYED_SESSIONS_MAX = 20000

UNAUTHENTICATED_ERROR = {
    "code": -32001,
    "message": (
        "Unauthenticated: this session began with an API key, and this request carries none. Send the key "
        "on every request (Authorization: Bearer <key>)."
    ),
}
UNAUTHENTICATED_BODY = json.dumps({"jsonrpc": "2.0", "id": None, "error": UNAUTHENTICATED_ERROR}).encode()
# The most of a refused POST body read to find its JSON-RPC id (2026-11-21, full test 04 finding 9: the 401 said
# id null instead of the request's id). A longer body is answered with id null.
_REFUSED_BODY_MAX = 1 << 20


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            return body
        body += message.get("body", b"")
        if len(body) > _REFUSED_BODY_MAX:
            return b""
        if not message.get("more_body"):
            return body


def unauthenticated_body(request_body: bytes) -> bytes:
    """The 401 answer, carrying the id of the JSON-RPC request it refuses (one error per request of a batch).

    A notification or response (no id), or a body that is not JSON-RPC, is answered with id null."""
    try:
        parsed = json.loads(request_body) if request_body else None
    except ValueError:
        parsed = None

    def _error_for(message) -> dict:
        request_id = message.get("id") if isinstance(message, dict) else None
        if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
            request_id = None
        return {"jsonrpc": "2.0", "id": request_id, "error": UNAUTHENTICATED_ERROR}

    if isinstance(parsed, list) and parsed:
        return json.dumps([_error_for(message) for message in parsed]).encode()
    return json.dumps(_error_for(parsed)).encode()


def _remember_keyed_session(session_id: str) -> None:
    _KEYED_SESSIONS[session_id] = True
    _KEYED_SESSIONS.move_to_end(session_id)
    while len(_KEYED_SESSIONS) > _KEYED_SESSIONS_MAX:
        _KEYED_SESSIONS.popitem(last=False)


class ApiKeyCapture:
    """ASGI middleware: the per-request API key.

    - Captures the request's key into a contextvar (kept for callers outside a tool call).
    - Records which sessions began with a key, and refuses (401, a JSON-RPC error) a later request on such a
      session that carries no key. The key itself is never stored or logged: only the session id.
    Each tool call is made with the key on the request that carried it (blackdome_mcp.server.current_api_key).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        key = _extract_key(scope)
        session_id = _header(scope, b"mcp-session-id")
        method = scope.get("method")
        if session_id and not key and method in ("POST", "GET") and _KEYED_SESSIONS.get(session_id):
            body = UNAUTHENTICATED_BODY
            if method == "POST":
                body = unauthenticated_body(await _read_body(receive))
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")],
            })
            await send({"type": "http.response.body", "body": body})
            return

        async def send_noting_session(message):
            if message.get("type") == "http.response.start" and key and not session_id:
                for raw_name, raw_value in message.get("headers") or []:
                    if bytes(raw_name).lower() == b"mcp-session-id":
                        _remember_keyed_session(bytes(raw_value).decode("latin-1").strip())
            await send(message)

        token = set_request_api_key(key)
        try:
            await self.app(scope, receive, send_noting_session)
        finally:
            from blackdome_mcp.server import _REQUEST_API_KEY

            _REQUEST_API_KEY.reset(token)


class LimitHeaders:
    """ASGI middleware: the caller's allowance headers on every HTTP answer to a request that carries a key.

    The daily headers (RateLimit-Limit, -Remaining, -Reset, -Policy) and the minute headers
    (X-RateLimit-Minute-Limit, -Remaining, -Reset), as on every keyed answer of the REST API (walkthrough
    2026-11-23, item 13). A tool's API calls leave the values they were answered with in a dict in this request's
    scope state (blackdome_mcp.server._record_limit). A streamed (SSE) answer would send its headers before the
    tool has run, so for a POST the start of the answer is held back until its first body chunk. An answer that
    made no API call (initialize, the tool list, a notification, the GET event stream, DELETE) reuses the values
    this key was answered with in the last few seconds, else reads its allowances from the API without spending
    them (blackdome_mcp.server.allowance_headers). An answer that already names a header keeps its own. A request
    without a key gets none.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        key = _extract_key(scope)
        holder: dict = {}
        state = scope.setdefault("state", {})
        state[LIMIT_STATE_KEY] = holder
        held: list[dict] = []
        hold_until_body = scope.get("method") == "POST"

        async def with_limit(start: dict) -> dict:
            info = holder.get("info")
            values = dict(info["headers"]) if info else {}
            if key and values:
                # A tool call's own answer: the freshest values, reused by this key's next answers that make no call.
                _server.remember_allowances(key, values)
            if key and not values:
                values = await _server.allowance_headers(key, _header(scope, b"x-real-ip") or None)
            if not values:
                return start
            raw = list(start.get("headers") or [])
            present = {bytes(name).lower() for name, _ in raw}
            for name, value in values.items():
                header = name.lower().encode("latin-1")
                if header not in present:
                    raw.append((header, str(value).encode("latin-1")))
            return {**start, "headers": raw}

        async def send_with_limit(message):
            if message.get("type") == "http.response.start":
                if hold_until_body:
                    held.append(message)
                    return
                await send(await with_limit(message))
                return
            if held and message.get("type") == "http.response.body":
                await send(await with_limit(held.pop()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_limit)
        finally:
            if held:
                await send(await with_limit(held.pop()))


def create_http_app():
    """Build the streamable-HTTP ASGI app with per-request key capture."""
    path = os.environ.get("BLACKDOME_MCP_PATH", "/mcp")
    allowed = [
        host.strip()
        for host in os.environ.get(
            "BLACKDOME_MCP_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS
        ).split(",")
        if host.strip()
    ]
    _use_hosted_upstream()
    mcp.settings.streamable_http_path = path
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=allowed,
    )
    return ApiKeyCapture(LimitHeaders(mcp.streamable_http_app()))


def main() -> None:
    """Entrypoint for the `blackdome-mcp-http` console script."""
    import uvicorn

    host = os.environ.get("BLACKDOME_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("BLACKDOME_MCP_PORT", "8901"))
    app = create_http_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
