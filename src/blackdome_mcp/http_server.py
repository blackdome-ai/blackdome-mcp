"""Streamable-HTTP transport for hosted BlackDome MCP deployments.

Runs the same toolset as the stdio package (`blackdome-mcp`) over HTTP so
customers can connect with a single URL instead of a local install:

    https://api.blackdome.ai/mcp

Per-request authentication: each HTTP request may carry the customer's API key
as `Authorization: Bearer bd_...` (or `X-API-Key: bd_...`). The ASGI
middleware below captures it into a contextvar that `_headers()` reads, so one
process serves many tenants; requests without a key still work for the free
community tools.

Environment:
    BLACKDOME_MCP_HOST  bind address  (default 127.0.0.1; put nginx in front)
    BLACKDOME_MCP_PORT  bind port     (default 8901)
    BLACKDOME_MCP_PATH  URL path      (default /mcp)
    BLACKDOME_BASE_URL  upstream API  (default https://api.blackdome.ai)
"""

from __future__ import annotations

import os

from mcp.server.transport_security import TransportSecuritySettings

from blackdome_mcp.server import mcp, set_request_api_key

# Hosts/origins allowed by the streamable-HTTP DNS-rebinding protection.
# Override for private deployments.
DEFAULT_ALLOWED_HOSTS = (
    "api.blackdome.ai,blackdome.ai,www.blackdome.ai,localhost,127.0.0.1,test"
)


def _extract_key(scope: dict) -> str:
    """Pull the customer API key from ASGI scope headers, if present."""
    authorization = ""
    x_api_key = ""
    for raw_name, raw_value in scope.get("headers") or []:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1").strip()
        if name == "authorization":
            authorization = value
        elif name == "x-api-key":
            x_api_key = value
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if authorization:
        return authorization
    return x_api_key


class ApiKeyCapture:
    """ASGI middleware: capture the per-request API key into a contextvar."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            token = set_request_api_key(_extract_key(scope))
            try:
                await self.app(scope, receive, send)
            finally:
                from blackdome_mcp.server import _REQUEST_API_KEY

                _REQUEST_API_KEY.reset(token)
        else:
            await self.app(scope, receive, send)


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
    mcp.settings.streamable_http_path = path
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=allowed,
    )
    return ApiKeyCapture(mcp.streamable_http_app())


def main() -> None:
    """Entrypoint for the `blackdome-mcp-http` console script."""
    import uvicorn

    host = os.environ.get("BLACKDOME_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("BLACKDOME_MCP_PORT", "8901"))
    app = create_http_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
