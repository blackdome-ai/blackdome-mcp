#!/usr/bin/env python3
"""Build and smoke-test the immutable BlackDome MCP release artifacts offline."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Sequence


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.4.0"
PACKAGE_NAME = "blackdome-mcp"
EXPECTED_TOOLS = (
    "lookup_attacker_ip",
    "top_attackers",
    "attack_map",
    "attack_heatmap",
    "credential_preview",
    "verify_sigil",
    "recent_iocs",
    "ioc_trends",
    "export_iocs",
    "search_credentials",
    "credential_stats",
    "list_payloads",
    "get_actor",
    "warboard",
    "list_notable_sessions",
    "get_session_transcript",
    "list_detonations",
    "get_detonation_report",
    "get_artifact",
    "whoami",
    "explain_ioc",
    "compare_samples",
    "get_evidence_cluster",
    "get_reproducible_novelty",
    "get_threatdrop_case",
    "get_takedown_status",
)


class ReleaseArtifactError(RuntimeError):
    """A built release artifact does not satisfy the immutable release contract."""


def _safe_environment() -> dict[str, str]:
    """Prevent package/release credentials from entering the isolated smoke process."""
    allowed = {"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "UV_CACHE_DIR", "UV_PYTHON_DOWNLOADS"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _run(command: Sequence[str], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=180,
    )
    if completed.returncode:
        command_text = " ".join(command)
        raise ReleaseArtifactError(
            "command failed: {command}\nstdout:\n{stdout}\nstderr:\n{stderr}".format(
                command=command_text,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        )


def _assert_metadata(metadata_bytes: bytes, artifact_name: str) -> None:
    metadata = BytesParser(policy=policy.default).parsebytes(metadata_bytes)
    if metadata["Name"] != PACKAGE_NAME:
        raise ReleaseArtifactError(
            "{artifact} has package name {actual!r}, expected {expected!r}".format(
                artifact=artifact_name,
                actual=metadata["Name"],
                expected=PACKAGE_NAME,
            )
        )
    if metadata["Version"] != RELEASE_VERSION:
        raise ReleaseArtifactError(
            "{artifact} has version {actual!r}, expected {expected!r}".format(
                artifact=artifact_name,
                actual=metadata["Version"],
                expected=RELEASE_VERSION,
            )
        )
    requires_dist = set(metadata.get_all("Requires-Dist", []))
    if "mcp[cli]<2.0.0,>=1.30.0" not in requires_dist:
        raise ReleaseArtifactError(
            "{artifact} does not preserve the supported MCP dependency range".format(
                artifact=artifact_name
            )
        )


def _assert_wheel(wheel: Path) -> None:
    expected_paths = {
        "blackdome_mcp/__init__.py",
        "blackdome_mcp/server.py",
        "blackdome_mcp/http_server.py",
        "blackdome_mcp-{version}.dist-info/METADATA".format(version=RELEASE_VERSION),
        "blackdome_mcp-{version}.dist-info/entry_points.txt".format(version=RELEASE_VERSION),
    }
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        missing = expected_paths - names
        if missing:
            raise ReleaseArtifactError(
                "wheel is missing required paths: {paths}".format(paths=sorted(missing))
            )
        _assert_metadata(
            archive.read(
                "blackdome_mcp-{version}.dist-info/METADATA".format(
                    version=RELEASE_VERSION
                )
            ),
            wheel.name,
        )
        entry_points = archive.read(
            "blackdome_mcp-{version}.dist-info/entry_points.txt".format(
                version=RELEASE_VERSION
            )
        ).decode()
    expected_entry_points = {
        "blackdome-mcp = blackdome_mcp.server:main",
        "blackdome-mcp-http = blackdome_mcp.http_server:main",
    }
    if not expected_entry_points.issubset(set(entry_points.splitlines())):
        raise ReleaseArtifactError("wheel is missing one or more console entry points")


def _assert_sdist(sdist: Path) -> None:
    root = "blackdome_mcp-{version}".format(version=RELEASE_VERSION)
    expected_paths = {
        "{root}/PKG-INFO".format(root=root),
        "{root}/README.md".format(root=root),
        "{root}/pyproject.toml".format(root=root),
        "{root}/server.json".format(root=root),
        "{root}/src/blackdome_mcp/__init__.py".format(root=root),
        "{root}/src/blackdome_mcp/server.py".format(root=root),
        "{root}/src/blackdome_mcp/http_server.py".format(root=root),
    }
    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        missing = expected_paths - names
        if missing:
            raise ReleaseArtifactError(
                "sdist is missing required paths: {paths}".format(paths=sorted(missing))
            )
        metadata_member = archive.extractfile("{root}/PKG-INFO".format(root=root))
        if metadata_member is None:
            raise ReleaseArtifactError("sdist does not contain PKG-INFO")
        _assert_metadata(metadata_member.read(), sdist.name)


def _smoke_installed_wheel(
    uv: str,
    wheel: Path,
    temporary_root: Path,
    environment: dict[str, str],
    mcp_version: str | None,
) -> None:
    venv = temporary_root / "venv"
    _run([sys.executable, "-m", "venv", str(venv)], cwd=PACKAGE_ROOT, environment=environment)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    if mcp_version:
        _run(
            [
                uv,
                "pip",
                "install",
                "--offline",
                "--python",
                str(python),
                "mcp[cli]=={version}".format(version=mcp_version),
                "httpx>=0.27.0",
                "uvicorn>=0.30.0",
            ],
            cwd=PACKAGE_ROOT,
            environment=environment,
        )
        install_command = [
            uv,
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--python",
            str(python),
            str(wheel),
        ]
    else:
        install_command = [
            uv,
            "pip",
            "install",
            "--offline",
            "--python",
            str(python),
            str(wheel),
        ]
    _run(install_command, cwd=PACKAGE_ROOT, environment=environment)

    smoke_code = """
import asyncio
from importlib import import_module, metadata
from pathlib import Path
import sys
import httpx

assert metadata.version("blackdome-mcp") == "0.4.0"
console_scripts = {
    entry.name: entry.value
    for entry in metadata.distribution("blackdome-mcp").entry_points
    if entry.group == "console_scripts"
}
assert console_scripts["blackdome-mcp"] == "blackdome_mcp.server:main"
assert console_scripts["blackdome-mcp-http"] == "blackdome_mcp.http_server:main"
server = import_module("blackdome_mcp.server")
assert Path(server.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
http_server = import_module("blackdome_mcp.http_server")
assert callable(server.main)
assert callable(http_server.main)
tools = asyncio.run(server.mcp.list_tools())
names = tuple(tool.name for tool in tools)
assert names == __EXPECTED_TOOLS__
assert len(names) == 26
assert len(set(names)) == 26
assert callable(http_server.create_http_app())

class LifespanDriver:
    def __init__(self, app):
        self.app = app
        self.inbox = [{"type": "lifespan.startup"}]
        self.responses = []
        self.task = None

    async def __aenter__(self):
        async def receive():
            while not self.inbox:
                await asyncio.sleep(0.01)
            return self.inbox.pop(0)

        async def send(message):
            self.responses.append(message)

        self.task = asyncio.create_task(self.app({"type": "lifespan"}, receive, send))
        while not any(item["type"] == "lifespan.startup.complete" for item in self.responses):
            if any(item["type"] == "lifespan.startup.failed" for item in self.responses):
                raise RuntimeError("lifespan startup failed")
            await asyncio.sleep(0.01)
        return self

    async def __aexit__(self, *exc):
        self.inbox.append({"type": "lifespan.shutdown"})
        try:
            await asyncio.wait_for(self.task, timeout=5)
        except BaseException:
            self.task.cancel()

async def hosted_flow():
    server.API_KEY = ""
    captured = []

    def upstream_handler(request):
        captured.append(request)
        return httpx.Response(200, json={"items": [], "count": 0})

    upstream_transport = httpx.MockTransport(upstream_handler)
    real_client = server.httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = upstream_transport
        return real_client(*args, **kwargs)

    server.httpx.AsyncClient = client_factory
    try:
        app = http_server.create_http_app()
        async with LifespanDriver(app):
            asgi_transport = httpx.ASGITransport(app=app)
            async with real_client(transport=asgi_transport, base_url="http://test") as client:
                initialize_headers = {
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "Authorization": "Bearer bd_customer_key",
                }
                initialize = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "release-gate", "version": "1.0"},
                        },
                    },
                    headers=initialize_headers,
                )
                assert initialize.status_code == 200
                session_id = initialize.headers.get("mcp-session-id")
                assert session_id
                session_headers = {
                    **initialize_headers,
                    "Mcp-Session-Id": session_id,
                }
                initialized = await client.post(
                    "/mcp",
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=session_headers,
                )
                assert initialized.status_code in {200, 202}
                tool_call = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "top_attackers",
                            "arguments": {"days": 1},
                        },
                    },
                    headers=session_headers,
                )
                assert tool_call.status_code == 200
        assert captured
        assert captured[-1].headers.get("Authorization") == "Bearer bd_customer_key"
    finally:
        server.httpx.AsyncClient = real_client

asyncio.run(hosted_flow())
requested_mcp = __REQUESTED_MCP__
if requested_mcp is not None:
    assert metadata.version("mcp") == requested_mcp
print("installed artifact imports, tool contract, and hosted flow: ok")
"""
    smoke_code = smoke_code.replace("__EXPECTED_TOOLS__", repr(EXPECTED_TOOLS))
    smoke_code = smoke_code.replace("__REQUESTED_MCP__", repr(mcp_version))
    _run(
        [str(python), "-I", "-c", smoke_code],
        cwd=temporary_root,
        environment=environment,
    )


def check_release_artifact(mcp_version: str | None = None) -> None:
    """Build and validate release artifacts without network or credentials."""
    uv = shutil.which("uv")
    if uv is None:
        raise ReleaseArtifactError("uv is required to build and install release artifacts")
    environment = _safe_environment()
    with tempfile.TemporaryDirectory(prefix="blackdome-mcp-release-") as temporary:
        temporary_root = Path(temporary)
        dist = temporary_root / "dist"
        _run(
            [uv, "build", "--offline", "--out-dir", str(dist)],
            cwd=PACKAGE_ROOT,
            environment=environment,
        )
        wheel = next(dist.glob("blackdome_mcp-{version}-*.whl".format(version=RELEASE_VERSION)), None)
        sdist = dist / "blackdome_mcp-{version}.tar.gz".format(version=RELEASE_VERSION)
        if wheel is None or not sdist.is_file():
            raise ReleaseArtifactError("build did not create the expected 0.4.0 wheel and sdist")
        _assert_wheel(wheel)
        _assert_sdist(sdist)
        _smoke_installed_wheel(uv, wheel, temporary_root, environment, mcp_version)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mcp-version",
        help="Install this exact MCP version before the isolated artifact smoke.",
    )
    arguments = parser.parse_args()
    try:
        check_release_artifact(arguments.mcp_version)
    except ReleaseArtifactError as error:
        print("release artifact gate failed: {error}".format(error=error), file=sys.stderr)
        return 1
    suffix = "mcp={version}".format(version=arguments.mcp_version or "locked")
    print("release artifact gate passed: version={version}, {suffix}, hosted_flow=ok".format(
        version=RELEASE_VERSION,
        suffix=suffix,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
