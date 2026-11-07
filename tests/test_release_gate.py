"""Release tests must run the artifact, never ambient source or credentials."""

import importlib.util
import json
from pathlib import Path


def load_gate():
    path = Path(__file__).resolve().parents[1] / "scripts/check_release_artifact.py"
    spec = importlib.util.spec_from_file_location("release_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_artifact_environment_excludes_source_injection_and_unrelated_secrets(monkeypatch):
    for key in ("PYTHONPATH", "PYTHONHOME", "OPENAI_API_KEY", "GITHUB_TOKEN",
                "PYPI_API_TOKEN", "BLACKDOME_BASE_URL", "BLACKDOME_API_KEY"):
        monkeypatch.setenv(key, "release-test-secret-or-source")
    monkeypatch.setenv("PATH", "/test/bin")
    result = load_gate()._safe_environment()
    assert result["PATH"] == "/test/bin"
    assert "release-test-secret-or-source" not in result.values()


def test_registry_description_fits_the_registry_validation_contract():
    # Registry /validate rejected the original manifest with description >100.
    manifest = json.loads((Path(__file__).resolve().parents[1] / "server.json").read_text())
    assert 1 <= len(manifest["description"]) <= 100
