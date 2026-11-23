"""The package text says what docs/blackdome/OFFER.md says (sweep 2026-11-21).

The tool list omits retired features and uses the offer wording.
"""

import asyncio
import re
from pathlib import Path

import blackdome_mcp.server as server
from blackdome_mcp import plans

ROOT = Path(__file__).resolve().parents[1]
TEXTS = {
    "server.py": (ROOT / "src" / "blackdome_mcp" / "server.py").read_text(),
    "README.md": (ROOT / "README.md").read_text(),
    "CHANGELOG.md": (ROOT / "CHANGELOG.md").read_text(),
    "server.json": (ROOT / "server.json").read_text(),
}


def test_no_text_sells_explanations():
    for name, text in TEXTS.items():
        if name == "CHANGELOG.md":
            continue
        assert not re.search(r"\bexplanations?\b", text.replace("ioc_explanation", ""), re.I), name


def test_retired_warboard_is_absent_from_the_tool_list_and_customer_docs():
    tools = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert "warboard" not in tools
    for name, text in TEXTS.items():
        if name == "CHANGELOG.md":
            continue  # the changelog must be able to say which tool was removed
        assert "warboard" not in text.lower(), name


def test_tool_descriptions_and_the_denial_sentence_use_the_offers_words():
    tools = {tool.name: tool.description for tool in asyncio.run(server.mcp.list_tools())}
    assert tools["explain_ioc"].startswith("An evidence record for an indicator in our malware graph")
    denied = server._denied_reason("feature not included", "explain_ioc")
    assert "explain_ioc needs Threat Intel Analyst (US$99 a month, 14-day free trial) or higher" in denied
    assert "no plan on sale" not in denied


def test_session_summary_and_transcript_have_different_access():
    assert plans.TOOL_ACCESS["list_notable_sessions"] == ("analyst", "pro")
    assert plans.TOOL_ACCESS["get_session_transcript"] == plans.NONE
