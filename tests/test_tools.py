# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""tools/list snapshot and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from proofpoint_mcp.api_client import ProofpointError
from proofpoint_mcp.server import INSTRUCTIONS, create_mcp_server
from proofpoint_mcp.tools.navigation import DOMAINS

# Tool names and required parameters are a public contract: existing agents
# and tenant connections depend on them. Changing this snapshot is breaking.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "proofpoint_navigate": {"domain"},
    "proofpoint_status": set(),
    "proofpoint_tap_get_all_threats": set(),
    "proofpoint_tap_get_messages_delivered": set(),
    "proofpoint_tap_get_messages_blocked": set(),
    "proofpoint_tap_get_clicks_permitted": set(),
    "proofpoint_tap_get_clicks_blocked": set(),
    "proofpoint_events_list": set(),
    "proofpoint_events_get_details": {"event_id"},
    "proofpoint_events_get_stats": set(),
    "proofpoint_smart_search_trace": set(),
    "proofpoint_smart_search_get_message": {"message_id"},
    "proofpoint_smart_search_get_headers": {"message_id"},
    "proofpoint_forensics_get_threat": {"threat_id"},
    "proofpoint_forensics_get_campaign": {"campaign_id"},
    "proofpoint_forensics_search_messages": set(),
    "proofpoint_forensics_pull_messages": {"message_ids"},
    "proofpoint_threat_get_by_id": {"threat_id"},
    "proofpoint_threat_get_campaign": {"campaign_id"},
    "proofpoint_threat_list_families": set(),
    "proofpoint_threat_get_iocs": set(),
    "proofpoint_people_get_vap": set(),
    "proofpoint_people_get_top_clickers": set(),
    "proofpoint_people_get_user_risk": {"email"},
    "proofpoint_url_decode": {"urls"},
    "proofpoint_url_analyze": {"url"},
    "proofpoint_reports_org_summary": set(),
    "proofpoint_reports_threat_summary": set(),
    "proofpoint_reports_mail_flow": set(),
    "proofpoint_reports_executive_summary": set(),
    "proofpoint_quarantine_list": set(),
    "proofpoint_quarantine_search": {"query"},
    "proofpoint_quarantine_release": {"message_id"},
    "proofpoint_quarantine_delete": {"message_id"},
    "proofpoint_policy_list": set(),
    "proofpoint_policy_get": {"policy_id"},
    "proofpoint_policy_list_routes": set(),
    "proofpoint_dlp_list_incidents": set(),
    "proofpoint_dlp_get_incident": {"incident_id"},
    "proofpoint_dlp_list_encrypted": set(),
}

UNSUPPORTED = {
    "proofpoint_quarantine_list": {},
    "proofpoint_quarantine_search": {"query": "x"},
    "proofpoint_quarantine_release": {"message_id": "m"},
    "proofpoint_quarantine_delete": {"message_id": "m"},
    "proofpoint_policy_list": {},
    "proofpoint_policy_get": {"policy_id": "p"},
    "proofpoint_policy_list_routes": {},
    "proofpoint_dlp_list_incidents": {},
    "proofpoint_dlp_get_incident": {"incident_id": "i"},
    "proofpoint_dlp_list_encrypted": {},
    "proofpoint_forensics_pull_messages": {"message_ids": ["m"]},
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_all_tools_listed(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_tool_is_read_only(tools, name):
    # No tool changes Proofpoint data: the write-style tools are unavailable stubs.
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True
    assert not annotations.destructiveHint


def test_navigation_covers_every_tool():
    listed = {tool for _summary, names in DOMAINS.values() for tool in names}
    assert listed | {"proofpoint_navigate", "proofpoint_status"} == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(UNSUPPORTED))
def test_unsupported_tools_explain_and_need_no_credentials(name):
    content, _ = asyncio.run(create_mcp_server().call_tool(name, UNSUPPORTED[name]))
    error = json.loads(content[0].text)["error"]
    assert error["code"] == "invalid_argument"
    assert error["message"].startswith("Not available:")
    assert error["retryable"] is False


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 2000


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (429, "rate_limited", False),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(ProofpointError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("proofpoint_tap_get_all_threats", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


def test_navigate_needs_no_credentials():
    content, _ = asyncio.run(create_mcp_server().call_tool("proofpoint_navigate", {"domain": "url_defense"}))
    assert json.loads(content[0].text)["tools"] == ["proofpoint_url_decode", "proofpoint_url_analyze"]


@pytest.mark.parametrize("name", ["proofpoint_people_get_vap", "proofpoint_people_get_top_clickers"])
def test_people_page_size_capped_at_200_default_50(tools, name):
    schema = tools[name].inputSchema["properties"]["size"]
    assert schema["maximum"] == 200 and schema["default"] == 50
