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
"""Tool discovery (kept for compatibility) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import ProofpointClient, ProofpointError
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

# A threat id that cannot exist: the Threat API has no quota, and its answer
# (401 versus 404 / 400) tells whether the credentials are accepted.
_PROBE_THREAT = "0" * 64

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "tap": (
        "SIEM feed: threat messages delivered / blocked and malicious URL clicks permitted / blocked.",
        [
            "proofpoint_tap_get_all_threats",
            "proofpoint_tap_get_messages_delivered",
            "proofpoint_tap_get_messages_blocked",
            "proofpoint_tap_get_clicks_permitted",
            "proofpoint_tap_get_clicks_blocked",
        ],
    ),
    "events": (
        "The same SIEM events as one filtered list, one event's detail, and window statistics.",
        ["proofpoint_events_list", "proofpoint_events_get_details", "proofpoint_events_get_stats"],
    ),
    "smart_search": (
        "Find threat messages by sender, recipient, subject or Message-ID; message record and header fields.",
        ["proofpoint_smart_search_trace", "proofpoint_smart_search_get_message", "proofpoint_smart_search_get_headers"],
    ),
    "forensics": (
        "Sandbox forensics for a threat or campaign, and message search. Message pull is unavailable.",
        [
            "proofpoint_forensics_get_threat",
            "proofpoint_forensics_get_campaign",
            "proofpoint_forensics_search_messages",
            "proofpoint_forensics_pull_messages",
        ],
    ),
    "threat_intel": (
        "Threat summaries, campaigns, malware families / actors in recent campaigns, and IOCs.",
        [
            "proofpoint_threat_get_by_id",
            "proofpoint_threat_get_campaign",
            "proofpoint_threat_list_families",
            "proofpoint_threat_get_iocs",
        ],
    ),
    "people": (
        "Very Attacked People, top clickers, and one user's risk.",
        ["proofpoint_people_get_vap", "proofpoint_people_get_top_clickers", "proofpoint_people_get_user_risk"],
    ),
    "url_defense": (
        "Decode URL Defense rewritten links and break a link down.",
        ["proofpoint_url_decode", "proofpoint_url_analyze"],
    ),
    "reports": (
        "Dashboard reports (separate Reports API key): protection overview, threat categories, trend, executive.",
        [
            "proofpoint_reports_org_summary",
            "proofpoint_reports_threat_summary",
            "proofpoint_reports_mail_flow",
            "proofpoint_reports_executive_summary",
        ],
    ),
    "quarantine": (
        "Unavailable: quarantine is not exposed by the TAP API.",
        [
            "proofpoint_quarantine_list",
            "proofpoint_quarantine_search",
            "proofpoint_quarantine_release",
            "proofpoint_quarantine_delete",
        ],
    ),
    "policy": (
        "Unavailable: policies and routes are not exposed by the TAP API.",
        ["proofpoint_policy_list", "proofpoint_policy_get", "proofpoint_policy_list_routes"],
    ),
    "dlp": (
        "Unavailable: DLP and encryption are not part of the TAP API.",
        ["proofpoint_dlp_list_incidents", "proofpoint_dlp_get_incident", "proofpoint_dlp_list_encrypted"],
    ),
}

DomainName = Literal[
    "tap", "events", "smart_search", "forensics", "threat_intel", "people", "url_defense", "reports",
    "quarantine", "policy", "dlp",
]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def proofpoint_navigate(domain: Annotated[DomainName, Field(description="Area to describe.")]) -> str:
        """Describe the tools of one Proofpoint area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_status() -> str:
        """Check the credentials: whether TAP accepts the service principal and whether Reports keys were sent."""

        async def action(client: ProofpointClient) -> dict:
            tap: dict
            try:
                await client.tap("GET", f"/v2/threat/summary/{_PROBE_THREAT}")
                tap = {"authorized": True}
            except ProofpointError as e:
                if e.status_code in (401, 403):
                    tap = {"authorized": False, "error": e.message}
                elif e.status_code in (400, 404):
                    tap = {"authorized": True}
                else:
                    tap = {"authorized": None, "error": e.message}
            return {
                "tap": tap,
                "reports_credentials_sent": client.has_reports_credentials,
                "domains": {name: summary for name, (summary, _tools) in DOMAINS.items()},
            }

        return await run_tool("proofpoint_status", client_factory, action)
