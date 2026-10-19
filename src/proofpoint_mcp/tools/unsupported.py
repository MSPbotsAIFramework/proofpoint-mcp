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
"""Tools kept for compatibility whose data the TAP API does not expose.

Quarantine, policy, DLP / encryption and message pull belong to other
Proofpoint products (Protection Server, Essentials, Threat Response). These
tools change nothing and answer with an error that points to what TAP does
offer, so an agent learns the limit instead of getting invented data.
"""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import error_envelope
from ._common import LOCAL, ClientFactory

QUARANTINE = (
    "Quarantine is managed in Proofpoint Protection Server / Essentials, which the TAP API does not expose. "
    "Blocked threat messages, with their quarantineFolder and quarantineRule, are in "
    "proofpoint_tap_get_messages_blocked."
)
POLICY = (
    "Mail policies and routes are not exposed by the TAP API. Each SIEM message event lists the policyRoutes "
    "and modulesRun that applied to it (proofpoint_smart_search_get_message)."
)
DLP = "DLP incidents and encrypted-message logs are not part of the TAP API."
PULL = (
    "Pulling delivered messages from mailboxes is done by Proofpoint Threat Response, which has no TAP API. "
    "Delivered threat messages to remediate are listed by proofpoint_tap_get_messages_delivered."
)

Page = Annotated[int | None, Field(description="Page number.")]
PerPage = Annotated[int | None, Field(description="Results per page.")]
Date = Annotated[str | None, Field(description="ISO8601 date-time (UTC).")]
Text = Annotated[str | None, Field(description="Filter text.")]


def unavailable(reason: str) -> str:
    return error_envelope("invalid_argument", f"Not available: {reason}", False)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:  # noqa: ARG001 - no API calls here
    @mcp.tool(annotations=LOCAL)
    async def proofpoint_quarantine_list(
        sender: Text = None,
        recipient: Text = None,
        subject: Text = None,
        startDate: Date = None,
        endDate: Date = None,
        folder: Annotated[
            Literal["SPAM", "VIRUS", "POLICY", "BULK", "PHISH", "ADMIN", "IMPOSTOR"] | None,
            Field(description="Quarantine folder."),
        ] = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Not available through the TAP API; returns an error naming the alternative.

        For blocked threat messages and their quarantine folder use proofpoint_tap_get_messages_blocked.
        """
        return unavailable(QUARANTINE)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_quarantine_search(
        query: Annotated[str, Field(description="Search text.")],
        startDate: Date = None,
        endDate: Date = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Not available through the TAP API; returns an error naming the alternative.

        To find a threat message use proofpoint_smart_search_trace.
        """
        return unavailable(QUARANTINE)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_quarantine_release(
        message_id: Annotated[str, Field(description="Quarantined message id.")],
    ) -> str:
        """Not available through the TAP API (changes nothing); release messages in the quarantine console."""
        return unavailable(QUARANTINE)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_quarantine_delete(
        message_id: Annotated[str, Field(description="Quarantined message id.")],
    ) -> str:
        """Not available through the TAP API (changes nothing); delete messages in the quarantine console."""
        return unavailable(QUARANTINE)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_policy_list(
        type: Annotated[Literal["inbound", "outbound", "internal"] | None, Field(description="Policy direction.")] = None,
    ) -> str:
        """Not available through the TAP API; returns an error naming the alternative."""
        return unavailable(POLICY)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_policy_get(policy_id: Annotated[str, Field(description="Policy id.")]) -> str:
        """Not available through the TAP API; returns an error naming the alternative."""
        return unavailable(POLICY)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_policy_list_routes(page: Page = None, per_page: PerPage = None) -> str:
        """Not available through the TAP API; message events carry their policyRoutes instead."""
        return unavailable(POLICY)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_dlp_list_incidents(
        startDate: Date = None,
        endDate: Date = None,
        severity: Annotated[
            Literal["critical", "high", "medium", "low", "info"] | None, Field(description="Severity.")
        ] = None,
        status: Annotated[Literal["open", "resolved", "false_positive"] | None, Field(description="Status.")] = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Not available through the TAP API; returns an error."""
        return unavailable(DLP)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_dlp_get_incident(incident_id: Annotated[str, Field(description="Incident id.")]) -> str:
        """Not available through the TAP API; returns an error."""
        return unavailable(DLP)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_dlp_list_encrypted(
        startDate: Date = None,
        endDate: Date = None,
        sender: Text = None,
        recipient: Text = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Not available through the TAP API; returns an error."""
        return unavailable(DLP)

    @mcp.tool(annotations=LOCAL)
    async def proofpoint_forensics_pull_messages(
        message_ids: Annotated[list[str], Field(description="Message ids to pull from mailboxes.")],
        reason: Text = None,
    ) -> str:
        """Not available through the TAP API (changes nothing); pull messages with Threat Response.

        Delivered threat messages to remediate: proofpoint_tap_get_messages_delivered.
        """
        return unavailable(PULL)
