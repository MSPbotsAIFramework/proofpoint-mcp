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
"""Message search over SIEM events (TAP has no separate message-trace API)."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Interval,
    Offset,
    SinceSeconds,
    SinceTime,
    dates_window,
    fetch_siem,
    locate,
    resume_fields,
    run_tool,
    siem_window,
)
from .tap import flatten, matches_id

HEADER_FIELDS = (
    "messageID",
    "subject",
    "fromAddress",
    "headerFrom",
    "sender",
    "replyToAddress",
    "headerReplyTo",
    "toAddresses",
    "ccAddresses",
    "recipient",
    "xmailer",
    "senderIP",
    "messageTime",
    "QID",
    "GUID",
    "messageSize",
)

StartDate = Annotated[str | None, Field(description="ISO8601 start (UTC). The SIEM search covers at most one hour.")]
EndDate = Annotated[str | None, Field(description="ISO8601 end (UTC), at most one hour after startDate.")]
MessageId = Annotated[str, Field(description="Message-ID header value, event GUID or QID.")]


def _values(event: dict, *fields: str) -> list[str]:
    out: list[str] = []
    for field in fields:
        value = event.get(field)
        for item in value if isinstance(value, list) else [value]:
            if item:
                out.append(str(item).lower())
    return out


def _has(event: dict, needle: str | None, *fields: str) -> bool:
    if not needle:
        return True
    text = needle.strip().lower()
    return any(text in value for value in _values(event, *fields))


def search_events(
    events: list[dict],
    sender: str | None = None,
    recipient: str | None = None,
    subject: str | None = None,
    message_id: str | None = None,
    threat_id: str | None = None,
) -> list[dict]:
    out = []
    for e in events:
        if not _has(e, sender, "sender", "fromAddress", "headerFrom"):
            continue
        if not _has(e, recipient, "recipient", "toAddresses", "ccAddresses"):
            continue
        if not _has(e, subject, "subject"):
            continue
        if message_id and not matches_id(e, message_id):
            continue
        if threat_id:
            ids = {str(t.get("threatID") or "") for t in e.get("threatsInfoMap") or [] if isinstance(t, dict)}
            ids.add(str(e.get("threatID") or ""))
            if threat_id.strip() not in ids:
                continue
        out.append(e)
    return out


async def _find_message(client: ProofpointClient, message_id: str, window: list) -> dict:
    if not message_id.strip():
        raise ValueError("message_id must not be blank.")
    payload = await fetch_siem(client, "all", window)
    messages = [e for e in flatten(payload) if e["eventType"].startswith("message") and matches_id(e, message_id)]
    if not messages:
        raise ValueError(
            f"No threat message {message_id!r} in this window. Only messages with a TAP threat are visible; "
            "pass the interval in which the event was created."
        )
    return messages[0]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_forensics_search_messages(
        sender: Annotated[str | None, Field(description="Part of the sender address.")] = None,
        subject: Annotated[str | None, Field(description="Part of the subject.")] = None,
        message_id: Annotated[str | None, Field(description="Exact Message-ID, GUID or QID.")] = None,
        threat_id: Annotated[str | None, Field(description="Exact TAP threatID carried by the message.")] = None,
        startDate: StartDate = None,
        endDate: EndDate = None,
        limit: Annotated[int, Field(description="Maximum results (1-200).", ge=1, le=200)] = 50,
    ) -> str:
        """Find threat messages by sender, subject, Message-ID or threat id within one hour of SIEM events.

        Only messages that carried a TAP-detected threat are searchable. Default window: the last hour.
        """

        async def action(client: ProofpointClient) -> dict:
            payload = await fetch_siem(client, "all", dates_window(startDate, endDate))
            events = [e for e in flatten(payload) if e["eventType"].startswith("message")]
            found = search_events(events, sender=sender, subject=subject, message_id=message_id, threat_id=threat_id)
            return {"count": len(found), "messages": found[:limit], "has_more": len(found) > limit}

        return await run_tool("proofpoint_forensics_search_messages", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_smart_search_trace(
        sender: Annotated[str | None, Field(description="Part of the sender address.")] = None,
        recipient: Annotated[str | None, Field(description="Part of a recipient address.")] = None,
        subject: Annotated[str | None, Field(description="Part of the subject.")] = None,
        message_id: Annotated[str | None, Field(description="Exact Message-ID, GUID or QID.")] = None,
        startDate: StartDate = None,
        endDate: EndDate = None,
        status: Annotated[
            Literal["delivered", "quarantined", "rejected", "all"],
            Field(description="delivered, quarantined / rejected (both = blocked by TAP) or all."),
        ] = "all",
        page: Annotated[int, Field(description="Page number, from 1.", ge=1)] = 1,
        per_page: Annotated[int, Field(description="Results per page (1-200).", ge=1, le=200)] = 50,
        offset: Offset = None,
    ) -> str:
        """Trace threat messages by sender, recipient, subject or Message-ID, with their delivery outcome.

        Searches one hour of TAP SIEM events (default the last hour); clean mail is not in TAP.
        """

        async def action(client: ProofpointClient) -> dict:
            payload = await fetch_siem(client, "all", dates_window(startDate, endDate))
            events = [e for e in flatten(payload) if e["eventType"].startswith("message")]
            if status == "delivered":
                events = [e for e in events if e["eventType"] == "messageDelivered"]
            elif status in ("quarantined", "rejected"):
                events = [e for e in events if e["eventType"] == "messageBlocked"]
            found = search_events(events, sender=sender, recipient=recipient, subject=subject, message_id=message_id)
            number, size, start = locate(offset, page, per_page)
            end = number * size  # the rest of the page that holds the offset
            rows = [
                {
                    "outcome": "delivered" if e["eventType"] == "messageDelivered" else "blocked",
                    **{k: e.get(k) for k in ("messageTime", "sender", "recipient", "subject", "messageID", "GUID",
                                             "QID", "quarantineFolder", "quarantineRule", "threatsInfoMap")},
                }
                for e in found[start:end]
            ]
            more = end < len(found)
            return {"total": len(found), "page": number, "messages": rows, "has_more": more} | resume_fields(
                start, len(rows), more
            )

        return await run_tool("proofpoint_smart_search_trace", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_smart_search_get_message(
        message_id: MessageId,
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
    ) -> str:
        """Full TAP record of one threat message: recipients, scores, threats, parts, policy routes.

        Searches one SIEM window (default the last hour); pass the window the event was created in.
        """

        async def action(client: ProofpointClient) -> dict:
            return await _find_message(client, message_id, siem_window(sinceSeconds, sinceTime, interval))

        return await run_tool("proofpoint_smart_search_get_message", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_smart_search_get_headers(
        message_id: MessageId,
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
    ) -> str:
        """Envelope and header fields of one threat message (From, Reply-To, To, Cc, X-Mailer, sender IP).

        TAP exposes these fields, not the raw header block. Searches one SIEM window (default the last hour).
        """

        async def action(client: ProofpointClient) -> dict[str, Any]:
            message = await _find_message(client, message_id, siem_window(sinceSeconds, sinceTime, interval))
            return {k: message.get(k) for k in HEADER_FIELDS if k in message}

        return await run_tool("proofpoint_smart_search_get_headers", client_factory, action)
