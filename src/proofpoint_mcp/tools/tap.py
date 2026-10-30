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
"""SIEM API: threat messages and clicks, as raw lists, filtered events and statistics."""

from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient
from ._common import (
    DEFAULT_MAX_EVENTS,
    READ_ONLY,
    ClientFactory,
    Interval,
    MaxEvents,
    SinceSeconds,
    SinceTime,
    ThreatStatus,
    fetch_siem,
    run_tool,
    shape_siem,
    siem_lists,
    siem_window,
)

EVENT_TYPES = {
    "messagesDelivered": "messageDelivered",
    "messagesBlocked": "messageBlocked",
    "clicksPermitted": "clickPermitted",
    "clicksBlocked": "clickBlocked",
}
ID_FIELDS = ("GUID", "id", "messageID", "QID")


def classifications(event: dict) -> set[str]:
    """Threat classifications of a message (threatsInfoMap) or a click."""
    found = {str(event.get("classification") or "").lower()}
    for threat in event.get("threatsInfoMap") or []:
        if isinstance(threat, dict):
            found.add(str(threat.get("classification") or "").lower())
    found.discard("")
    return found


def flatten(payload: Any) -> list[dict]:
    """Every SIEM event as one list, each tagged with its eventType."""
    out = []
    for key, rows in siem_lists(payload).items():
        for row in rows:
            out.append({"eventType": EVENT_TYPES[key], **row})
    return out


def matches_id(event: dict, wanted: str) -> bool:
    target = wanted.strip().strip("<>").lower()
    return any(str(event.get(f) or "").strip().strip("<>").lower() == target for f in ID_FIELDS)


def _register_siem_tool(
    mcp: FastMCP,
    client_factory: ClientFactory,
    name: str,
    endpoint: str,
    doc: str,
    *,
    caller: Callable[[ProofpointClient, str, list[tuple[str, Any]]], Awaitable[Any]] | None = None,
    requires: Callable[[ProofpointClient], bool] | None = None,
    not_configured: str | None = None,
) -> None:
    """Register one SIEM-shaped tool.

    ``caller`` picks which credential set/host the request goes out on (default: TAP); a module
    for another SIEM-shaped API (e.g. Essentials Threat, PRD-21255) passes its own caller plus
    ``requires``/``not_configured`` instead of duplicating this function.
    """

    async def tool(
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
        threatStatus: ThreatStatus = None,
        threatType: Annotated[
            Literal["url", "attachment", "messageText"] | None, Field(description="Only this threat type.")
        ] = None,
        format: Annotated[
            Literal["json", "syslog"], Field(description="json (structured, default) or syslog lines.")
        ] = "json",
        max_events: MaxEvents = DEFAULT_MAX_EVENTS,
    ) -> str:
        async def action(client: ProofpointClient) -> Any:
            window = siem_window(sinceSeconds, sinceTime, interval)
            payload = await fetch_siem(client, endpoint, window, threatStatus, threatType, format, caller)
            return shape_siem(payload, max_events)

        return await run_tool(name, client_factory, action, requires=requires, not_configured=not_configured)

    tool.__name__ = name
    tool.__doc__ = doc
    mcp.tool(name=name, annotations=READ_ONLY)(tool)


SIEM_TOOLS = [
    (
        "proofpoint_tap_get_all_threats",
        "all",
        "All threat messages (delivered and blocked) and URL clicks (permitted and blocked) in a time window.\n\n"
        "At most one hour per call, up to 7 days back; default is the last hour. Lists are capped at max_events.",
    ),
    (
        "proofpoint_tap_get_messages_delivered",
        "messages/delivered",
        "Messages with threats that were delivered to users in a time window (the ones to remediate).\n\n"
        "At most one hour per call, up to 7 days back; default is the last hour.",
    ),
    (
        "proofpoint_tap_get_messages_blocked",
        "messages/blocked",
        "Messages with threats that were blocked or quarantined in a time window.\n\n"
        "At most one hour per call, up to 7 days back; default is the last hour.",
    ),
    (
        "proofpoint_tap_get_clicks_permitted",
        "clicks/permitted",
        "Clicks on malicious URLs that were allowed through (users who reached the threat).\n\n"
        "At most one hour per call, up to 7 days back; default is the last hour.",
    ),
    (
        "proofpoint_tap_get_clicks_blocked",
        "clicks/blocked",
        "Clicks on malicious URLs that URL Defense blocked.\n\n"
        "At most one hour per call, up to 7 days back; default is the last hour.",
    ),
]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    for name, endpoint, doc in SIEM_TOOLS:
        _register_siem_tool(mcp, client_factory, name, endpoint, doc)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_events_list(
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
        threatType: Annotated[
            Literal["spam", "phish", "malware", "impostor"] | None,
            Field(description="Only events whose threat classification is this."),
        ] = None,
        disposition: Annotated[
            Literal["delivered", "blocked", "quarantined"] | None,
            Field(description="Only messages with this outcome (quarantined = blocked into a quarantine folder)."),
        ] = None,
        max_events: MaxEvents = DEFAULT_MAX_EVENTS,
    ) -> str:
        """Threat events as one flat list, each tagged with eventType, filtered by classification or outcome.

        Built on the SIEM API (one hour per call, 7 days back; default last hour). A disposition filter
        returns messages only.
        """

        async def action(client: ProofpointClient) -> dict:
            payload = await fetch_siem(client, "all", siem_window(sinceSeconds, sinceTime, interval))
            events = flatten(payload)
            if disposition == "delivered":
                events = [e for e in events if e["eventType"] == "messageDelivered"]
            elif disposition == "blocked":
                events = [e for e in events if e["eventType"] == "messageBlocked"]
            elif disposition == "quarantined":
                events = [e for e in events if e["eventType"] == "messageBlocked" and e.get("quarantineFolder")]
            if threatType:
                events = [e for e in events if threatType in classifications(e)]
            return {
                "queryEndTime": payload.get("queryEndTime") if isinstance(payload, dict) else None,
                "count": len(events),
                "events": events[:max_events],
                "has_more": len(events) > max_events,
            }

        return await run_tool("proofpoint_events_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_events_get_details(
        event_id: Annotated[str, Field(description="Event GUID, event id, QID or the message's Message-ID.")],
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
    ) -> str:
        """Full record of one message or click event, found by its GUID, id, QID or Message-ID.

        The SIEM API has no lookup by id, so this searches one time window (default the last hour);
        pass the window the event was created in.
        """

        async def action(client: ProofpointClient) -> dict:
            if not event_id.strip():
                raise ValueError("event_id must not be blank.")
            payload = await fetch_siem(client, "all", siem_window(sinceSeconds, sinceTime, interval))
            found = [e for e in flatten(payload) if matches_id(e, event_id)]
            if not found:
                raise ValueError(
                    f"No event {event_id!r} in this window; pass the interval in which the event was created."
                )
            return {"event": found[0], "related": found[1:10]} if len(found) > 1 else {"event": found[0]}

        return await run_tool("proofpoint_events_get_details", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_events_get_stats(
        sinceSeconds: SinceSeconds = None,
        sinceTime: SinceTime = None,
        interval: Interval = None,
    ) -> str:
        """Counts for a time window: events by type, classification and status; top recipients and senders.

        Computed from the SIEM API (one hour per call, 7 days back; default last hour).
        """

        async def action(client: ProofpointClient) -> dict:
            payload = await fetch_siem(client, "all", siem_window(sinceSeconds, sinceTime, interval))
            events = flatten(payload)
            by_class: Counter[str] = Counter()
            by_status: Counter[str] = Counter()
            by_threat_type: Counter[str] = Counter()
            recipients: Counter[str] = Counter()
            senders: Counter[str] = Counter()
            for e in events:
                for c in classifications(e):
                    by_class[c] += 1
                threats = [t for t in e.get("threatsInfoMap") or [] if isinstance(t, dict)] or [e]
                for t in threats:
                    if t.get("threatStatus"):
                        by_status[str(t["threatStatus"])] += 1
                    if t.get("threatType"):
                        by_threat_type[str(t["threatType"]).lower()] += 1
                rcpt = e.get("recipient")
                for r in rcpt if isinstance(rcpt, list) else [rcpt]:
                    if r:
                        recipients[str(r).lower()] += 1
                if e.get("sender"):
                    senders[str(e["sender"]).lower()] += 1
            counts = Counter(e["eventType"] for e in events)
            return {
                "queryEndTime": payload.get("queryEndTime") if isinstance(payload, dict) else None,
                "total": len(events),
                "byEventType": {name: counts.get(name, 0) for name in EVENT_TYPES.values()},
                "byClassification": dict(by_class),
                "byThreatStatus": dict(by_status),
                "byThreatType": dict(by_threat_type),
                "topRecipients": recipients.most_common(10),
                "topSenders": senders.most_common(10),
            }

        return await run_tool("proofpoint_events_get_stats", client_factory, action)
