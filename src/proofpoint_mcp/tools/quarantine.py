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
"""Quarantine tools backed by Proofpoint Protection Server (PPS), a second, optional credential
set independent of TAP (PRD-21254).

Names and required parameters are unchanged from the stubs these tools replace in
unsupported.py -- that snapshot is a declared public contract (tests/test_tools.py). Only the
behavior behind them changes: with PPS credentials they call the real PPS REST API; without
them they return not_configured instead of the old "Not available: belongs to another
Proofpoint product" message (PPS is the product that message used to point away from).

Wire shapes (base path /rest/v1/quarantine, Basic auth, action field for release/delete) follow
the Cortex XSOAR "Proofpoint Protection Server v2" integration, the most complete public mapping
of this API found during design (no single official PPS REST reference exists) -- see the
ticket's tech design, Open question Q1.
"""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import error_envelope
from ..api_client import ProofpointClient
from ._common import (
    DESTRUCTIVE,
    NOT_CONFIGURED,
    PPS_NOT_CONFIGURED,
    READ_ONLY,
    WRITES,
    ClientFactory,
    Date,
    Page,
    PerPage,
    Text,
    locate,
    resume_fields,
    run_tool,
)

Folder = Annotated[
    Literal["SPAM", "VIRUS", "POLICY", "BULK", "PHISH", "ADMIN", "IMPOSTOR"] | None,
    Field(description="Quarantine folder."),
]
MessageId = Annotated[str, Field(description="Quarantined message id, as returned by _list / _search.")]
Query = Annotated[str, Field(description="Search text, matched against sender, recipient and subject.")]

# PPS "messagestatus" filter: "t" keeps only messages still held in quarantine (matches what
# _list/_search/_release/_delete all reason about -- a message already released/deleted is gone).
_HELD = "t"


def _encode_id(folder: Any, localguid: Any) -> str | None:
    folder, localguid = str(folder or ""), str(localguid or "")
    return f"{folder}:{localguid}" if folder and localguid else None


def _decode_id(message_id: str) -> tuple[str, str]:
    folder, sep, localguid = message_id.partition(":")
    if not sep or not folder or not localguid:
        raise ValueError(
            "message_id must be an id returned by proofpoint_quarantine_list or _search "
            "(folder:localguid); it cannot be invented by the caller."
        )
    return folder, localguid


def _shape(raw: dict) -> dict:
    return {
        "message_id": _encode_id(raw.get("folder"), raw.get("localguid")),
        "folder": raw.get("folder"),
        "sender": raw.get("from"),
        "recipients": raw.get("rcpts"),
        "subject": raw.get("subject"),
        "date": raw.get("date"),
        "spam_score": raw.get("spamscore"),
        "size": raw.get("size"),
    }


async def _pps_list(
    client: ProofpointClient,
    *,
    sender: str | None = None,
    recipient: str | None = None,
    subject: str | None = None,
    startDate: str | None = None,
    endDate: str | None = None,
    folder: str | None = None,
) -> list[dict]:
    """GET /quarantine. None-valued params are dropped by the client's query encoder."""
    payload = await client.pps(
        "GET",
        "/quarantine",
        params={
            "from": sender,
            "rcpt": recipient,
            "subject": subject,
            "startdate": startDate,
            "enddate": endDate,
            "folder": folder,
            "dlpviolation": "details",
            "messagestatus": _HELD,
        },
    )
    records = payload.get("records") if isinstance(payload, dict) else None
    return [r for r in records or [] if isinstance(r, dict)]


def _page(records: list[dict], page: int | None, per_page: int | None, offset: int | None) -> dict:
    number, size, start = locate(offset, page, per_page or 50)
    end = number * size
    rows = [_shape(r) for r in records[start:end]]
    more = end < len(records)
    return {"total": len(records), "page": number, "messages": rows, "has_more": more} | resume_fields(
        start, len(rows), more
    )


async def _quarantine_action(client: ProofpointClient, action: Literal["release", "delete"], message_id: str) -> dict:
    folder, localguid = _decode_id(message_id)
    result = await client.pps("POST", "/quarantine", body={"action": action, "folder": folder, "localguid": localguid})
    return result if isinstance(result, dict) else {"status": "ok", "action": action, "message_id": message_id}


async def _run(name: str, client_factory: ClientFactory, action) -> str:
    """Like run_tool, but checks the PPS-specific preconditions this module owns.

    A malformed PPS base URL (pps_header_error) and missing PPS credentials must not affect any
    other tool -- that is why they are not checked in the shared run_tool -- so they are checked
    here, before delegating the real call, logging and TAP-side error handling to run_tool.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    if client.pps_header_error:
        return error_envelope("invalid_argument", client.pps_header_error, False)
    if not client.has_pps_credentials:
        return PPS_NOT_CONFIGURED
    return await run_tool(name, lambda: client, action)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_quarantine_list(
        sender: Text = None,
        recipient: Text = None,
        subject: Text = None,
        startDate: Date = None,
        endDate: Date = None,
        folder: Folder = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Quarantined messages in Proofpoint Protection Server, optionally filtered.

        Needs Proofpoint Protection Server credentials (X-Proofpoint-Pps-Base-Url, -Username,
        -Password); without them returns not_configured. For blocked threat messages seen by
        TAP (a different Proofpoint product) use proofpoint_tap_get_messages_blocked instead.
        """

        async def action(client: ProofpointClient) -> dict:
            records = await _pps_list(
                client, sender=sender, recipient=recipient, subject=subject, startDate=startDate, endDate=endDate, folder=folder
            )
            return _page(records, page, per_page, None)

        return await _run("proofpoint_quarantine_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_quarantine_search(
        query: Query,
        startDate: Date = None,
        endDate: Date = None,
        page: Page = None,
        per_page: PerPage = None,
    ) -> str:
        """Find a quarantined message by sender, recipient or subject (one query, matched as OR).

        Needs Proofpoint Protection Server credentials; without them returns not_configured.
        To find a threat message seen by TAP instead, use proofpoint_smart_search_trace.
        """

        async def action(client: ProofpointClient) -> dict:
            text = query.strip()
            if not text:
                raise ValueError("query must not be blank.")
            by_field: list[list[dict]] = []
            for kwargs in ({"sender": text}, {"recipient": text}, {"subject": text}):
                by_field.append(await _pps_list(client, startDate=startDate, endDate=endDate, **kwargs))
            merged: dict[tuple[str, str], dict] = {}
            for records in by_field:
                for r in records:
                    merged.setdefault((str(r.get("folder")), str(r.get("localguid"))), r)
            return _page(list(merged.values()), page, per_page, None)

        return await _run("proofpoint_quarantine_search", client_factory, action)

    @mcp.tool(annotations=WRITES)
    async def proofpoint_quarantine_release(message_id: MessageId) -> str:
        """Release a quarantined message in Proofpoint Protection Server.

        Needs Proofpoint Protection Server credentials; without them returns not_configured.
        message_id must come from _list / _search -- releasing it removes it from that folder.
        """

        async def action(client: ProofpointClient) -> dict:
            return await _quarantine_action(client, "release", message_id)

        return await _run("proofpoint_quarantine_release", client_factory, action)

    @mcp.tool(annotations=DESTRUCTIVE)
    async def proofpoint_quarantine_delete(message_id: MessageId) -> str:
        """Permanently delete a quarantined message in Proofpoint Protection Server.

        Needs Proofpoint Protection Server credentials; without them returns not_configured.
        This cannot be undone.
        """

        async def action(client: ProofpointClient) -> dict:
            return await _quarantine_action(client, "delete", message_id)

        return await _run("proofpoint_quarantine_delete", client_factory, action)
