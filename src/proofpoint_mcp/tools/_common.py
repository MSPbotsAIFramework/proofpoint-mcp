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
"""Shared argument types, the SIEM time-window rules and the error-handling wrapper."""

import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import ProofpointClient, ProofpointError

logger = logging.getLogger("proofpoint_mcp.tools")

ClientFactory = Callable[[], ProofpointClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
WRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "Proofpoint credentials are missing for this request (X-Proofpoint-Service-Principal, "
    "X-Proofpoint-Service-Secret).",
    False,
)

# SIEM API limits (official docs): at most one hour per request, at most
# seven days into the past, interval at least 30 seconds.
SIEM_MAX_SECONDS = 3600
SIEM_MAX_AGE = timedelta(days=7)
_CLOCK_SLACK = timedelta(minutes=5)
DEFAULT_MAX_EVENTS = 100
SIEM_LISTS = ("messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked")

SinceSeconds = Annotated[
    int | None,
    Field(description="Events created in the last N seconds (1-3600). Default when no time option is given: 3600."),
]
SinceTime = Annotated[
    str | None,
    Field(description="ISO8601 start time within the last hour (UTC), e.g. 2026-01-01T12:00:00Z; ends now."),
]
Interval = Annotated[
    str | None,
    Field(
        description="ISO8601 interval of 30s-1h within the last 7 days, e.g. "
        "2026-01-01T12:00:00Z/2026-01-01T13:00:00Z or PT30M/2026-01-01T12:30:00Z."
    ),
]
ThreatStatus = Annotated[
    Literal["active", "cleared", "falsePositive"] | None,
    Field(description="Only threats with this status (default: active and cleared)."),
]
MaxEvents = Annotated[
    int,
    Field(description="Keep at most this many events per event list (1-500).", ge=1, le=500),
]
Window = Annotated[
    Literal[14, 30, 90],
    Field(description="Look-back window in days: 14, 30 or 90."),
]
Offset = Annotated[
    int | None,
    Field(description="Record position to start from (0-based, overrides page); pass next_offset from the previous result.", ge=0),
]


def locate(offset: int | None, page: int | None, size: int) -> tuple[int, int, int]:
    """(page number, page size, start) for a read from record ``start``.

    Proofpoint pages by number only, so a position is reached by reading the page that holds
    it (same page size) and skipping the records before it.
    """
    start = offset if offset is not None else ((page or 1) - 1) * size
    return start // size + 1, size, start


def resume_fields(start: int, returned: int, more: bool) -> dict[str, Any]:
    """offset / next_offset of a read from record ``start``.

    next_offset continues right after the last record returned, also when the result is cut
    to fit the size limit (a page number cannot: the rest of a cut page is on no other page).
    """
    fields: dict[str, Any] = {"offset": start}
    if more:
        fields["next_offset"] = start + returned
    fields["_resume"] = {"key": "next_offset", "start": start}
    return fields


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def parse_time(value: str, name: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as e:
        raise ValueError(f"{name} must be an ISO8601 date-time such as 2026-01-01T12:00:00Z, got {value!r}.") from e
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(UTC)


def siem_window(
    sinceSeconds: int | None = None, sinceTime: str | None = None, interval: str | None = None
) -> list[tuple[str, Any]]:
    """Exactly one SIEM time option, validated against the documented limits."""
    given = [name for name, v in (("sinceSeconds", sinceSeconds), ("sinceTime", sinceTime), ("interval", interval)) if v]
    if len(given) > 1:
        raise ValueError(f"Give only one of sinceSeconds, sinceTime or interval (got {', '.join(given)}).")
    if interval:
        if "/" not in interval:
            raise ValueError("interval must be an ISO8601 interval: start/end, PT30M/end or start/PT30M.")
        return [("interval", interval.strip())]
    if sinceTime:
        start = parse_time(sinceTime, "sinceTime")
        age = now() - start
        if age < -_CLOCK_SLACK:
            raise ValueError("sinceTime is in the future.")
        if age > timedelta(seconds=SIEM_MAX_SECONDS) + _CLOCK_SLACK:
            raise ValueError(
                "The SIEM API returns at most one hour per call; for older data pass an interval of up to one "
                "hour (within the last 7 days)."
            )
        return [("sinceTime", iso(start))]
    seconds = SIEM_MAX_SECONDS if sinceSeconds is None else sinceSeconds
    if not 1 <= seconds <= SIEM_MAX_SECONDS:
        raise ValueError("sinceSeconds must be between 1 and 3600 (the SIEM API returns at most one hour per call).")
    return [("sinceSeconds", seconds)]


def dates_window(startDate: str | None, endDate: str | None) -> list[tuple[str, Any]]:
    """startDate / endDate turned into a SIEM window (at most one hour)."""
    if not startDate and not endDate:
        return siem_window()
    if startDate and not endDate:
        start = parse_time(startDate, "startDate")
        if now() - start <= timedelta(seconds=SIEM_MAX_SECONDS) + _CLOCK_SLACK:
            return siem_window(sinceTime=startDate)
        return [("interval", f"{iso(start)}/PT1H")]
    end = parse_time(endDate or "", "endDate")
    start = parse_time(startDate, "startDate") if startDate else end - timedelta(hours=1)
    if end <= start:
        raise ValueError("endDate must be after startDate.")
    if end - start > timedelta(seconds=SIEM_MAX_SECONDS):
        raise ValueError("The SIEM API searches at most one hour per call; narrow startDate/endDate to one hour.")
    if now() - start > SIEM_MAX_AGE:
        raise ValueError("The SIEM API keeps 7 days of events; startDate is older than that.")
    return [("interval", f"{iso(start)}/{iso(end)}")]


async def fetch_siem(
    client: ProofpointClient,
    endpoint: str,
    window: list[tuple[str, Any]],
    threatStatus: str | None = None,
    threatType: str | None = None,
    fmt: str = "json",
) -> Any:
    params = [("format", fmt), *window]
    if threatStatus:
        params.append(("threatStatus", threatStatus))
    if threatType:
        params.append(("threatType", threatType))
    return await client.tap("GET", f"/v2/siem/{endpoint}", params)


def siem_lists(payload: Any) -> dict[str, list[dict]]:
    data = payload if isinstance(payload, dict) else {}
    return {key: [e for e in data.get(key) or [] if isinstance(e, dict)] for key in SIEM_LISTS}


def shape_siem(payload: Any, max_events: int) -> Any:
    """SIEM JSON with each event list capped and the full counts reported."""
    if isinstance(payload, dict) and "raw_text" in payload:
        lines = [line for line in str(payload["raw_text"]).splitlines() if line.strip()]
        return {"format": "syslog", "count": len(lines), "lines": lines[:max_events], "has_more": len(lines) > max_events}
    if not isinstance(payload, dict):
        return payload
    lists = siem_lists(payload)
    out: dict[str, Any] = {"queryEndTime": payload.get("queryEndTime")}
    out["counts"] = {key: len(rows) for key, rows in lists.items() if key in payload}
    for key, rows in lists.items():
        if key in payload:
            out[key] = rows[:max_events]
    if any(len(rows) > max_events for rows in lists.values()):
        out["has_more"] = True
        out["note"] = f"Each list was cut to {max_events} events; use a shorter window or raise max_events."
    return out


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[ProofpointClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    if client.header_error:
        return error_envelope("invalid_argument", client.header_error, False)
    started = time.monotonic()
    try:
        result = await action(client)
    except ProofpointError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "Proofpoint returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
