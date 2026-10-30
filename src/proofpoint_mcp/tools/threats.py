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
"""Threat, Campaign and Forensics APIs, plus family and IOC roll-ups built on them."""

import asyncio
from datetime import timedelta
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient, ProofpointError
from ._common import (
    READ_ONLY,
    ClientFactory,
    Interval,
    fetch_siem,
    iso,
    now,
    parse_time,
    path_segment,
    run_tool,
    siem_window,
)
from .tap import flatten

ThreatId = Annotated[str, Field(description="TAP threat id (threatID from a SIEM event or the dashboard URL).")]
CampaignId = Annotated[str, Field(description="TAP campaign id (campaignId from a SIEM event or campaign list).")]
CAMPAIGN_MAX_DAYS = 1
_FAMILY_CONCURRENCY = 3

# Evidence type -> fields in its "what" map that are indicators of compromise.
IOC_FIELDS: dict[str, tuple[str, ...]] = {
    "attachment": ("sha256", "md5"),
    "file": ("sha256", "md5", "path"),
    "url": ("url", "ip", "sha256", "md5"),
    "dns": ("host", "ips", "cnames"),
    "network": ("ip", "port"),
    "dropper": ("url", "path"),
    "cookie": ("domain",),
    "registry": ("key", "value"),
    "mutex": ("name",),
    "process": ("path",),
}


def extract_iocs(forensics: Any, malicious_only: bool = True) -> list[dict]:
    """Indicators from a forensics report, de-duplicated by type and value."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    reports = forensics.get("reports") if isinstance(forensics, dict) else None
    for report in reports or []:
        if not isinstance(report, dict):
            continue
        for evidence in report.get("forensics") or []:
            if not isinstance(evidence, dict) or (malicious_only and not evidence.get("malicious")):
                continue
            kind = str(evidence.get("type") or "")
            what = evidence.get("what") if isinstance(evidence.get("what"), dict) else {}
            for field in IOC_FIELDS.get(kind, ()):
                value = what.get(field)
                for item in value if isinstance(value, list) else [value]:
                    if item in (None, ""):
                        continue
                    key = (f"{kind}.{field}", str(item))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({"type": kind, "field": field, "value": item, "report": report.get("name")})
    return out


def campaign_interval(sinceTime: str | None, interval: str | None) -> str:
    """Campaign API interval: 30 seconds to 1 day; default the last 24 hours."""
    if sinceTime and interval:
        raise ValueError("Give sinceTime or interval, not both.")
    if interval:
        if "/" not in interval:
            raise ValueError("interval must be an ISO8601 interval such as 2026-01-01T00:00:00Z/2026-01-02T00:00:00Z.")
        return interval.strip()
    end = now().replace(microsecond=0)
    start = parse_time(sinceTime, "sinceTime") if sinceTime else end - timedelta(days=CAMPAIGN_MAX_DAYS)
    if end - start > timedelta(days=CAMPAIGN_MAX_DAYS, minutes=5):
        raise ValueError("The Campaign API covers at most one day per call; use an interval of up to one day.")
    return f"{iso(start)}/{iso(end)}"


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_forensics_get_threat(
        threat_id: ThreatId,
        includeCampaignForensics: Annotated[
            bool, Field(description="True: forensics of the whole campaign the threat belongs to, if any.")
        ] = False,
    ) -> str:
        """Sandbox forensics for one threat: evidence such as URLs, files, DNS, network and registry activity.

        Quota: 50 calls per 24 hours per threat id.
        """

        async def action(client: ProofpointClient) -> Any:
            params = {"threatId": threat_id.strip() or None, "includeCampaignForensics": includeCampaignForensics}
            if not params["threatId"]:
                raise ValueError("threat_id must not be blank.")
            return await client.tap("GET", "/v2/forensics", params)

        return await run_tool("proofpoint_forensics_get_threat", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_forensics_get_campaign(campaign_id: CampaignId) -> str:
        """Aggregate sandbox forensics for every threat variant in a campaign."""

        async def action(client: ProofpointClient) -> Any:
            if not campaign_id.strip():
                raise ValueError("campaign_id must not be blank.")
            return await client.tap("GET", "/v2/forensics", {"campaignId": campaign_id.strip()})

        return await run_tool("proofpoint_forensics_get_campaign", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_threat_get_campaign(campaign_id: CampaignId) -> str:
        """Campaign details: name, description, start date, member threats, actors, malware and techniques.

        Quota: 50 Campaign API calls per 24 hours.
        """

        async def action(client: ProofpointClient) -> Any:
            return await client.tap("GET", f"/v2/campaign/{path_segment(campaign_id, 'campaign_id')}")

        return await run_tool("proofpoint_threat_get_campaign", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_threat_get_by_id(threat_id: ThreatId) -> str:
        """Threat summary: type, classification, severity, status, first seen and related campaign."""

        async def action(client: ProofpointClient) -> Any:
            return await client.tap("GET", f"/v2/threat/summary/{path_segment(threat_id, 'threat_id')}")

        return await run_tool("proofpoint_threat_get_by_id", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_threat_list_families(
        sinceTime: Annotated[str | None, Field(description="ISO8601 start within the last day; ends now.")] = None,
        interval: Annotated[
            str | None, Field(description="ISO8601 interval of 30 seconds to 1 day. Default: the last 24 hours.")
        ] = None,
        max_campaigns: Annotated[
            int, Field(description="Campaigns to open for their families (1-20). Each one uses Campaign quota.", ge=1, le=20)
        ] = 5,
    ) -> str:
        """Malware families, actors and techniques of the campaigns active in a time window.

        Lists campaign ids, then reads up to max_campaigns of them (Campaign API quota: 50 calls per 24 hours).
        """

        async def action(client: ProofpointClient) -> dict:
            window = campaign_interval(sinceTime, interval)
            listing = await client.tap("GET", "/v2/campaign/ids", {"interval": window, "size": 200})
            campaigns = [c for c in (listing or {}).get("campaigns") or [] if isinstance(c, dict) and c.get("id")]
            chosen = campaigns[:max_campaigns]
            semaphore = asyncio.Semaphore(_FAMILY_CONCURRENCY)

            async def detail(campaign: dict) -> dict | None:
                async with semaphore:
                    try:
                        return await client.tap("GET", f"/v2/campaign/{path_segment(str(campaign['id']), 'id')}")
                    except ProofpointError as e:
                        if e.status_code in (401, 429):
                            raise
                        return None

            families: dict[str, dict[str, Any]] = {}
            for full in await asyncio.gather(*(detail(c) for c in chosen)):
                if not isinstance(full, dict):
                    continue
                for kind in ("malware", "actors", "techniques"):
                    for item in full.get(kind) or []:
                        if not isinstance(item, dict) or not item.get("name"):
                            continue
                        entry = families.setdefault(
                            f"{kind}:{item['name']}", {"kind": kind, "name": item["name"], "id": item.get("id"), "campaigns": []}
                        )
                        entry["campaigns"].append({"id": full.get("id"), "name": full.get("name")})
            result: dict[str, Any] = {
                "interval": window,
                "campaigns_in_window": len(campaigns),
                "campaigns_read": len(chosen),
                "families": sorted(families.values(), key=lambda f: (f["kind"], -len(f["campaigns"]), f["name"])),
            }
            if len(campaigns) > len(chosen):
                result["note"] = f"Only {len(chosen)} of {len(campaigns)} campaigns were read; raise max_campaigns."
            return result

        return await run_tool("proofpoint_threat_list_families", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_threat_get_iocs(
        campaign_id: Annotated[
            str | None, Field(description="Campaign id: indicators from its sandbox forensics.")
        ] = None,
        sinceTime: Annotated[str | None, Field(description="Without campaign_id: SIEM start within the last hour.")] = None,
        interval: Interval = None,
        threat_type: Annotated[
            Literal["url", "attachment", "messageText"] | None, Field(description="Only threats of this type.")
        ] = None,
    ) -> str:
        """Indicators of compromise: from a campaign's forensics, or the threats seen in a SIEM window.

        With campaign_id: hashes, URLs, hosts, IPs found by the sandbox. Without it: the threat values
        (URLs, attachment hashes) in recent events (default the last hour).
        """

        async def action(client: ProofpointClient) -> dict:
            if campaign_id and campaign_id.strip():
                forensics = await client.tap("GET", "/v2/forensics", {"campaignId": campaign_id.strip()})
                iocs = extract_iocs(forensics)
                if threat_type == "url":
                    iocs = [i for i in iocs if i["type"] in ("url", "dns", "network", "dropper")]
                elif threat_type == "attachment":
                    iocs = [i for i in iocs if i["type"] in ("attachment", "file")]
                return {"campaign_id": campaign_id.strip(), "count": len(iocs), "iocs": iocs}
            payload = await fetch_siem(client, "all", siem_window(None, sinceTime, interval), threatType=threat_type)
            seen: dict[str, dict] = {}
            for event in flatten(payload):
                threats = [t for t in event.get("threatsInfoMap") or [] if isinstance(t, dict)]
                if not threats and event.get("threatID"):
                    threats = [{"threatID": event.get("threatID"), "threat": event.get("url"), "threatType": "url",
                                "classification": event.get("classification"), "campaignId": event.get("campaignId")}]
                for t in threats:
                    if threat_type and str(t.get("threatType") or "").lower() != threat_type.lower():
                        continue
                    key = str(t.get("threatID") or t.get("threat"))
                    entry = seen.setdefault(key, {
                        "threatID": t.get("threatID"),
                        "value": t.get("threat"),
                        "threatType": t.get("threatType"),
                        "classification": t.get("classification"),
                        "campaignId": t.get("campaignId"),
                        "events": 0,
                    })
                    entry["events"] += 1
            iocs = sorted(seen.values(), key=lambda i: -i["events"])
            return {"count": len(iocs), "iocs": iocs}

        return await run_tool("proofpoint_threat_get_iocs", client_factory, action)
