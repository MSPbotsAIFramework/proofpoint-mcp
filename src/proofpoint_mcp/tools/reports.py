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
"""Dashboard Reports API (separate API key; 20 calls per report section per day)."""

import asyncio
from datetime import timedelta
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient, ProofpointError
from ._common import READ_ONLY, ClientFactory, iso, now, run_tool

ReportWindow = Annotated[Literal[1, 7, 14, 30, 90], Field(description="Report period in days, ending now.")]
QUOTA_NOTE = "Needs the Reports API key headers; 20 calls per report section per day."
# Dashboard threat category names for the threatType values of this tool.
CATEGORY_NAMES = {"spam": "spam", "phish": "phishing", "malware": "malware", "impostor": "bec"}


def period(days: int) -> list[tuple[str, str]]:
    end = now().replace(microsecond=0)
    return [("start", iso(end - timedelta(days=days))), ("end", iso(end))]


def group_by(days: int, granularity: str | None) -> str:
    """Trend grouping allowed by the Reports API for this range length."""
    allowed = ["DAY"] if days < 14 else ["DAY", "WEEK"] if days <= 30 else ["WEEK", "MONTH", "QUARTER"]
    if granularity is None:
        return allowed[0]
    if granularity == "hourly":
        raise ValueError("The Reports API has no hourly trend; use daily or weekly.")
    wanted = {"daily": "DAY", "weekly": "WEEK"}[granularity]
    if wanted not in allowed:
        raise ValueError(f"For a {days}-day window the Reports API allows: {', '.join(allowed)}.")
    return wanted


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_reports_org_summary(window: ReportWindow = 30) -> str:
        """Organisation inbound protection overview: messages protected before and after delivery, exposure.

        Dashboard Executive Summary. Needs the Reports API key headers; 20 calls per section per day.
        """

        async def action(client: ProofpointClient) -> Any:
            return await client.reports("/executive-summary/inbound-protection-overview", period(window))

        return await run_tool("proofpoint_reports_org_summary", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_reports_threat_summary(
        window: ReportWindow = 30,
        threatType: Annotated[
            Literal["spam", "phish", "malware", "impostor", "all"],
            Field(description="Keep one category (impostor = BEC) or all."),
        ] = "all",
    ) -> str:
        """Threat volume by category (malware, phishing, spam, BEC) with share of the total.

        Dashboard Executive Summary. Needs the Reports API key headers; 20 calls per section per day.
        """

        async def action(client: ProofpointClient) -> Any:
            data = await client.reports("/executive-summary/threat-categories", period(window))
            if threatType != "all" and isinstance(data, dict) and isinstance(data.get("threatCategories"), list):
                wanted = CATEGORY_NAMES[threatType]
                data = {
                    **data,
                    "threatCategories": [
                        c for c in data["threatCategories"]
                        if isinstance(c, dict) and str(c.get("name") or "").lower() == wanted
                    ],
                }
            return data

        return await run_tool("proofpoint_reports_threat_summary", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_reports_mail_flow(
        window: ReportWindow = 30,
        granularity: Annotated[
            Literal["hourly", "daily", "weekly"] | None,
            Field(description="Trend bucket. Allowed: <14 days daily; 14-30 daily/weekly; 90 weekly. Default: finest."),
        ] = None,
    ) -> str:
        """Trend of protected messages over time, by threat type.

        Dashboard Effectiveness report. Needs the Reports API key headers; 20 calls per section per day.
        """

        async def action(client: ProofpointClient) -> Any:
            params = [*period(window), ("groupBy", group_by(window, granularity))]
            return await client.reports("/effectiveness-reports/messages-protected-trend", params)

        return await run_tool("proofpoint_reports_mail_flow", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_reports_executive_summary(
        window: Annotated[Literal[7, 14, 30, 90], Field(description="Report period in days, ending now.")] = 30,
    ) -> str:
        """Executive summary: threat categories, Very Attacked People and top clickers for the period.

        Three Executive Summary calls (of 20 per day). Needs the Reports API key headers.
        """

        async def action(client: ProofpointClient) -> dict:
            params = period(window)
            sections = {
                "threatCategories": "/executive-summary/threat-categories",
                "veryAttackedPeople": "/executive-summary/very-attacked-people",
                "topClickers": "/executive-summary/top-clickers",
            }
            results = await asyncio.gather(
                *(client.reports(path, params) for path in sections.values()), return_exceptions=True
            )
            out: dict[str, Any] = {"start": params[0][1], "end": params[1][1]}
            errors: dict[str, str] = {}
            for name, result in zip(sections, results, strict=True):
                if isinstance(result, ProofpointError):
                    errors[name] = result.message
                elif isinstance(result, BaseException):
                    raise result
                else:
                    out[name] = result
            if len(errors) == len(sections):
                first = next(r for r in results if isinstance(r, ProofpointError))
                raise first
            if errors:
                out["errors"] = errors
            return out

        return await run_tool("proofpoint_reports_executive_summary", client_factory, action)
