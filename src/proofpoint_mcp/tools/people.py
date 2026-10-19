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
"""People API: Very Attacked People, top clickers, and one user's standing in both."""

import asyncio
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient
from ._common import READ_ONLY, ClientFactory, Window, run_tool

VAP_MAX_SIZE = 1000
CLICKERS_MAX_SIZE = 200
Page = Annotated[int, Field(description="Page number, from 1.", ge=1)]


def find_user(payload: Any, email: str) -> tuple[int, dict] | None:
    """(1-based rank, user) of the user whose identity lists this email."""
    users = payload.get("users") if isinstance(payload, dict) else None
    wanted = email.strip().lower()
    for rank, user in enumerate(users or [], start=1):
        identity = user.get("identity") if isinstance(user, dict) else None
        emails = identity.get("emails") if isinstance(identity, dict) else None
        if any(str(e).lower() == wanted for e in emails or []):
            return rank, user
    return None


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_people_get_vap(
        window: Window = 30,
        page: Page = 1,
        size: Annotated[int, Field(description="Users per page (1-1000), highest attack index first.", ge=1, le=1000)] = 100,
    ) -> str:
        """Very Attacked People: users ranked by attack index, with the threat families aimed at them.

        Quota: 50 calls per 24 hours.
        """

        async def action(client: ProofpointClient) -> Any:
            return await client.tap("GET", "/v2/people/vap", {"window": window, "page": page, "size": size})

        return await run_tool("proofpoint_people_get_vap", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_people_get_top_clickers(
        window: Window = 30,
        page: Page = 1,
        size: Annotated[int, Field(description="Users per page (1-200).", ge=1, le=200)] = 100,
    ) -> str:
        """Users who clicked the most malicious URLs, with click counts per threat family.

        Quota: 50 calls per 24 hours.
        """

        async def action(client: ProofpointClient) -> Any:
            return await client.tap("GET", "/v2/people/top-clickers", {"window": window, "page": page, "size": size})

        return await run_tool("proofpoint_people_get_top_clickers", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_people_get_user_risk(
        email: Annotated[str, Field(description="The user's email address.")],
        window: Window = 30,
    ) -> str:
        """One user's risk: whether they are a Very Attacked Person or a top clicker, with rank and statistics.

        Reads the first page of each list (1000 VAPs, 200 clickers); uses one call of each 50/day quota.
        """

        async def action(client: ProofpointClient) -> dict:
            if "@" not in email:
                raise ValueError("email must be an email address.")
            vap, clickers = await asyncio.gather(
                client.tap("GET", "/v2/people/vap", {"window": window, "size": VAP_MAX_SIZE}),
                client.tap("GET", "/v2/people/top-clickers", {"window": window, "size": CLICKERS_MAX_SIZE}),
            )
            vap_hit = find_user(vap, email)
            click_hit = find_user(clickers, email)
            result: dict[str, Any] = {
                "email": email.strip(),
                "window_days": window,
                "isVeryAttackedPerson": vap_hit is not None,
                "isTopClicker": click_hit is not None,
            }
            if isinstance(vap, dict):
                result["vapAttackIndexThreshold"] = vap.get("vapAttackIndexThreshold")
                result["averageAttackIndex"] = vap.get("averageAttackIndex")
            if vap_hit:
                result["vapRank"] = vap_hit[0]
                result["identity"] = vap_hit[1].get("identity")
                result["threatStatistics"] = vap_hit[1].get("threatStatistics")
            if click_hit:
                result["topClickerRank"] = click_hit[0]
                result.setdefault("identity", click_hit[1].get("identity"))
                result["clickStatistics"] = click_hit[1].get("clickStatistics")
            if not vap_hit and not click_hit:
                result["note"] = "Not in the VAP or top-clicker lists for this window (low attack and click activity)."
            return result

        return await run_tool("proofpoint_people_get_user_risk", client_factory, action)
