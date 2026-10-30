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
"""Proofpoint Essentials Admin/Reporting API (PRD-21255): domain and user inventory.

Read only (list/get); matches the repo's existing TAP-is-read-only principle (see
docs/tickets/PRD-21255.md "Open questions"). Essentials Admin credentials are independent of
TAP and Essentials Threat -- see server.py's "at least one credential set" gateway rule.

Pagination: the exact paging contract of the live Essentials Admin API could not be confirmed
from a static doc fetch at design time (no account available -- references/mcp-track.md 2.5
does not block on this). Rather than assume a server-side page/size contract that might not
hold, these tools fetch each org's full list once per call and page it client-side with the
same offset/next_offset helper tools/search.py's proofpoint_smart_search_trace already uses for
a result fetched in one shot -- correct regardless of what the vendor's own pagination does,
at the cost of re-fetching the full list on every page for very large orgs. See docs/tickets/
PRD-21255.md Self-test for this decision.
"""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Offset,
    NOT_CONFIGURED_ESSENTIALS_ADMIN,
    locate,
    path_segment,
    resume_fields,
    run_tool,
)

OrgDomain = Annotated[str, Field(description="The Essentials organization's domain, e.g. example.com.")]
Size = Annotated[int, Field(description="Records per page (1-500, default 50).", ge=1, le=500)]
Page = Annotated[int, Field(description="Page number, from 1.", ge=1)]

_ENVELOPE_KEYS = ("domains", "users", "data", "results", "items")


def _records(payload: Any) -> list[dict]:
    """The list of records in an Essentials Admin response, tolerant of the exact envelope shape
    (unconfirmed at design time -- see module docstring)."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in _ENVELOPE_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


async def _list_page(
    client: ProofpointClient, path: str, item_key: str, page: int | None, size: int, offset: int | None
) -> dict:
    number, size, start = locate(offset, page, size)
    payload = await client.essentials_admin("GET", path)
    records = _records(payload)
    end = number * size
    kept = records[start:end]
    more = end < len(records)
    return {item_key: kept, "count": len(records), "page": number, "has_more": more} | resume_fields(
        start, len(kept), more
    )


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    def requires(client: ProofpointClient) -> bool:
        return client.has_essentials_admin_credentials

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_essentials_list_domains(
        org_domain: OrgDomain, page: Page = 1, size: Size = 50, offset: Offset = None
    ) -> str:
        """Domains registered in an Essentials organization, paginated with offset/next_offset."""

        async def action(client: ProofpointClient) -> dict:
            org = path_segment(org_domain, "org_domain")
            return await _list_page(client, f"/orgs/{org}/domains", "domains", page, size, offset)

        return await run_tool(
            "proofpoint_essentials_list_domains", client_factory, action,
            requires=requires, not_configured=NOT_CONFIGURED_ESSENTIALS_ADMIN,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_essentials_get_domain(org_domain: OrgDomain, domain: Annotated[str, Field(description="The domain to look up, e.g. example.com.")]) -> str:
        """One domain's Essentials record. A domain not in the organization returns not_found."""

        async def action(client: ProofpointClient) -> Any:
            org = path_segment(org_domain, "org_domain")
            dom = path_segment(domain, "domain")
            return await client.essentials_admin("GET", f"/orgs/{org}/domains/{dom}")

        return await run_tool(
            "proofpoint_essentials_get_domain", client_factory, action,
            requires=requires, not_configured=NOT_CONFIGURED_ESSENTIALS_ADMIN,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_essentials_list_users(
        org_domain: OrgDomain, page: Page = 1, size: Size = 50, offset: Offset = None
    ) -> str:
        """Users in an Essentials organization, paginated with offset/next_offset."""

        async def action(client: ProofpointClient) -> dict:
            org = path_segment(org_domain, "org_domain")
            return await _list_page(client, f"/orgs/{org}/users", "users", page, size, offset)

        return await run_tool(
            "proofpoint_essentials_list_users", client_factory, action,
            requires=requires, not_configured=NOT_CONFIGURED_ESSENTIALS_ADMIN,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_essentials_get_user(org_domain: OrgDomain, email: Annotated[str, Field(description="The user's email address.")]) -> str:
        """One user's Essentials record. An email not in the organization returns not_found."""

        async def action(client: ProofpointClient) -> Any:
            org = path_segment(org_domain, "org_domain")
            user = path_segment(email, "email")
            return await client.essentials_admin("GET", f"/orgs/{org}/users/{user}")

        return await run_tool(
            "proofpoint_essentials_get_user", client_factory, action,
            requires=requires, not_configured=NOT_CONFIGURED_ESSENTIALS_ADMIN,
        )
