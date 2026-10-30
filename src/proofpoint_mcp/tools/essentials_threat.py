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
"""Proofpoint Essentials Threat API (PRD-21255): the same SIEM path shape as TAP, on its own host
and credential pair (Integration Key/Secret), independent of TAP.
"""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..api_client import ProofpointClient
from ._common import ClientFactory, NOT_CONFIGURED_ESSENTIALS_THREAT
from .tap import _register_siem_tool

ESSENTIALS_THREAT_SIEM_TOOLS = [
    (
        "proofpoint_essentials_threat_get_messages_blocked",
        "messages/blocked",
        "Essentials: messages with threats that were blocked or quarantined in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret (independent of TAP and Essentials Admin).",
    ),
    (
        "proofpoint_essentials_threat_get_messages_delivered",
        "messages/delivered",
        "Essentials: messages with threats that were delivered to users in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret.",
    ),
    (
        "proofpoint_essentials_threat_get_clicks_blocked",
        "clicks/blocked",
        "Essentials: clicks on malicious URLs that were blocked, in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret.",
    ),
    (
        "proofpoint_essentials_threat_get_clicks_permitted",
        "clicks/permitted",
        "Essentials: clicks on malicious URLs that were allowed through, in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret.",
    ),
    (
        "proofpoint_essentials_threat_get_issues",
        "issues",
        "Essentials: permitted clicks and delivered messages combined, in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret.",
    ),
    (
        "proofpoint_essentials_threat_get_all",
        "all",
        "Essentials: every threat message and click event in a time window.\n\n"
        "At most one hour per call, up to 3 days back; default is the last hour. Needs the "
        "Essentials Threat API Integration Key/Secret.",
    ),
]


async def _essentials_threat_siem_call(client: ProofpointClient, path: str, params: list[tuple[str, Any]]) -> Any:
    return await client.essentials_threat(path, params)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    for name, endpoint, doc in ESSENTIALS_THREAT_SIEM_TOOLS:
        _register_siem_tool(
            mcp,
            client_factory,
            name,
            endpoint,
            doc,
            caller=_essentials_threat_siem_call,
            requires=lambda client: client.has_essentials_threat_credentials,
            not_configured=NOT_CONFIGURED_ESSENTIALS_THREAT,
        )
