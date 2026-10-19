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
"""URL Decoder API: turn URL Defense rewritten links back into their targets."""

from typing import Annotated, Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ProofpointClient
from ._common import READ_ONLY, ClientFactory, run_tool

MAX_URLS = 100
REWRITE_HOSTS = ("urldefense.proofpoint.com", "urldefense.com", "urldefense.us")


def is_rewritten(url: str) -> bool:
    host = (urlsplit(url.strip()).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in REWRITE_HOSTS)


async def decode(client: ProofpointClient, urls: list[str]) -> Any:
    cleaned = [u.strip() for u in urls if u and u.strip()]
    if not cleaned:
        raise ValueError("urls must contain at least one URL.")
    if len(cleaned) > MAX_URLS:
        raise ValueError(f"Decode at most {MAX_URLS} URLs per call.")
    # Decoding is a pure function of the input, so a retry is harmless.
    return await client.tap("POST", "/v2/url/decode", body={"urls": cleaned}, idempotent=True)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_url_decode(
        urls: Annotated[list[str], Field(description="URL Defense rewritten URLs (v1, v2 or v3), up to 100.")],
    ) -> str:
        """Decode URL Defense rewritten links (urldefense.com, urldefense.proofpoint.com) to the original URLs.

        Results keep the input order; each has decodedUrl and success, plus the message GUID and recipient
        when known.
        """

        async def action(client: ProofpointClient) -> Any:
            return await decode(client, urls)

        return await run_tool("proofpoint_url_decode", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def proofpoint_url_analyze(
        url: Annotated[str, Field(description="A URL, usually a URL Defense rewritten link from an email.")],
    ) -> str:
        """Break down a link: whether URL Defense rewrote it, the real target URL and its scheme, host, path.

        No reputation verdict: TAP has no URL scoring API. For threat details use the threatID from SIEM events.
        """

        async def action(client: ProofpointClient) -> dict:
            text = url.strip()
            if not text:
                raise ValueError("url must not be blank.")
            target = text
            result: dict[str, Any] = {"input": text, "rewrittenByUrlDefense": is_rewritten(text)}
            if result["rewrittenByUrlDefense"]:
                decoded = await decode(client, [text])
                rows = decoded.get("urls") if isinstance(decoded, dict) else None
                first = rows[0] if rows and isinstance(rows[0], dict) else {}
                result["decode"] = first
                if first.get("success") and first.get("decodedUrl"):
                    target = str(first["decodedUrl"])
            parts = urlsplit(target)
            result["target"] = {
                "url": target,
                "scheme": parts.scheme or None,
                "host": parts.hostname,
                "port": parts.port,
                "path": parts.path or None,
                "query": parts.query or None,
            }
            return result

        return await run_tool("proofpoint_url_analyze", client_factory, action)
