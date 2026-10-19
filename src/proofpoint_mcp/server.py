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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import ProofpointClient, ProofpointCredentials
from .config import ALLOWED_HOST_SUFFIX, DEFAULT_TAP_URL, Settings

HEADER_PRINCIPAL = "X-Proofpoint-Service-Principal"
HEADER_SECRET = "X-Proofpoint-Service-Secret"
HEADER_CLUSTER_URL = "X-Proofpoint-Cluster-Url"
HEADER_REPORTS_KEY = "X-Proofpoint-Reports-Key"
HEADER_REPORTS_SECRET = "X-Proofpoint-Reports-Secret"
REQUIRED_HEADERS = [HEADER_PRINCIPAL, HEADER_SECRET]
OPTIONAL_HEADERS = [HEADER_CLUSTER_URL, HEADER_REPORTS_KEY, HEADER_REPORTS_SECRET]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[ProofpointCredentials | None] = contextvars.ContextVar(
    "proofpoint_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("proofpoint_request_id", default="-")

INSTRUCTIONS = (
    "Proofpoint Targeted Attack Protection (TAP) shows the email threats aimed at "
    "an organisation: malicious messages delivered or blocked, and clicks on "
    "malicious URLs.\n"
    "Usage:\n"
    "- Recent activity: proofpoint_tap_get_all_threats (or one of the four "
    "tap_get_* views). SIEM queries cover at most 1 hour per call and at most "
    "7 days back; give sinceSeconds (<=3600), sinceTime or an ISO8601 interval. "
    "The default is the last hour.\n"
    "- Find a message: proofpoint_smart_search_trace / "
    "proofpoint_forensics_search_messages filter those events by sender, "
    "recipient, subject or message id.\n"
    "- Drill down with the threatID / campaignId from an event: "
    "proofpoint_threat_get_by_id, proofpoint_forensics_get_threat, "
    "proofpoint_threat_get_campaign, proofpoint_threat_get_iocs.\n"
    "- People: proofpoint_people_get_vap (most attacked), _get_top_clickers, "
    "_get_user_risk(email).\n"
    "- proofpoint_url_decode turns rewritten urldefense URLs back into the original.\n"
    "- reports_* need a separate Dashboard Reports API key; each report section "
    "allows 20 calls a day.\n"
    "- Quarantine, policy, DLP and message-pull tools are not part of the TAP API "
    "and return an error explaining that.\n"
    "Quotas are tight (People and Campaign: 50 calls per 24h); avoid repeating calls."
)


def get_client_from_context() -> ProofpointClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return ProofpointClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def normalize_base_url(value: str | None) -> str:
    """The TAP base URL: https on a proofpoint.com host, no path or query."""
    if not value:
        return DEFAULT_TAP_URL
    text = value.strip().rstrip("/")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not (host == ALLOWED_HOST_SUFFIX[1:] or host.endswith(ALLOWED_HOST_SUFFIX)):
        raise ValueError(f"{HEADER_CLUSTER_URL} must be an https URL on a proofpoint.com host")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError(f"{HEADER_CLUSTER_URL} must be a bare host URL such as {DEFAULT_TAP_URL}")
    port = f":{parts.port}" if parts.port else ""
    return f"https://{host}{port}"


class GatewayCredentialsMiddleware:
    """Reads the Proofpoint headers on /mcp requests; 401 when a required one is missing."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        values = {name: _clean(request.headers.get(name)) for name in REQUIRED_HEADERS + OPTIONAL_HEADERS}
        missing = [name for name in REQUIRED_HEADERS if not values[name]]
        if missing:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Missing header(s): {', '.join(missing)}",
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": OPTIONAL_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return
        try:
            base_url = normalize_base_url(values[HEADER_CLUSTER_URL])
        except ValueError as e:
            await JSONResponse({"error": "Invalid header", "message": str(e)}, status_code=400)(scope, receive, send)
            return

        credentials = ProofpointCredentials(
            principal=values[HEADER_PRINCIPAL] or "",
            secret=values[HEADER_SECRET] or "",
            base_url=base_url,
            reports_key=values[HEADER_REPORTS_KEY],
            reports_secret=values[HEADER_REPORTS_SECRET],
        )
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = FastMCP(
        name="proofpoint-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], ProofpointClient | None] = get_client_from_context

    from .tools import navigation, people, reports, search, tap, threats, unsupported, urls

    for module in (navigation, tap, search, threats, people, urls, reports, unsupported):
        module.register(mcp, client_factory)

    return mcp
