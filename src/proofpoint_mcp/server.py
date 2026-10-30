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

from ._arguments import EnvelopeFastMCP
from .api_client import ProofpointClient, ProofpointCredentials
from .config import (
    ALLOWED_ESSENTIALS_ADMIN_SUFFIX,
    ALLOWED_ESSENTIALS_THREAT_SUFFIX,
    ALLOWED_HOST_SUFFIX,
    DEFAULT_ESSENTIALS_ADMIN_URL,
    DEFAULT_ESSENTIALS_THREAT_URL,
    DEFAULT_TAP_URL,
    Settings,
)

HEADER_PRINCIPAL = "X-Proofpoint-Service-Principal"
HEADER_SECRET = "X-Proofpoint-Service-Secret"
HEADER_CLUSTER_URL = "X-Proofpoint-Cluster-Url"
HEADER_REPORTS_KEY = "X-Proofpoint-Reports-Key"
HEADER_REPORTS_SECRET = "X-Proofpoint-Reports-Secret"
# Proofpoint Essentials (PRD-21255): a credential set independent of TAP and of each other.
HEADER_ESSENTIALS_USER = "X-Proofpoint-Essentials-User"
HEADER_ESSENTIALS_PASSWORD = "X-Proofpoint-Essentials-Password"
HEADER_ESSENTIALS_ADMIN_URL = "X-Proofpoint-Essentials-Admin-Url"
HEADER_ESSENTIALS_THREAT_KEY = "X-Proofpoint-Essentials-Threat-Key"
HEADER_ESSENTIALS_THREAT_SECRET = "X-Proofpoint-Essentials-Threat-Secret"
HEADER_ESSENTIALS_THREAT_URL = "X-Proofpoint-Essentials-Threat-Url"

# Each pair is a complete credential set on its own; the gateway requires at least one of the
# three to be fully present (both headers of a pair), not any specific one of them.
CREDENTIAL_SETS: list[tuple[str, str]] = [
    (HEADER_PRINCIPAL, HEADER_SECRET),
    (HEADER_ESSENTIALS_USER, HEADER_ESSENTIALS_PASSWORD),
    (HEADER_ESSENTIALS_THREAT_KEY, HEADER_ESSENTIALS_THREAT_SECRET),
]
REQUIRED_HEADERS = [header for pair in CREDENTIAL_SETS for header in pair]
OPTIONAL_HEADERS = [
    HEADER_CLUSTER_URL,
    HEADER_REPORTS_KEY,
    HEADER_REPORTS_SECRET,
    HEADER_ESSENTIALS_ADMIN_URL,
    HEADER_ESSENTIALS_THREAT_URL,
]

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
    "- essentials_admin_* tools (Essentials Organization Admin credentials) read a "
    "different product, Proofpoint Essentials: domain and user inventory for one "
    "org. essentials_threat_* tools (a separate Essentials Threat Integration "
    "Key/Secret) read Essentials' own SIEM-shaped threat/click/message events, "
    "same window rules as tap_*. Essentials and TAP are independent credential "
    "sets: sending one never requires or affects the other.\n"
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


def normalize_base_url(
    value: str | None,
    default: str = DEFAULT_TAP_URL,
    suffix: str = ALLOWED_HOST_SUFFIX,
    header_name: str = HEADER_CLUSTER_URL,
) -> str:
    """A base URL: https on a host under ``suffix``, no query, and no path beyond ``default``'s own
    (empty for TAP; ``/api/v1`` for the Essentials Admin API, whose base legitimately has one).

    Generalized (PRD-21255) so the Essentials Admin and Essentials Threat base-url headers reuse
    this instead of a copy-pasted validator; the TAP cluster URL keeps calling it with just
    ``value`` since its defaults are this function's defaults.
    """
    if not value:
        return default
    text = value.strip().rstrip("/")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not (host == suffix[1:] or host.endswith(suffix)):
        raise ValueError(f"{header_name} must be an https URL on a {suffix[1:]} host")
    default_path = urlsplit(default).path.rstrip("/")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/", default_path):
        raise ValueError(f"{header_name} must be a bare host URL such as {default}")
    port = f":{parts.port}" if parts.port else ""
    return f"https://{host}{port}{default_path}"


# (header, default base url, allowed host suffix) for every base-url header this gateway
# validates the same way. A malformed one does not block the request (tools/list must still
# work); the first error found is reported by every tool call instead (see header_error).
_URL_HEADERS: list[tuple[str, str, str]] = [
    (HEADER_CLUSTER_URL, DEFAULT_TAP_URL, ALLOWED_HOST_SUFFIX),
    (HEADER_ESSENTIALS_ADMIN_URL, DEFAULT_ESSENTIALS_ADMIN_URL, ALLOWED_ESSENTIALS_ADMIN_SUFFIX),
    (HEADER_ESSENTIALS_THREAT_URL, DEFAULT_ESSENTIALS_THREAT_URL, ALLOWED_ESSENTIALS_THREAT_SUFFIX),
]


class GatewayCredentialsMiddleware:
    """Reads the Proofpoint headers on /mcp requests; 401 when no credential set is present.

    Three credential sets are recognised -- TAP, Essentials Admin, Essentials Threat (PRD-21255)
    -- and each is independently sufficient: at least one must be fully present (both headers of
    its pair), but a caller never needs more than one. A caller already sending only TAP headers
    sees no change here (TAP is one of the three sets, same as before this ticket).

    A malformed base-url header does not block the request (tools/list must work with any
    values); tools report it instead and never send credentials to any host.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        values = {name: _clean(request.headers.get(name)) for name in REQUIRED_HEADERS + OPTIONAL_HEADERS}
        satisfied = any(values[a] and values[b] for a, b in CREDENTIAL_SETS)
        if not satisfied:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        "At least one full credential set is required: TAP service principal/secret "
                        f"({HEADER_PRINCIPAL} + {HEADER_SECRET}), Proofpoint Essentials Admin "
                        f"username/password ({HEADER_ESSENTIALS_USER} + {HEADER_ESSENTIALS_PASSWORD}), "
                        f"or Proofpoint Essentials Threat API Integration Key/Secret "
                        f"({HEADER_ESSENTIALS_THREAT_KEY} + {HEADER_ESSENTIALS_THREAT_SECRET})."
                    ),
                    "credential_sets": [list(pair) for pair in CREDENTIAL_SETS],
                    "optional_headers": OPTIONAL_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return

        header_error = None
        resolved: dict[str, str] = {}
        for header_name, default, suffix in _URL_HEADERS:
            try:
                resolved[header_name] = normalize_base_url(values[header_name], default, suffix, header_name)
            except ValueError as e:
                # Never the caller's value: the client is built on the default host, and tools
                # return header_error before any request. First error found wins; it is rare
                # for a caller to send two malformed base urls at once.
                if header_error is None:
                    header_error = str(e)
                resolved[header_name] = default

        credentials = ProofpointCredentials(
            principal=values[HEADER_PRINCIPAL] or "",
            secret=values[HEADER_SECRET] or "",
            base_url=resolved[HEADER_CLUSTER_URL],
            reports_key=values[HEADER_REPORTS_KEY],
            reports_secret=values[HEADER_REPORTS_SECRET],
            essentials_user=values[HEADER_ESSENTIALS_USER],
            essentials_password=values[HEADER_ESSENTIALS_PASSWORD],
            essentials_admin_url=resolved[HEADER_ESSENTIALS_ADMIN_URL],
            essentials_threat_key=values[HEADER_ESSENTIALS_THREAT_KEY],
            essentials_threat_secret=values[HEADER_ESSENTIALS_THREAT_SECRET],
            essentials_threat_url=resolved[HEADER_ESSENTIALS_THREAT_URL],
            header_error=header_error,
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
    mcp = EnvelopeFastMCP(
        name="proofpoint-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], ProofpointClient | None] = get_client_from_context

    from .tools import essentials_admin, essentials_threat, navigation, people, reports, search, tap, threats, unsupported, urls

    for module in (
        navigation, tap, search, threats, people, urls, reports, unsupported, essentials_admin, essentials_threat,
    ):
        module.register(mcp, client_factory)

    return mcp
