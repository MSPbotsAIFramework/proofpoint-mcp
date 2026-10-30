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
"""Async client for the Proofpoint TAP and Dashboard Reports APIs."""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from ._json import error_envelope
from .config import REPORTS_API, REPORTS_TOKEN_URL

logger = logging.getLogger("proofpoint_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own values, so
# sharing the pool across tenants is safe.
_shared_http_client: httpx.AsyncClient | None = None


class _RejectAllCookies(DefaultCookiePolicy):
    """Never store or send a cookie: the HTTP client is shared by every tenant."""

    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: ANN001 - stdlib signature
        return False


def _no_cookies() -> CookieJar:
    # A plain CookieJar: httpx uses it as is (an httpx.Cookies would be copied into a default jar).
    return CookieJar(policy=_RejectAllCookies())


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(cookies=_no_cookies(), timeout=_TIMEOUT)
    return _shared_http_client


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    # TAP and Reports throttles are rolling 24-hour (or per-minute) quotas,
    # so an immediate retry by the agent does not help.
    429: ("rate_limited", False),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class ProofpointError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Proofpoint API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class ProofpointCredentials:
    principal: str
    secret: str
    base_url: str
    reports_key: str | None = None
    reports_secret: str | None = None
    # Proofpoint Essentials: a different product from TAP, independent credential sets
    # (PRD-21255). Any of (principal, secret), (essentials_user, essentials_password) or
    # (essentials_threat_key, essentials_threat_secret) satisfies the gateway on its own.
    essentials_user: str | None = None
    essentials_password: str | None = None
    essentials_admin_url: str | None = None
    essentials_threat_key: str | None = None
    essentials_threat_secret: str | None = None
    essentials_threat_url: str | None = None
    # Set when a header value is malformed: tools then return invalid_argument
    # instead of calling Proofpoint, while tools/list still works.
    header_error: str | None = None

    def __repr__(self) -> str:  # never leak secrets into logs or tracebacks
        return (
            "ProofpointCredentials(principal=<redacted>, secret=<redacted>, "
            f"base_url={self.base_url!r}, essentials_user=<redacted>, "
            "essentials_password=<redacted>, essentials_threat_key=<redacted>, "
            "essentials_threat_secret=<redacted>)"
        )


class ProofpointClient:
    """Proofpoint API wrapper for one caller's credentials.

    Lives for a single MCP request. The Reports Bearer token is requested
    lazily and kept only on this instance; nothing is cached across requests.
    """

    def __init__(self, credentials: ProofpointCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.header_error = credentials.header_error
        self._reports_token: str | None = None
        self._token_lock = asyncio.Lock()

    @property
    def has_reports_credentials(self) -> bool:
        return bool(self._credentials.reports_key and self._credentials.reports_secret)

    @property
    def has_essentials_admin_credentials(self) -> bool:
        return bool(self._credentials.essentials_user and self._credentials.essentials_password)

    @property
    def has_essentials_threat_credentials(self) -> bool:
        return bool(self._credentials.essentials_threat_key and self._credentials.essentials_threat_secret)

    def _client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    def _basic(self) -> str:
        raw = f"{self._credentials.principal}:{self._credentials.secret}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    async def tap(
        self,
        method: str,
        path: str,
        params: list[tuple[str, Any]] | dict[str, Any] | None = None,
        body: Any = None,
        idempotent: bool = False,
    ) -> Any:
        """Call a TAP API (Basic auth) on the caller's cluster URL."""
        url = f"{self._credentials.base_url}/{path.lstrip('/')}"
        headers = {"Authorization": self._basic(), "Accept": "application/json"}
        return await self._send(method, url, path, params, body, headers, idempotent or method == "GET")

    async def reports(self, path: str, params: list[tuple[str, Any]] | dict[str, Any] | None = None) -> Any:
        """Call a Dashboard Reports API (Bearer token from the reports API key)."""
        if not self.has_reports_credentials:
            raise ValueError(
                "Dashboard Reports need their own API key: send X-Proofpoint-Reports-Key and "
                "X-Proofpoint-Reports-Secret (Admin Portal > Settings > API Key Management > "
                "Threat Protection). The TAP service principal is not accepted by this API."
            )
        token = await self._get_reports_token()
        url = f"{REPORTS_API}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        return await self._send("GET", url, f"reports/{path.lstrip('/')}", params, None, headers, True)

    async def essentials_admin(
        self,
        method: str,
        path: str,
        params: list[tuple[str, Any]] | dict[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        """Call the Proofpoint Essentials Admin/Reporting API.

        Auth is two literal headers (X-User / X-Password), not HTTP Basic -- the one place the
        auth shape differs from every other method on this client.
        """
        if not self.has_essentials_admin_credentials:
            raise ValueError(
                "Proofpoint Essentials Admin credentials are missing for this request "
                "(X-Proofpoint-Essentials-User, X-Proofpoint-Essentials-Password)."
            )
        url = f"{self._credentials.essentials_admin_url}/{path.lstrip('/')}"
        headers = {
            "X-User": self._credentials.essentials_user or "",
            "X-Password": self._credentials.essentials_password or "",
            "Accept": "application/json",
        }
        label = f"essentials_admin/{path.lstrip('/')}"
        return await self._send(method, url, label, params, body, headers, method == "GET")

    async def essentials_threat(self, path: str, params: list[tuple[str, Any]] | dict[str, Any] | None = None) -> Any:
        """Call the Essentials Threat API (HTTP Basic with the Integration Key/Secret).

        Structurally identical to ``tap()`` -- same SIEM path shape, just a different credential
        pair and host.
        """
        if not self.has_essentials_threat_credentials:
            raise ValueError(
                "Proofpoint Essentials Threat API credentials are missing for this request "
                "(X-Proofpoint-Essentials-Threat-Key, X-Proofpoint-Essentials-Threat-Secret)."
            )
        url = f"{self._credentials.essentials_threat_url}/{path.lstrip('/')}"
        raw = f"{self._credentials.essentials_threat_key}:{self._credentials.essentials_threat_secret}".encode()
        headers = {"Authorization": "Basic " + base64.b64encode(raw).decode(), "Accept": "application/json"}
        label = f"essentials_threat/{path.lstrip('/')}"
        return await self._send("GET", url, label, params, None, headers, True)

    async def _get_reports_token(self) -> str:
        async with self._token_lock:
            if self._reports_token is None:
                self._reports_token = await self._request_token()
            return self._reports_token

    async def _request_token(self) -> str:
        form = {
            "grant_type": "client_credentials",
            "client_id": self._credentials.reports_key or "",
            "client_secret": self._credentials.reports_secret or "",
        }
        try:
            resp = await self._client().post(REPORTS_TOKEN_URL, data=form, headers={"Accept": "application/json"})
        except httpx.RequestError as e:
            raise ProofpointError(0, f"Network error requesting a Reports token: {type(e).__name__}") from e
        logger.info("proofpoint_api method=POST path=token status=%s", resp.status_code)
        if resp.status_code in (400, 401, 403):
            raise ProofpointError(401, "Proofpoint rejected the Reports API key / secret")
        if resp.status_code >= 400:
            raise ProofpointError(resp.status_code, f"Proofpoint token endpoint returned HTTP {resp.status_code}")
        try:
            token = resp.json().get("access_token")
        except (ValueError, AttributeError):
            token = None
        if not token:
            raise ProofpointError(502, "Proofpoint token response had no access_token")
        return token

    async def _send(
        self,
        method: str,
        url: str,
        label: str,
        params: list[tuple[str, Any]] | dict[str, Any] | None,
        body: Any,
        headers: dict[str, str],
        retry_failures: bool,
    ) -> Any:
        query = _query(params)
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: ProofpointError | None = None
            try:
                resp = await self._client().request(method, url, params=query, json=body, headers=headers)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, ProofpointError(0, f"Timed out calling Proofpoint ({method} {label})")
            except httpx.RequestError as e:
                status = 0
                error = ProofpointError(0, f"Network error calling Proofpoint ({method} {label}): {type(e).__name__}")

            logger.info(
                "proofpoint_api method=%s path=%s status=%s ms=%d attempt=%d",
                method, label, status, (time.monotonic() - t0) * 1000, attempt,
            )

            # 429 is retried only when the server says it clears within seconds
            # (TAP quotas are 24-hour windows). Other failures are retried only
            # for reads and pure functions, so nothing runs twice.
            delay = _retry_delay(resp, attempt)
            retryable = (status == 429 and delay is not None) or (retry_failures and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                wait = delay if delay is not None else min(float(2**attempt), _MAX_BACKOFF_SECONDS)
                if time.monotonic() - started + wait < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(wait)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                raise ProofpointError(resp.status_code, _error_message(resp, label))
            return _parse_body(resp)


def _query(params: list[tuple[str, Any]] | dict[str, Any] | None) -> list[tuple[str, str]]:
    pairs = list(params.items()) if isinstance(params, dict) else list(params or [])
    out: list[tuple[str, str]] = []
    for key, value in pairs:
        if value is None:
            continue
        if isinstance(value, bool):
            out.append((key, "true" if value else "false"))
        else:
            out.append((key, str(value)))
    return out


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float | None:
    """Seconds from a short Retry-After header, or None when there is none."""
    if resp is None:
        return None
    retry_after = resp.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        seconds = float(retry_after)
    except ValueError:
        return None
    return seconds if 0 <= seconds <= _MAX_BACKOFF_SECONDS else None


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content or not resp.content.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_text": resp.text}


def _error_message(resp: httpx.Response, label: str) -> str:
    fallback = f"Proofpoint returned HTTP {resp.status_code} for {label}"
    if resp.status_code == 401:
        return f"{fallback}: the credentials were rejected (check principal / secret and cluster URL)"
    if resp.status_code == 429:
        return f"{fallback}: the API quota for this endpoint is used up; try again later"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        for key in ("message", "error_description", "error", "detail", "title"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return f"{fallback}: {value[:300]}"
    return fallback
