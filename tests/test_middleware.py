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
"""Credential middleware: 401 on missing headers, cluster URL checks, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from proofpoint_mcp.__main__ import build_http_app
from proofpoint_mcp.config import (
    ALLOWED_ESSENTIALS_ADMIN_SUFFIX,
    ALLOWED_ESSENTIALS_THREAT_SUFFIX,
    DEFAULT_ESSENTIALS_ADMIN_URL,
    DEFAULT_ESSENTIALS_THREAT_URL,
)
from proofpoint_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
    normalize_base_url,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
CREDS = {
    "X-Proofpoint-Service-Principal": "your-principal",
    "X-Proofpoint-Service-Secret": "your-secret",
}
# Proofpoint Essentials (PRD-21255): independent credential sets, neither related to TAP.
ESSENTIALS_ADMIN_CREDS = {
    "X-Proofpoint-Essentials-User": "admin@example.com",
    "X-Proofpoint-Essentials-Password": "your-essentials-password",
}
ESSENTIALS_THREAT_CREDS = {
    "X-Proofpoint-Essentials-Threat-Key": "your-threat-key",
    "X-Proofpoint-Essentials-Threat-Secret": "your-threat-secret",
}
ALL_CREDENTIAL_HEADERS = list(CREDS) + list(ESSENTIALS_ADMIN_CREDS) + list(ESSENTIALS_THREAT_CREDS)


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_no_credentials_at_all_is_401_naming_all_three_sets():
    # TC-PFE-007 (AC5): no Proofpoint headers of any kind -> 401 naming TAP, Essentials Admin
    # and Essentials Threat, not just TAP (this is the one behavior change in this ticket).
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS)
    assert resp.status_code == 401
    body = resp.json()
    assert body["credential_sets"] == [list(CREDS), list(ESSENTIALS_ADMIN_CREDS), list(ESSENTIALS_THREAT_CREDS)]
    for header in ALL_CREDENTIAL_HEADERS:
        assert header in body["message"], header


@pytest.mark.parametrize("drop", list(CREDS))
def test_an_incomplete_tap_pair_alone_is_still_401(drop):
    # AC5: a partial set does not satisfy the gateway when no other complete set is present.
    headers = {k: v for k, v in CREDS.items() if k != drop}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401


@pytest.mark.parametrize("creds", [ESSENTIALS_ADMIN_CREDS, ESSENTIALS_THREAT_CREDS], ids=["essentials_admin", "essentials_threat"])
def test_a_complete_non_tap_set_alone_satisfies_the_gateway(creds):
    # TC-PFE-010 (AC6): only Essentials headers, no TAP at all -> 200, not a 401.
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | creds)
    assert resp.status_code == 200


def test_placeholder_counts_as_missing():
    with _client() as client:
        resp = client.post(
            "/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Proofpoint-Service-Secret": "${SECRET}"}
        )
    assert resp.status_code == 401


def test_placeholder_values_still_list_tools():
    # The admin console refreshes the tool catalog with placeholder header values.
    names = ALL_CREDENTIAL_HEADERS + [
        "X-Proofpoint-Cluster-Url", "X-Proofpoint-Reports-Key", "X-Proofpoint-Reports-Secret",
        "X-Proofpoint-Essentials-Admin-Url", "X-Proofpoint-Essentials-Threat-Url",
    ]
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | {name: "placeholder" for name in names})
    assert resp.status_code == 200
    assert "proofpoint_tap_get_all_threats" in resp.text
    assert "proofpoint_essentials_list_domains" in resp.text
    assert "proofpoint_essentials_threat_get_all" in resp.text


def test_foreign_cluster_url_is_reported_by_tools():
    seen = _run_middleware(_raw({"X-Proofpoint-Cluster-Url": "https://evil.example"}))
    assert "proofpoint.com" in seen["client"].header_error
    assert seen["credentials"].base_url == "https://tap-api-v2.proofpoint.com"
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "proofpoint_status", "arguments": {}}}
    with _client() as client:
        resp = client.post(
            "/mcp", json=call, headers=MCP_HEADERS | CREDS | {"X-Proofpoint-Cluster-Url": "https://evil.example"}
        )
    assert resp.status_code == 200
    assert '\\"invalid_argument\\"' in resp.text and "on a proofpoint.com host" in resp.text


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS)
    assert resp.status_code == 200
    for name in ("proofpoint_navigate", "proofpoint_tap_get_all_threats", "proofpoint_url_decode"):
        assert name in resp.text


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "https://tap-api-v2.proofpoint.com"),
        ("https://tap-api-v2.proofpoint.com/", "https://tap-api-v2.proofpoint.com"),
        ("tap-api-v2.proofpoint.com", "https://tap-api-v2.proofpoint.com"),
        ("https://TAP-API-V2.Proofpoint.com:443", "https://tap-api-v2.proofpoint.com:443"),
    ],
)
def test_cluster_url_normalised(value, expected):
    assert normalize_base_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "http://tap-api-v2.proofpoint.com",
        "https://proofpoint.com.evil.example",
        "https://evilproofpoint.com",
        "https://tap-api-v2.proofpoint.com/v2",
        "https://user:pw@tap-api-v2.proofpoint.com",
        "https://tap-api-v2.proofpoint.com?x=1",
    ],
)
def test_cluster_url_rejected(value):
    with pytest.raises(ValueError):
        normalize_base_url(value)


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "https://us1.proofpointessentials.com/api/v1"),
        ("https://us5.proofpointessentials.com/api/v1/", "https://us5.proofpointessentials.com/api/v1"),
        ("us5.proofpointessentials.com", "https://us5.proofpointessentials.com/api/v1"),
    ],
)
def test_essentials_admin_url_normalised(value, expected):
    assert normalize_base_url(value, DEFAULT_ESSENTIALS_ADMIN_URL, ALLOWED_ESSENTIALS_ADMIN_SUFFIX) == expected


@pytest.mark.parametrize(
    "value",
    ["https://us-siem.evil.example", "https://us-siem.proofpointessentials.com/extra/path"],
)
def test_essentials_threat_url_rejected(value):
    with pytest.raises(ValueError):
        normalize_base_url(value, DEFAULT_ESSENTIALS_THREAT_URL, ALLOWED_ESSENTIALS_THREAT_SUFFIX)


def test_essentials_threat_url_normalised():
    assert normalize_base_url(
        "eu-siem.proofpointessentials.com", DEFAULT_ESSENTIALS_THREAT_URL, ALLOWED_ESSENTIALS_THREAT_SUFFIX
    ) == "https://eu-siem.proofpointessentials.com"


def _raw(extra: dict[str, str] | None = None) -> list[tuple[bytes, bytes]]:
    return [(k.lower().encode(), v.encode()) for k, v in (CREDS | (extra or {})).items()]


def _raw_only(headers: dict[str, str]) -> list[tuple[bytes, bytes]]:
    """Headers with no implicit TAP pair added -- for essentials-only scenarios (AC6/AC8)."""
    return [(k.lower().encode(), v.encode()) for k, v in headers.items()]


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_headers_reach_request_context_and_are_reset():
    seen = _run_middleware(_raw({"X-Proofpoint-Service-Principal": " p1 "}))
    creds = seen["credentials"]
    assert (creds.principal, creds.secret, creds.base_url) == ("p1", "your-secret", "https://tap-api-v2.proofpoint.com")
    assert creds.reports_key is None and not seen["client"].has_reports_credentials
    assert _credentials_var.get() is None


def test_optional_reports_headers():
    seen = _run_middleware(_raw({"X-Proofpoint-Reports-Key": "k", "X-Proofpoint-Reports-Secret": "s"}))
    assert seen["client"].has_reports_credentials


def test_essentials_admin_only_reaches_context_with_empty_tap_fields():
    # AC6/AC8: Essentials Admin alone, no TAP headers at all.
    seen = _run_middleware(_raw_only(ESSENTIALS_ADMIN_CREDS))
    creds, client = seen["credentials"], seen["client"]
    assert (creds.principal, creds.secret) == ("", "")
    assert not client.has_reports_credentials and not client.has_essentials_threat_credentials
    assert client.has_essentials_admin_credentials
    assert creds.essentials_admin_url == "https://us1.proofpointessentials.com/api/v1"


def test_essentials_threat_only_reaches_context_with_empty_tap_fields():
    seen = _run_middleware(_raw_only(ESSENTIALS_THREAT_CREDS))
    creds, client = seen["credentials"], seen["client"]
    assert (creds.principal, creds.secret) == ("", "")
    assert not client.has_essentials_admin_credentials
    assert client.has_essentials_threat_credentials
    assert creds.essentials_threat_url == "https://us-siem.proofpointessentials.com"


def test_tap_only_has_no_essentials_credentials():
    # AC6 regression: a TAP-only caller is unaffected by the Essentials fields existing.
    seen = _run_middleware(_raw())
    client = seen["client"]
    assert not client.has_essentials_admin_credentials and not client.has_essentials_threat_credentials


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().principal
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().principal))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(principal: str) -> dict:
        return {"type": "http", "path": "/mcp", "headers": _raw({"X-Proofpoint-Service-Principal": principal})}

    async def both():
        await asyncio.gather(middleware(scope("tenant-a"), receive, send), middleware(scope("tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_concurrent_requests_do_not_share_essentials_credentials():
    # TC-PFE-012 (AC8): two concurrent requests with two different orgs' Essentials Admin
    # credentials never see each other's values.
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().essentials_user
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().essentials_user))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(user: str) -> dict:
        return {"type": "http", "path": "/mcp", "headers": _raw_only(ESSENTIALS_ADMIN_CREDS | {"X-Proofpoint-Essentials-User": user})}

    async def both():
        await asyncio.gather(middleware(scope("org-a-admin"), receive, send), middleware(scope("org-b-admin"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("org-a-admin", "org-a-admin"), ("org-b-admin", "org-b-admin")]


def test_credentials_repr_hides_secrets():
    seen = _run_middleware(_raw({"X-Proofpoint-Service-Secret": "very-secret-value"}))
    text = repr(seen["credentials"])
    assert "very-secret-value" not in text and "your-principal" not in text


def test_credentials_repr_hides_essentials_secrets():
    seen = _run_middleware(_raw_only(ESSENTIALS_ADMIN_CREDS | ESSENTIALS_THREAT_CREDS))
    text = repr(seen["credentials"])
    assert "admin@example.com" not in text
    assert "your-essentials-password" not in text
    assert "your-threat-key" not in text
    assert "your-threat-secret" not in text
