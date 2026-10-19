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


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("drop", list(CREDS))
def test_each_header_is_required(drop):
    headers = {k: v for k, v in CREDS.items() if k != drop}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    body = resp.json()
    assert body["required_headers"] == list(CREDS)
    assert drop in body["message"]


def test_placeholder_counts_as_missing():
    with _client() as client:
        resp = client.post(
            "/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Proofpoint-Service-Secret": "${SECRET}"}
        )
    assert resp.status_code == 401


def test_foreign_cluster_url_is_rejected():
    with _client() as client:
        resp = client.post(
            "/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | {"X-Proofpoint-Cluster-Url": "https://evil.example"}
        )
    assert resp.status_code == 400
    assert "proofpoint.com" in resp.json()["message"]


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


def _raw(extra: dict[str, str] | None = None) -> list[tuple[bytes, bytes]]:
    return [(k.lower().encode(), v.encode()) for k, v in (CREDS | (extra or {})).items()]


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


def test_credentials_repr_hides_secrets():
    seen = _run_middleware(_raw({"X-Proofpoint-Service-Secret": "very-secret-value"}))
    text = repr(seen["credentials"])
    assert "very-secret-value" not in text and "your-principal" not in text
