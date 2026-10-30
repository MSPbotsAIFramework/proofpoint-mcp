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
"""Quarantine tools backed by Proofpoint Protection Server (PRD-21254). No network access:
PPS responses are mocked the same way test_api_client.py mocks TAP/Reports."""

import json

import httpx
import pytest

from proofpoint_mcp import api_client
from proofpoint_mcp.api_client import ProofpointCredentials
from proofpoint_mcp.server import _credentials_var, create_mcp_server

TAP = "https://tap-api-v2.proofpoint.com"
PPS = "https://tenant.pphosted.com"


def _creds(**pps) -> ProofpointCredentials:
    return ProofpointCredentials(principal="prin", secret="sec", base_url=TAP, **pps)


TAP_ONLY = _creds()
PPS_CREDS = _creds(pps_base_url=PPS, pps_username="ppsuser", pps_password="ppspass")


class Recorder:
    """Mock transport: replies by "METHOD host/path"."""

    def __init__(self, routes=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.method} {request.url.host}{request.url.path}"
        reply = self.routes.get(key, httpx.Response(404, json={"error": "no such route in test"}))
        if callable(reply):
            return reply(request)
        if isinstance(reply, httpx.Response):
            return reply
        return httpx.Response(200, json=reply)


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, creds: ProofpointCredentials = PPS_CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(creds)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


RECORD_A = {
    "folder": "SPAM", "localguid": "g-a1", "from": "bad@evil.example", "rcpts": ["user@corp.example"],
    "subject": "Win a prize", "date": "2026-10-30T01:00:00Z", "spamscore": 95, "size": 1024,
}
RECORD_B = {
    "folder": "PHISH", "localguid": "g-b2", "from": "phish@evil.example", "rcpts": ["user2@corp.example"],
    "subject": "Reset your password", "date": "2026-10-30T02:00:00Z", "spamscore": 88, "size": 2048,
}


# ---- AC1 / AC2: list ----------------------------------------------------------------------


async def test_list_returns_real_messages_with_pps_credentials(monkeypatch):
    rec = Recorder({f"GET tenant.pphosted.com/rest/v1/quarantine": {"records": [RECORD_A]}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_list", {"folder": "SPAM"})
    assert out["messages"] == [{
        "message_id": "SPAM:g-a1", "folder": "SPAM", "sender": "bad@evil.example",
        "recipients": ["user@corp.example"], "subject": "Win a prize", "date": "2026-10-30T01:00:00Z",
        "spam_score": 95, "size": 1024,
    }]
    query = dict(rec.requests[0].url.params)
    assert query["folder"] == "SPAM" and query["messagestatus"] == "t"


async def test_list_empty_folder_returns_empty_list(monkeypatch):
    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": {"records": []}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_list", {"folder": "VIRUS"})
    assert out["messages"] == [] and out["total"] == 0 and out["has_more"] is False


# ---- AC2: search (OR across sender / recipient / subject) ---------------------------------


async def test_search_matches_quarantined_message_by_subject(monkeypatch):
    def reply(request: httpx.Request):
        query = dict(request.url.params)
        if query.get("subject") == "prize":
            return httpx.Response(200, json={"records": [RECORD_A]})
        return httpx.Response(200, json={"records": []})

    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": reply})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_search", {"query": "prize"})
    assert [m["message_id"] for m in out["messages"]] == ["SPAM:g-a1"]
    # one lookup per field (sender, recipient, subject), merged and de-duplicated
    assert len(rec.requests) == 3


async def test_search_no_match_returns_empty_list(monkeypatch):
    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": {"records": []}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_search", {"query": "nothing-matches-this"})
    assert out["messages"] == []


async def test_search_deduplicates_a_message_matched_by_more_than_one_field(monkeypatch):
    # RECORD_A would match both subject and sender filters if the vendor's own matching is loose;
    # the tool must not return it twice.
    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": {"records": [RECORD_A]}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_search", {"query": "evil"})
    assert len(out["messages"]) == 1


# ---- AC5: not_configured without PPS headers ----------------------------------------------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("proofpoint_quarantine_list", {}),
        ("proofpoint_quarantine_search", {"query": "x"}),
        ("proofpoint_quarantine_release", {"message_id": "SPAM:g-a1"}),
        ("proofpoint_quarantine_delete", {"message_id": "SPAM:g-a1"}),
    ],
)
async def test_quarantine_tools_return_not_configured_without_pps_headers(monkeypatch, tool, args):
    rec = Recorder()
    out = await _call(monkeypatch, rec, tool, args, TAP_ONLY)
    assert out["error"]["code"] == "not_configured"
    assert "Pps" in out["error"]["message"]
    assert not rec.requests  # never calls PPS (or TAP) without the right credentials


# ---- AC6: PPS rejects the credentials -------------------------------------------------------


async def test_quarantine_list_with_wrong_pps_credentials_returns_unauthorized(monkeypatch):
    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": httpx.Response(401)})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_list", {})
    assert out["error"]["code"] == "unauthorized"


# ---- AC7: unknown message id -> not_found ---------------------------------------------------


async def test_release_unknown_message_id_returns_not_found(monkeypatch):
    rec = Recorder({"POST tenant.pphosted.com/rest/v1/quarantine": httpx.Response(404)})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_release", {"message_id": "SPAM:no-such-guid"})
    assert out["error"]["code"] == "not_found"


async def test_delete_unknown_message_id_returns_not_found(monkeypatch):
    rec = Recorder({"POST tenant.pphosted.com/rest/v1/quarantine": httpx.Response(404)})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_delete", {"message_id": "SPAM:no-such-guid"})
    assert out["error"]["code"] == "not_found"


# ---- release / delete happy path (mechanics only; the live round trip is manual, TC-PPQ-005/007) --


async def test_release_sends_action_and_decoded_folder_localguid(monkeypatch):
    rec = Recorder({"POST tenant.pphosted.com/rest/v1/quarantine": {"status": "released"}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_release", {"message_id": "SPAM:g-a1"})
    assert out == {"status": "released"}
    body = json.loads(rec.requests[0].content)
    assert body == {"action": "release", "folder": "SPAM", "localguid": "g-a1"}


async def test_delete_sends_action_delete(monkeypatch):
    rec = Recorder({"POST tenant.pphosted.com/rest/v1/quarantine": {"status": "deleted"}})
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_delete", {"message_id": "PHISH:g-b2"})
    assert out == {"status": "deleted"}
    body = json.loads(rec.requests[0].content)
    assert body == {"action": "delete", "folder": "PHISH", "localguid": "g-b2"}


async def test_release_rejects_a_message_id_not_shaped_like_folder_colon_localguid(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_release", {"message_id": "not-a-real-id"})
    assert out["error"]["code"] == "invalid_argument"
    assert not rec.requests


# ---- AC8: no state shared across requests with different PPS credentials -------------------


async def test_list_isolates_pps_credentials_between_requests(monkeypatch):
    creds_a = _creds(pps_base_url="https://tenant-a.pphosted.com", pps_username="user-a", pps_password="pass-a")
    creds_b = _creds(pps_base_url="https://tenant-b.pphosted.com", pps_username="user-b", pps_password="pass-b")
    rec_a = Recorder({"GET tenant-a.pphosted.com/rest/v1/quarantine": {"records": [RECORD_A]}})
    rec_b = Recorder({"GET tenant-b.pphosted.com/rest/v1/quarantine": {"records": [RECORD_B]}})

    out_a = await _call(monkeypatch, rec_a, "proofpoint_quarantine_list", {}, creds_a)
    out_b = await _call(monkeypatch, rec_b, "proofpoint_quarantine_list", {}, creds_b)

    assert [m["message_id"] for m in out_a["messages"]] == ["SPAM:g-a1"]
    assert [m["message_id"] for m in out_b["messages"]] == ["PHISH:g-b2"]
    assert rec_a.requests[0].url.host == "tenant-a.pphosted.com"
    assert rec_b.requests[0].url.host == "tenant-b.pphosted.com"
    assert rec_a.requests[0].headers["Authorization"] != rec_b.requests[0].headers["Authorization"]


# ---- pps_header_error (malformed PPS base URL) does not touch TAP tools --------------------


async def test_tap_tool_unaffected_by_malformed_pps_base_url(monkeypatch):
    # Build credentials the way the middleware would when X-Proofpoint-Pps-Base-Url is malformed:
    # pps_header_error set, pps_base_url None (see server.GatewayCredentialsMiddleware).
    creds = ProofpointCredentials(
        principal="prin", secret="sec", base_url=TAP,
        pps_header_error="X-Proofpoint-Pps-Base-Url must be an https URL with a host",
    )
    rec = Recorder({f"GET tap-api-v2.proofpoint.com/v2/threat/summary/{'0' * 64}": httpx.Response(404)})
    out = await _call(monkeypatch, rec, "proofpoint_status", {}, creds)
    assert out["tap"] == {"authorized": True}
    assert out["pps_credentials_sent"] is False


async def test_quarantine_tool_reports_malformed_pps_base_url(monkeypatch):
    creds = ProofpointCredentials(
        principal="prin", secret="sec", base_url=TAP,
        pps_header_error="X-Proofpoint-Pps-Base-Url must be an https URL with a host",
    )
    rec = Recorder()
    out = await _call(monkeypatch, rec, "proofpoint_quarantine_list", {}, creds)
    assert out["error"]["code"] == "invalid_argument"
    assert "X-Proofpoint-Pps-Base-Url" in out["error"]["message"]
    assert not rec.requests
