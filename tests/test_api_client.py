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
"""Auth, retries, errors and tool requests against a mocked Proofpoint API."""

import base64
import json
from datetime import timedelta
from urllib.parse import parse_qs

import httpx
import pytest

from proofpoint_mcp import api_client
from proofpoint_mcp.api_client import ProofpointClient, ProofpointCredentials, ProofpointError
from proofpoint_mcp.server import _credentials_var, create_mcp_server
from proofpoint_mcp.tools import _common
from proofpoint_mcp.tools._common import dates_window, iso, now, siem_window

TAP = "https://tap-api-v2.proofpoint.com"
CREDS = ProofpointCredentials(principal="prin", secret="sec", base_url=TAP)
REPORT_CREDS = ProofpointCredentials(principal="prin", secret="sec", base_url=TAP, reports_key="rk", reports_secret="rs")

THREAT = {
    "threatID": "t1",
    "threat": "http://bad.example/x",
    "threatType": "url",
    "classification": "phish",
    "threatStatus": "active",
    "campaignId": "c1",
}
DELIVERED = {
    "GUID": "g-del",
    "QID": "q1",
    "messageID": "<m1@example.com>",
    "sender": "attacker@bad.example",
    "fromAddress": ["attacker@bad.example"],
    "recipient": ["alice@corp.example"],
    "subject": "Invoice overdue",
    "threatsInfoMap": [THREAT],
    "xmailer": "Mailer 1",
    "policyRoutes": ["default_inbound"],
}
BLOCKED = {
    "GUID": "g-blk",
    "messageID": "<m2@example.com>",
    "sender": "spam@other.example",
    "recipient": ["bob@corp.example"],
    "subject": "Prize",
    "quarantineFolder": "Phish",
    "threatsInfoMap": [THREAT | {"threatID": "t2", "classification": "malware", "threatType": "attachment",
                                 "threat": "abc123"}],
}
CLICK = {"GUID": "g-clk", "id": "click-1", "recipient": "alice@corp.example", "sender": "attacker@bad.example",
         "classification": "phish", "threatID": "t1", "url": "http://bad.example/x", "threatStatus": "active"}
SIEM = {"queryEndTime": "2026-01-01T13:00:00Z", "messagesDelivered": [DELIVERED], "messagesBlocked": [BLOCKED],
        "clicksPermitted": [CLICK], "clicksBlocked": []}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class Recorder:
    """Mock transport: replies by "METHOD host/path"."""

    def __init__(self, routes=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.method} {request.url.host}{request.url.path}"
        reply = self.routes.get(key, {})
        if callable(reply):
            return reply(request)
        if isinstance(reply, httpx.Response):
            return reply
        return httpx.Response(200, json=reply)

    def query(self, index: int = -1) -> dict[str, list[str]]:
        return parse_qs(self.requests[index].url.query.decode())


def siem_route(path: str = "/v2/siem/all", payload=SIEM) -> dict:
    return {f"GET tap-api-v2.proofpoint.com{path}": payload}


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, creds=CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(creds)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder, creds=CREDS) -> ProofpointClient:
    return ProofpointClient(creds, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- client ----------------------------------------------------------------


async def test_basic_auth_on_cluster_url():
    rec = Recorder({"GET tap.eu.proofpoint.com/v2/threat/summary/t1": {"id": "t1"}})
    creds = ProofpointCredentials(principal="prin", secret="sec", base_url="https://tap.eu.proofpoint.com")
    assert await _client(rec, creds).tap("GET", "/v2/threat/summary/t1") == {"id": "t1"}
    request = rec.requests[0]
    assert request.headers["Authorization"] == "Basic " + base64.b64encode(b"prin:sec").decode()
    assert str(request.url) == "https://tap.eu.proofpoint.com/v2/threat/summary/t1"


async def test_pps_basic_auth_on_pps_base_url():
    rec = Recorder({"GET tenant.pphosted.com/rest/v1/quarantine": {"records": []}})
    creds = ProofpointCredentials(
        principal="prin", secret="sec", base_url=TAP,
        pps_base_url="https://tenant.pphosted.com", pps_username="ppsuser", pps_password="ppspass",
    )
    assert await _client(rec, creds).pps("GET", "/quarantine") == {"records": []}
    request = rec.requests[0]
    assert request.headers["Authorization"] == "Basic " + base64.b64encode(b"ppsuser:ppspass").decode()
    assert str(request.url) == "https://tenant.pphosted.com/rest/v1/quarantine"


async def test_pps_without_credentials_raises():
    rec = Recorder()
    with pytest.raises(ValueError, match="Protection Server"):
        await _client(rec, CREDS).pps("GET", "/quarantine")
    assert not rec.requests


async def test_get_retries_5xx():
    replies = iter([httpx.Response(503), httpx.Response(200, json={"ok": 1})])
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/x": lambda r: next(replies)})
    assert await _client(rec).tap("GET", "/v2/x") == {"ok": 1}
    assert len(rec.requests) == 2


async def test_quota_429_is_not_retried():
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/people/vap": httpx.Response(429, text="Too Many Requests")})
    with pytest.raises(ProofpointError) as err:
        await _client(rec).tap("GET", "/v2/people/vap")
    assert err.value.status_code == 429 and "quota" in err.value.message
    assert len(rec.requests) == 1


async def test_429_with_short_retry_after_is_retried():
    replies = iter([httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(200, json={})])
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/x": lambda r: next(replies)})
    await _client(rec).tap("GET", "/v2/x")
    assert len(rec.requests) == 2


async def test_non_idempotent_post_is_not_retried():
    rec = Recorder({"POST tap-api-v2.proofpoint.com/v2/x": httpx.Response(502)})
    with pytest.raises(ProofpointError):
        await _client(rec).tap("POST", "/v2/x", body={})
    assert len(rec.requests) == 1


async def test_text_error_body_is_reported():
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/siem/all": httpx.Response(400, text="The interval is too long")})
    with pytest.raises(ProofpointError) as err:
        await _client(rec).tap("GET", "/v2/siem/all")
    assert "interval is too long" in err.value.message


async def test_401_message_never_echoes_secret():
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/x": httpx.Response(401, text="sec")})
    with pytest.raises(ProofpointError) as err:
        await _client(rec).tap("GET", "/v2/x")
    assert "rejected" in err.value.message and "sec" not in err.value.message.replace("secret", "")


async def test_reports_token_then_bearer():
    rec = Recorder({
        "POST auth.proofpoint.com/v1/token": {"access_token": "tok", "token_type": "Bearer"},
        "GET threatprotection-api.proofpoint.com/api/v1/dash/reports/executive-summary/threat-categories": {"x": 1},
    })
    client = _client(rec, REPORT_CREDS)
    await client.reports("/executive-summary/threat-categories")
    await client.reports("/executive-summary/threat-categories")
    token_request = rec.requests[0]
    assert parse_qs(token_request.content.decode()) == {
        "grant_type": ["client_credentials"], "client_id": ["rk"], "client_secret": ["rs"]}
    assert [r.url.path for r in rec.requests].count("/v1/token") == 1
    assert rec.requests[-1].headers["Authorization"] == "Bearer tok"


async def test_reports_token_rejected():
    rec = Recorder({"POST auth.proofpoint.com/v1/token": httpx.Response(401, json={"error": "invalid_client"})})
    with pytest.raises(ProofpointError) as err:
        await _client(rec, REPORT_CREDS).reports("/x")
    assert err.value.status_code == 401


# ---- time windows ----------------------------------------------------------


def test_siem_window_rules():
    assert siem_window() == [("sinceSeconds", 3600)]
    assert siem_window(sinceSeconds=600) == [("sinceSeconds", 600)]
    assert siem_window(interval="PT30M/2026-01-01T12:30:00Z") == [("interval", "PT30M/2026-01-01T12:30:00Z")]
    with pytest.raises(ValueError):
        siem_window(sinceSeconds=7200)
    with pytest.raises(ValueError):
        siem_window(sinceSeconds=60, interval="a/b")
    with pytest.raises(ValueError):
        siem_window(sinceTime=iso(now() - timedelta(hours=3)))
    recent = iso(now() - timedelta(minutes=10))
    assert siem_window(sinceTime=recent) == [("sinceTime", recent)]


def test_dates_window_rules():
    end = now() - timedelta(days=1)
    start = end - timedelta(minutes=30)
    assert dates_window(iso(start), iso(end)) == [("interval", f"{iso(start)}/{iso(end)}")]
    assert dates_window(None, iso(end)) == [("interval", f"{iso(end - timedelta(hours=1))}/{iso(end)}")]
    with pytest.raises(ValueError):
        dates_window(iso(end - timedelta(hours=2)), iso(end))
    with pytest.raises(ValueError):
        dates_window(iso(now() - timedelta(days=9)), iso(now() - timedelta(days=9) + timedelta(minutes=5)))


# ---- tools -----------------------------------------------------------------


async def test_tap_all_threats_query_and_cap(monkeypatch):
    rec = Recorder(siem_route())
    out = await _call(monkeypatch, rec, "proofpoint_tap_get_all_threats",
                      {"sinceSeconds": 900, "threatStatus": "active", "max_events": 1})
    assert rec.query() == {"format": ["json"], "sinceSeconds": ["900"], "threatStatus": ["active"]}
    assert out["counts"] == {"messagesDelivered": 1, "messagesBlocked": 1, "clicksPermitted": 1, "clicksBlocked": 0}
    assert out["messagesDelivered"][0]["GUID"] == "g-del"


async def test_tap_syslog_is_split_into_lines(monkeypatch):
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/siem/clicks/blocked": lambda r: httpx.Response(200, text="a\nb\n")})
    out = await _call(monkeypatch, rec, "proofpoint_tap_get_clicks_blocked", {"format": "syslog"})
    assert out == {"format": "syslog", "count": 2, "lines": ["a", "b"], "has_more": False}


@pytest.mark.parametrize(
    "tool,path",
    [
        ("proofpoint_tap_get_messages_delivered", "/v2/siem/messages/delivered"),
        ("proofpoint_tap_get_messages_blocked", "/v2/siem/messages/blocked"),
        ("proofpoint_tap_get_clicks_permitted", "/v2/siem/clicks/permitted"),
    ],
)
async def test_tap_views_use_their_endpoint(monkeypatch, tool, path):
    rec = Recorder(siem_route(path))
    await _call(monkeypatch, rec, tool, {})
    assert rec.requests[0].url.path == path


async def test_two_time_options_rejected(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "proofpoint_tap_get_all_threats",
                      {"sinceSeconds": 60, "interval": "PT1M/2026-01-01T00:01:00Z"})
    assert out["error"]["code"] == "invalid_argument" and not rec.requests


async def test_events_list_filters(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_events_list", {"threatType": "phish"})
    assert [e["eventType"] for e in out["events"]] == ["messageDelivered", "clickPermitted"]
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_events_list", {"disposition": "quarantined"})
    assert [e["GUID"] for e in out["events"]] == ["g-blk"]


async def test_events_get_details_by_message_id(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_events_get_details", {"event_id": "m2@example.com"})
    assert out["event"]["GUID"] == "g-blk"
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_events_get_details", {"event_id": "nope"})
    assert out["error"]["code"] == "invalid_argument"


async def test_events_get_stats(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_events_get_stats", {})
    assert out["total"] == 3
    assert out["byEventType"]["clickPermitted"] == 1
    assert out["byClassification"] == {"phish": 2, "malware": 1}
    assert out["topRecipients"][0] == ["alice@corp.example", 2]


async def test_smart_search_trace(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_smart_search_trace",
                      {"recipient": "ALICE@", "status": "delivered"})
    assert out["total"] == 1 and out["messages"][0]["outcome"] == "delivered"
    assert out["messages"][0]["subject"] == "Invoice overdue"


async def test_forensics_search_by_threat_id(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_forensics_search_messages", {"threat_id": "t2"})
    assert [m["GUID"] for m in out["messages"]] == ["g-blk"]


async def test_smart_search_headers(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_smart_search_get_headers", {"message_id": "q1"})
    assert out["xmailer"] == "Mailer 1" and "threatsInfoMap" not in out


async def test_forensics_queries(monkeypatch):
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/forensics": {"reports": []}})
    await _call(monkeypatch, rec, "proofpoint_forensics_get_threat", {"threat_id": "t1", "includeCampaignForensics": True})
    assert rec.query() == {"threatId": ["t1"], "includeCampaignForensics": ["true"]}
    await _call(monkeypatch, rec, "proofpoint_forensics_get_campaign", {"campaign_id": "c1"})
    assert rec.query() == {"campaignId": ["c1"]}


async def test_threat_and_campaign_paths_are_escaped(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "proofpoint_threat_get_by_id", {"threat_id": "a/b"})
    await _call(monkeypatch, rec, "proofpoint_threat_get_campaign", {"campaign_id": "c1"})
    assert rec.requests[0].url.raw_path == b"/v2/threat/summary/a%2Fb"
    assert rec.requests[1].url.path == "/v2/campaign/c1"


async def test_list_families(monkeypatch):
    rec = Recorder({
        "GET tap-api-v2.proofpoint.com/v2/campaign/ids": {"campaigns": [{"id": "c1"}, {"id": "c2"}, {"id": "c3"}]},
        "GET tap-api-v2.proofpoint.com/v2/campaign/c1": {"id": "c1", "name": "One", "malware": [{"id": "m", "name": "Emotet"}]},
        "GET tap-api-v2.proofpoint.com/v2/campaign/c2": {"id": "c2", "name": "Two", "malware": [{"id": "m", "name": "Emotet"}],
                                                         "actors": [{"id": "a", "name": "TA542"}]},
    })
    out = await _call(monkeypatch, rec, "proofpoint_threat_list_families", {"max_campaigns": 2})
    assert out["campaigns_in_window"] == 3 and out["campaigns_read"] == 2 and "note" in out
    emotet = next(f for f in out["families"] if f["name"] == "Emotet")
    assert [c["id"] for c in emotet["campaigns"]] == ["c1", "c2"]
    assert rec.query(0)["size"] == ["200"] and "/" in rec.query(0)["interval"][0]


async def test_list_families_interval_limit(monkeypatch):
    out = await _call(monkeypatch, Recorder(), "proofpoint_threat_list_families",
                      {"sinceTime": iso(now() - timedelta(days=3))})
    assert out["error"]["code"] == "invalid_argument"


async def test_iocs_from_campaign_forensics(monkeypatch):
    forensics = {"reports": [{"name": "r", "forensics": [
        {"type": "url", "malicious": True, "what": {"url": "http://bad.example/x", "ip": "203.0.113.5"}},
        {"type": "dns", "malicious": True, "what": {"host": "bad.example", "ips": ["203.0.113.5", "203.0.113.6"]}},
        {"type": "file", "malicious": False, "what": {"sha256": "ignored"}},
    ]}]}
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/forensics": forensics})
    out = await _call(monkeypatch, rec, "proofpoint_threat_get_iocs", {"campaign_id": "c1"})
    values = {i["value"] for i in out["iocs"]}
    assert values == {"http://bad.example/x", "203.0.113.5", "bad.example", "203.0.113.6"}


async def test_iocs_from_siem(monkeypatch):
    out = await _call(monkeypatch, Recorder(siem_route()), "proofpoint_threat_get_iocs", {"threat_type": "url"})
    assert [(i["threatID"], i["events"]) for i in out["iocs"]] == [("t1", 2)]


async def test_people_vap_query(monkeypatch):
    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/people/vap": {"users": []}})
    await _call(monkeypatch, rec, "proofpoint_people_get_vap", {"window": 90, "size": 10})
    assert rec.query() == {"window": ["90"], "page": ["1"], "size": ["10"]}


async def test_user_risk(monkeypatch):
    user = {"identity": {"emails": ["Alice@corp.example"], "name": "Alice"}, "threatStatistics": {"attackIndex": 900}}
    rec = Recorder({
        "GET tap-api-v2.proofpoint.com/v2/people/vap": {"users": [{"identity": {"emails": ["x@y"]}}, user],
                                                        "vapAttackIndexThreshold": 500},
        "GET tap-api-v2.proofpoint.com/v2/people/top-clickers": {"users": []},
    })
    out = await _call(monkeypatch, rec, "proofpoint_people_get_user_risk", {"email": "alice@corp.example"})
    assert out["isVeryAttackedPerson"] is True and out["vapRank"] == 2 and out["isTopClicker"] is False
    assert out["threatStatistics"] == {"attackIndex": 900}


async def test_url_decode_body_and_retry(monkeypatch):
    replies = iter([httpx.Response(500), httpx.Response(200, json={"urls": [{"decodedUrl": "https://a", "success": True}]})])
    rec = Recorder({"POST tap-api-v2.proofpoint.com/v2/url/decode": lambda r: next(replies)})
    out = await _call(monkeypatch, rec, "proofpoint_url_decode", {"urls": [" https://urldefense.com/v3/__x "]})
    assert json.loads(rec.requests[-1].content) == {"urls": ["https://urldefense.com/v3/__x"]}
    assert out["urls"][0]["decodedUrl"] == "https://a" and len(rec.requests) == 2


async def test_url_analyze(monkeypatch):
    rec = Recorder({"POST tap-api-v2.proofpoint.com/v2/url/decode": {"urls": [
        {"decodedUrl": "https://target.example:8443/p?q=1", "success": True}]}})
    out = await _call(monkeypatch, rec, "proofpoint_url_analyze", {"url": "https://urldefense.com/v3/__x"})
    assert out["rewrittenByUrlDefense"] is True
    assert out["target"]["host"] == "target.example" and out["target"]["port"] == 8443
    plain = await _call(monkeypatch, Recorder(), "proofpoint_url_analyze", {"url": "https://plain.example/a"})
    assert plain["rewrittenByUrlDefense"] is False and plain["target"]["path"] == "/a"


async def test_reports_need_their_own_key(monkeypatch):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "proofpoint_reports_org_summary", {})
    assert out["error"]["code"] == "invalid_argument" and "X-Proofpoint-Reports-Key" in out["error"]["message"]
    assert not rec.requests


def _reports_routes(**paths) -> dict:
    routes = {"POST auth.proofpoint.com/v1/token": {"access_token": "tok"}}
    for path, payload in paths.items():
        routes[f"GET threatprotection-api.proofpoint.com/api/v1/dash/reports/{path.replace('__', '/').replace('_', '-')}"] = payload
    return routes


async def test_reports_threat_summary_filter(monkeypatch):
    payload = {"totalVolume": 3, "threatCategories": [{"name": "Malware", "volume": 1}, {"name": "BEC", "volume": 2}]}
    rec = Recorder(_reports_routes(executive_summary__threat_categories=payload))
    out = await _call(monkeypatch, rec, "proofpoint_reports_threat_summary",
                      {"window": 7, "threatType": "impostor"}, REPORT_CREDS)
    assert out["threatCategories"] == [{"name": "BEC", "volume": 2}]
    query = rec.query()
    assert set(query) == {"start", "end"} and query["end"][0].endswith("Z")


@pytest.mark.parametrize("window,granularity,expected", [(7, None, "DAY"), (30, "weekly", "WEEK"), (90, None, "WEEK")])
async def test_reports_mail_flow_grouping(monkeypatch, window, granularity, expected):
    rec = Recorder(_reports_routes(effectiveness_reports__messages_protected_trend={}))
    await _call(monkeypatch, rec, "proofpoint_reports_mail_flow",
                {"window": window, "granularity": granularity}, REPORT_CREDS)
    assert rec.query()["groupBy"] == [expected]


@pytest.mark.parametrize("window,granularity", [(7, "weekly"), (90, "daily"), (30, "hourly")])
async def test_reports_mail_flow_invalid_grouping(monkeypatch, window, granularity):
    rec = Recorder()
    out = await _call(monkeypatch, rec, "proofpoint_reports_mail_flow",
                      {"window": window, "granularity": granularity}, REPORT_CREDS)
    assert out["error"]["code"] == "invalid_argument" and not rec.requests


async def test_reports_executive_partial_failure(monkeypatch):
    rec = Recorder(_reports_routes(
        executive_summary__threat_categories={"totalVolume": 1},
        executive_summary__very_attacked_people=httpx.Response(429),
        executive_summary__top_clickers={"users": []},
    ))
    out = await _call(monkeypatch, rec, "proofpoint_reports_executive_summary", {}, REPORT_CREDS)
    assert out["threatCategories"] == {"totalVolume": 1} and "veryAttackedPeople" in out["errors"]


async def test_status_probe(monkeypatch):
    rec = Recorder({f"GET tap-api-v2.proofpoint.com/v2/threat/summary/{'0' * 64}": httpx.Response(404)})
    out = await _call(monkeypatch, rec, "proofpoint_status", {})
    assert out["tap"] == {"authorized": True} and out["reports_credentials_sent"] is False
    assert out["pps_credentials_sent"] is False
    rec = Recorder({f"GET tap-api-v2.proofpoint.com/v2/threat/summary/{'0' * 64}": httpx.Response(401)})
    out = await _call(monkeypatch, rec, "proofpoint_status", {})
    assert out["tap"]["authorized"] is False


async def test_status_probe_reports_pps_credentials_sent(monkeypatch):
    rec = Recorder({f"GET tap-api-v2.proofpoint.com/v2/threat/summary/{'0' * 64}": httpx.Response(404)})
    creds = ProofpointCredentials(
        principal="prin", secret="sec", base_url=TAP,
        pps_base_url="https://tenant.pphosted.com:10000", pps_username="u", pps_password="p",
    )
    out = await _call(monkeypatch, rec, "proofpoint_status", {}, creds)
    assert out["pps_credentials_sent"] is True


def test_common_has_no_module_level_credentials():
    assert not [name for name in vars(_common) if "secret" in name.lower() or "principal" in name.lower()]


# ---- Page-number paging that survives truncation (offset / next_offset) -----------------------------
# Self-test checklist: a cut page continues right after the last record returned (from page 1 and
# from a later page); offset aligned / not aligned to a page; offset past the end; offset wins over
# page; page-only calls send the same request as before; no retry hint for a page size.

TOTAL = 137
BIG = {f"f{k}": f"value {k}" for k in range(40)}
PEOPLE_ROWS = [{"id": f"r{i:03d}", "identity": {"emails": [f"u{i}@corp.example"]}, **BIG} for i in range(TOTAL)]
TRACE_ROWS = [{"GUID": f"r{i:03d}", "subject": f"Message {i}", "threatsInfoMap": [BIG, BIG]} for i in range(TOTAL)]

# tool, route, items field, id field, page-size parameter
PAGED_TOOLS = [
    ("proofpoint_people_get_vap", "/v2/people/vap", "users", "id", "size"),
    ("proofpoint_people_get_top_clickers", "/v2/people/top-clickers", "users", "id", "size"),
    ("proofpoint_smart_search_trace", "/v2/siem/all", "messages", "GUID", "per_page"),
]
PEOPLE_TOTAL = {"/v2/people/vap": "totalVapUsers", "/v2/people/top-clickers": "totalTopClickers"}


def _paged_api(path, rows):
    """People pages by page / size like Proofpoint; the SIEM search returns every event at once."""

    def reply(request):
        if path == "/v2/siem/all":
            return httpx.Response(200, json={"messagesDelivered": rows})
        params = dict(request.url.params)
        number, size = int(params.get("page", 1)), int(params["size"])
        return httpx.Response(200, json={"users": rows[(number - 1) * size : number * size], PEOPLE_TOTAL[path]: len(rows)})

    return reply


def _api(path, small=False):
    if path == "/v2/siem/all":
        rows = [{"GUID": r["GUID"]} for r in TRACE_ROWS] if small else TRACE_ROWS
    else:
        rows = [{"id": r["id"]} for r in PEOPLE_ROWS] if small else PEOPLE_ROWS
    return Recorder({f"GET tap-api-v2.proofpoint.com{path}": _paged_api(path, rows)})


def _ids(result, key, id_field):
    return [r[id_field] for r in result[key]]


async def _walk(monkeypatch, rec, tool, key, id_field, args):
    ids, calls, cut = [], 0, 0
    while True:
        result = await _call(monkeypatch, rec, tool, args)
        calls += 1
        assert "retry_page_size" not in result, result.get("note")
        cut += bool(result.get("truncated"))
        ids += _ids(result, key, id_field)
        if result.get("next_offset") is None:
            return ids, cut
        args = {k: v for k, v in args.items() if k != "page"} | {"offset": result["next_offset"]}
        assert calls < 200


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
async def test_cut_pages_continue_without_gaps_from_page_1(monkeypatch, tool, path, key, id_field, size_param):
    ids, cut = await _walk(monkeypatch, _api(path), tool, key, id_field, {size_param: 50})
    assert cut > 0  # pages really were cut
    assert ids == [f"r{i:03d}" for i in range(TOTAL)]  # no gaps, no duplicates


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
async def test_cut_pages_continue_without_gaps_from_a_later_page(monkeypatch, tool, path, key, id_field, size_param):
    ids, cut = await _walk(monkeypatch, _api(path), tool, key, id_field, {"page": 3, size_param: 40})
    assert cut > 0
    assert ids == [f"r{i:03d}" for i in range(80, TOTAL)]


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
@pytest.mark.parametrize("offset,size,page,first", [(30, 25, 2, "r030"), (50, 25, 3, "r050"), (0, 25, 1, "r000")])
async def test_offset_reads_the_page_that_holds_it(
    monkeypatch, tool, path, key, id_field, size_param, offset, size, page, first
):
    rec = _api(path, small=True)
    result = await _call(monkeypatch, rec, tool, {"offset": offset, size_param: size})
    if path != "/v2/siem/all":
        assert rec.query()["page"] == [str(page)] and rec.query()["size"] == [str(size)]
    assert _ids(result, key, id_field) == [f"r{i:03d}" for i in range(offset, page * size)]
    assert result[key][0][id_field] == first and result["offset"] == offset and result["page"] == page
    assert result["next_offset"] == page * size  # rest of the page returned, next page starts after it


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
async def test_offset_past_the_end_is_empty(monkeypatch, tool, path, key, id_field, size_param):
    result = await _call(monkeypatch, _api(path, small=True), tool, {"offset": 500, size_param: 25})
    assert (result[key], result["has_more"], result.get("next_offset")) == ([], False, None)


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
async def test_offset_wins_over_page(monkeypatch, tool, path, key, id_field, size_param):
    rec = _api(path, small=True)
    result = await _call(monkeypatch, rec, tool, {"offset": 10, "page": 4, size_param: 10})
    if path != "/v2/siem/all":
        assert rec.query()["page"] == ["2"]
    assert result[key][0][id_field] == "r010" and result["page"] == 2


@pytest.mark.parametrize("tool,path,key,id_field,size_param", PAGED_TOOLS)
async def test_page_only_sends_the_same_request_as_before(monkeypatch, tool, path, key, id_field, size_param):
    rec = _api(path, small=True)
    result = await _call(monkeypatch, rec, tool, {"page": 2, size_param: 25})
    if path == "/v2/siem/all":
        assert rec.query() == {"format": ["json"], "sinceSeconds": ["3600"]}
    else:
        assert rec.query() == {"window": ["30"], "page": ["2"], "size": ["25"]}
    assert _ids(result, key, id_field) == [f"r{i:03d}" for i in range(25, 50)]
    assert (result["page"], result["offset"], result["next_offset"], result["has_more"]) == (2, 25, 50, True)


async def test_people_keeps_the_api_fields_and_the_last_page_has_no_next_offset(monkeypatch):
    rec = _api("/v2/people/vap", small=True)
    result = await _call(monkeypatch, rec, "proofpoint_people_get_vap", {"page": 6, "size": 25})
    assert result["totalVapUsers"] == TOTAL and len(result["users"]) == 12
    assert result["has_more"] is False and "next_offset" not in result


async def test_people_without_a_total_pages_while_a_page_is_full(monkeypatch):
    rows = [{"id": f"r{i:03d}"} for i in range(28)]

    def reply(request):
        number, size = int(request.url.params["page"]), int(request.url.params["size"])
        return httpx.Response(200, json={"users": rows[(number - 1) * size : number * size]})

    rec = Recorder({"GET tap-api-v2.proofpoint.com/v2/people/top-clickers": reply})
    full = await _call(monkeypatch, rec, "proofpoint_people_get_top_clickers", {"offset": 5, "size": 10})
    assert (full["has_more"], full["next_offset"]) == (True, 10)
    last = await _call(monkeypatch, rec, "proofpoint_people_get_top_clickers", {"offset": 25, "size": 10})
    assert (last["has_more"], len(last["users"]), last.get("next_offset")) == (False, 3, None)
