# Proofpoint MCP Server

An [MCP](https://modelcontextprotocol.io) server for Proofpoint
[Targeted Attack Protection (TAP)](https://www.proofpoint.com/us/products/advanced-threat-protection/targeted-attack-protection),
used by MSPs and security teams to investigate email threats. It lets an AI agent read the TAP
SIEM feed (threat messages delivered or blocked, malicious URL clicks), search those messages,
drill into threats, campaigns and sandbox forensics, see the most attacked people and top
clickers, decode URL Defense links, and, with a separate key, read the Dashboard reports.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored
- Read only: no tool changes anything in Proofpoint
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Proofpoint-Service-Principal` | Yes | string | none | - | TAP service principal | `your-service-principal` |
| `X-Proofpoint-Service-Secret` | Yes | string | none | - | TAP service secret | `your-service-secret` |
| `X-Proofpoint-Cluster-Url` | No | string | `https://tap-api-v2.proofpoint.com` | https URL on a `proofpoint.com` host | TAP API base URL | `https://tap-api-v2.proofpoint.com` |
| `X-Proofpoint-Reports-Key` | No | string | none | - | Dashboard Reports API key (only for `reports_*` tools) | `your-reports-key` |
| `X-Proofpoint-Reports-Secret` | No | string | none | - | Dashboard Reports API secret | `your-reports-secret` |
| `X-Proofpoint-Pps-Base-Url` | No | string | none | https URL, bare host | Proofpoint Protection Server (PPS) REST API base URL; required to use the quarantine tools | `https://tenant.pphosted.com:10000` |
| `X-Proofpoint-Pps-Username` | No | string | none | - | PPS API-role account username; required to use the quarantine tools | `your-pps-username` |
| `X-Proofpoint-Pps-Password` | No | string | none | - | PPS API-role account password; required to use the quarantine tools | `your-pps-password` |

Where to get them:

- **TAP service credentials:** create a service credential on the **Settings** page of the TAP
  (Threat Insight) Dashboard; it shows the service principal and the secret.
- **Reports API key (optional):** in the Admin Portal open **Settings -> API Key Management ->
  Threat Protection** and choose **Create New**. The TAP service principal is not accepted by
  the Reports API, so the four `reports_*` tools need this second pair.
- **PPS credentials (optional, only for the quarantine tools):** an administrator with a role
  that includes REST API access on your Proofpoint Protection Server. Cloud tenants: request
  this through a Proofpoint support ticket. On-prem: enable the API GUI in `filter.cfg` and
  create an API-type admin role in the PPS management interface.

How credentials are sent to Proofpoint: TAP calls go to the cluster URL
(`https://tap-api-v2.proofpoint.com/v2/...`) with HTTP Basic authentication
(`principal:secret`). Reports calls first get a Bearer token from
`POST https://auth.proofpoint.com/v1/token` (client credentials grant with the reports key and
secret), then call `https://threatprotection-api.proofpoint.com/api/v1/dash/reports/...`; the
token is used only within the one request. Quarantine calls go to the PPS base URL
(`<pps-base-url>/rest/v1/quarantine`) with HTTP Basic authentication (`pps_username:pps_password`).
A cluster/base URL that fails its structural check does not block the request (tools/list still
works), but every TAP/Reports tool call then returns an `invalid_argument` error before any
outbound request for a malformed TAP cluster URL, and the 4 quarantine tools do the same for a
malformed PPS base URL -- without affecting any other tool -- so credentials can never be sent
elsewhere. The PPS base URL has no domain-suffix allowlist (unlike the TAP cluster URL): PPS
cloud tenants are on `*.pphosted.com` and on-prem tenants are on an arbitrary customer host.
Values that look like unresolved templates (`${...}`) are treated as missing.

A request to `/mcp` without the principal and secret gets HTTP 401 naming the missing ones. The
3 PPS headers are optional: without them, the 4 quarantine tools return `not_configured`
naming the missing headers; every other tool is unaffected.

## Tools

All tools return a JSON string.

**Time windows.** The TAP SIEM API returns at most one hour per call and keeps 7 days of events.
SIEM-based tools take one of `sinceSeconds` (1-3600), `sinceTime` (ISO8601, within the last
hour) or `interval` (ISO8601, 30 seconds to 1 hour, e.g.
`2026-01-01T12:00:00Z/2026-01-01T13:00:00Z`); the default is the last hour. Search tools take
`startDate` / `endDate` instead, covering at most one hour.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `proofpoint_navigate` | Describe the tools of one area (changes nothing) | **domain** |
| `proofpoint_status` | Check that TAP accepts the credentials; whether Reports keys were sent | - |
| `proofpoint_tap_get_all_threats` | All threat messages and clicks in a window | sinceSeconds, sinceTime, interval, threatStatus, threatType, format, max_events |
| `proofpoint_tap_get_messages_delivered` | Threat messages that reached users | same as above |
| `proofpoint_tap_get_messages_blocked` | Threat messages blocked or quarantined | same as above |
| `proofpoint_tap_get_clicks_permitted` | Malicious URL clicks that were allowed | same as above |
| `proofpoint_tap_get_clicks_blocked` | Malicious URL clicks that were blocked | same as above |
| `proofpoint_events_list` | All events as one list, filtered by classification or outcome | sinceSeconds, sinceTime, interval, threatType (`spam`, `phish`, `malware`, `impostor`), disposition, max_events |
| `proofpoint_events_get_details` | One event by GUID, id, QID or Message-ID | **event_id**, sinceSeconds, sinceTime, interval |
| `proofpoint_events_get_stats` | Counts by event type, classification, status; top recipients and senders | sinceSeconds, sinceTime, interval |
| `proofpoint_smart_search_trace` | Find threat messages by sender, recipient, subject, Message-ID | sender, recipient, subject, message_id, startDate, endDate, status, page, per_page, offset |
| `proofpoint_smart_search_get_message` | Full TAP record of one threat message | **message_id**, sinceSeconds, sinceTime, interval |
| `proofpoint_smart_search_get_headers` | Envelope and header fields of one threat message | **message_id**, sinceSeconds, sinceTime, interval |
| `proofpoint_forensics_search_messages` | Find threat messages by sender, subject, Message-ID or threat id | sender, subject, message_id, threat_id, startDate, endDate, limit |
| `proofpoint_forensics_get_threat` | Sandbox forensics for a threat (or its whole campaign) | **threat_id**, includeCampaignForensics |
| `proofpoint_forensics_get_campaign` | Aggregate forensics for a campaign | **campaign_id** |
| `proofpoint_threat_get_by_id` | Threat summary | **threat_id** |
| `proofpoint_threat_get_campaign` | Campaign details, actors, malware, techniques | **campaign_id** |
| `proofpoint_threat_list_families` | Malware families, actors and techniques of recent campaigns | sinceTime, interval (up to 1 day), max_campaigns |
| `proofpoint_threat_get_iocs` | IOCs from a campaign's forensics, or threats in a SIEM window | campaign_id, sinceTime, interval, threat_type |
| `proofpoint_people_get_vap` | Very Attacked People | window (14, 30, 90), page, size, offset |
| `proofpoint_people_get_top_clickers` | Users who clicked the most malicious URLs | window, page, size, offset |
| `proofpoint_people_get_user_risk` | One user's VAP and top-clicker standing | **email**, window |
| `proofpoint_url_decode` | Decode URL Defense rewritten links | **urls** |
| `proofpoint_url_analyze` | Decode and break down one link | **url** |
| `proofpoint_reports_org_summary` | Inbound protection overview | window (1, 7, 14, 30, 90) |
| `proofpoint_reports_threat_summary` | Threat volume by category | window, threatType |
| `proofpoint_reports_mail_flow` | Trend of protected messages | window, granularity |
| `proofpoint_reports_executive_summary` | Threat categories, VAPs and top clickers | window (7, 14, 30, 90) |
| `proofpoint_quarantine_list` | Quarantined messages in Proofpoint Protection Server (PPS), optionally filtered | sender, recipient, subject, startDate, endDate, folder, page, per_page |
| `proofpoint_quarantine_search` | Find a quarantined message by sender, recipient or subject (one query, matched as OR) | **query**, startDate, endDate, page, per_page |
| `proofpoint_quarantine_release` | Release a quarantined message | **message_id** |
| `proofpoint_quarantine_delete` | Permanently delete a quarantined message | **message_id** |
| `proofpoint_policy_list` / `_get` / `_list_routes` | Unavailable (see below) | as before |
| `proofpoint_dlp_list_incidents` / `_get_incident` / `_list_encrypted` | Unavailable (see below) | as before |
| `proofpoint_forensics_pull_messages` | Unavailable (see below) | **message_ids**, reason |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "rate_limited", "message": "Proofpoint returned HTTP 429 for /v2/people/vap: the API quota for this endpoint is used up; try again later", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`.

**Quotas.** Proofpoint throttles per credential over a rolling 24 hours: SIEM 1800 calls,
People 50, Campaign 50, Forensics 50 per threat id; Reports allow 10 calls a minute and 20 a day
per report section. A 429 is therefore reported as not retryable. Reads (and URL decoding, a
pure function) are retried with backoff on 5xx and network errors.

## Run locally

```bash
uv sync
uv run python -m proofpoint_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t proofpoint-mcp:dev .
docker run --rm -p 8080:8080 proofpoint-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Proofpoint-Service-Principal: your-service-principal" \
  -H "X-Proofpoint-Service-Secret: your-service-secret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# threat messages delivered in the last 30 minutes
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Proofpoint-Service-Principal: your-service-principal" \
  -H "X-Proofpoint-Service-Secret: your-service-secret" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"proofpoint_tap_get_messages_delivered","arguments":{"sinceSeconds":1800}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (40).** Kept as is because the tool names are an existing contract; every tool is
  listed from the first `tools/list`.
- **Real endpoints only.** Earlier versions called paths that the TAP API does not have
  (`/v1/quarantine`, `/v1/policies`, `/v1/dlp/...`, `/v1/smart-search`, `/v2/events/...`,
  `/v1/reports/...`, `/v2/threat/families`, `/v2/url/analyze`, `/v2/people/{email}`). Each tool
  now uses a documented endpoint:
  - `events_*`, `smart_search_*` and `forensics_search_messages` filter SIEM events
    (`/v2/siem/all`), so they see messages that carried a TAP threat, one hour at a time.
  - `forensics_get_threat` / `_get_campaign` use `/v2/forensics?threatId=` / `?campaignId=`.
  - `threat_get_campaign` uses `/v2/campaign/{id}`; `threat_list_families` lists
    `/v2/campaign/ids` and reads the campaigns' malware, actors and techniques;
    `threat_get_iocs` extracts indicators from forensics or SIEM threats.
  - `people_get_user_risk` looks the user up in the VAP and top-clicker lists.
  - `url_analyze` decodes the link with `/v2/url/decode` and parses it; TAP has no URL scoring.
  - `reports_*` use the Dashboard Reports API, which needs its own key (optional headers).
- **Unavailable tools.** Policy, DLP / encryption and message pull belong to other Proofpoint
  products (Protection Server, Essentials, Threat Response), or -- for policy -- are not exposed
  by any Proofpoint API found during research (TAP, Essentials Interface/Threat APIs, PPS REST
  API; confirmed 2026-10-30). These 7 tools stay listed for compatibility, change nothing, and
  return `invalid_argument` naming the TAP tool that covers the nearest need.
- **Quarantine, via Proofpoint Protection Server (PRD-21254).** The 4 `quarantine_*` tools keep
  their names and parameters but now call the real PPS REST API (`<pps-base-url>/rest/v1/quarantine`,
  documented via the Cortex XSOAR "Proofpoint Protection Server v2" integration -- Proofpoint has
  no single official PPS REST reference) when PPS credentials are sent; otherwise they return
  `not_configured`. `message_id` is an opaque `folder:localguid` pair minted by `_list`/`_search`
  and consumed by `_release`/`_delete` -- callers must not construct one themselves.
  `_search`'s single `query` parameter is matched as OR across sender/recipient/subject (three
  PPS lookups, merged and de-duplicated) to keep the tool's existing single-field search promise.
- **Cluster/base URL checks.** `X-Proofpoint-Cluster-Url` is accepted only as an https URL on a
  `proofpoint.com` host, so a caller cannot redirect the TAP Basic credentials to another server.
  `X-Proofpoint-Pps-Base-Url` has the same structural check (https, bare host) but no domain
  allowlist, because PPS cloud tenants are on `*.pphosted.com` and on-prem tenants are on an
  arbitrary customer host -- the PPS admin password is supplied by the same tenant that supplies
  the base URL, so the trust boundary is unchanged, but this is a narrower check than the TAP one
  and is called out here for that reason.
- **Bounded output.** SIEM lists are capped per list (`max_events`, default 100) with the full
  counts reported; every result is capped at 20,000 characters.
- **Paging by offset.** `smart_search_trace`, `people_get_vap` and `people_get_top_clickers` page
  by page number, and a page cut to fit the size limit has its rest on no other page. They also
  take `offset` (record position, overriding `page`) and return `next_offset`, which continues
  right after the last record returned; pass it back to read every record exactly once.
- **No interactive prompts or UI cards.** The stateless gateway cannot relay them; missing
  information is a required parameter or an error instead.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
