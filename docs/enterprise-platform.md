# Identity, traffic analysis, adaptive policy, and AI

The platform adds five areas: reliability fixes, enterprise identity and access
checks, asynchronous traffic analysis, versioned adaptive filtering, and AI
assistance with controlled AI egress. These are opt-in building blocks. Identity
provider compatibility has been tested with local fixtures, not certified against
live enterprise IdPs.

## Local example

[examples/platform.yaml](../examples/platform.yaml) binds only loopback, allows
only local unauthenticated clients, and enables metadata analysis, shadow policy,
and local explanations. It contains no administrative secret. Supply a unique
management credential before using the platform API. Without a configured secret
or API users, the platform endpoints return 503.

```sh
export ADS_API_SECRET="$(openssl rand -hex 32)"
go run ./cmd/proxy -config examples/platform.yaml
```

Keep the working directory writable for the findings journal and policy state.
Use a dedicated data directory in production and restrict access to these files.
Do not share a journal or policy state file between processes.

## 1. Reliability and request limits

Shared caching runs inside request and response checks. Sensitive, private,
streaming, and unsupported negotiated responses bypass shared caching. Successful
unsafe requests invalidate cached variants of the affected resource; explicit
purges include its variants. This does not infer application dependencies between
different URLs.

Gateway route `rate_limit` is requests per second, with a burst equal to that
value. It is separate from `bandwidth_limit` (bytes per second). Limits are local
to a process. Management listeners and owned background services are closed on
shutdown, and analysis workers drain within the shutdown deadline. Active SOCKS
connections still cannot be drained through the current SOCKS library.

## 2. Identity and zero-trust checks

Choose one `auth.mechanism` per instance. OIDC browser login uses authorization
code flow with PKCE, state, nonce, validated tokens, and local session cookies.
`GET /auth/login` begins browser login; the configured callback completes it.
SAML uses SP-initiated browser login and validates signed responses through the
SAML library. Both expose `/auth/logout` and support local subject revocation.
OAuth2 resource-server authentication uses token introspection; configure the
expected issuer, audience, scopes, and expiry requirement explicitly.

Example OIDC configuration (replace domains; YAML does not expand shell variables):

```yaml
gateway_tls:
  cert: /run/secrets/gateway.crt
  key: /run/secrets/gateway.key
auth:
  mechanism: oidc
  oidc:
    issuer: https://idp.example.com
    client_id: gateway
    redirect_url: https://gateway.example.com/auth/callback
    scopes: [openid, profile, email]
    groups_claim: groups
    tenant_claim: tenant
    session_ttl_seconds: 3600
    session_capacity: 10000
    allow_legacy_id_tokens: false
access:
  enabled: true
  require_identity: true
  required_groups: [employees]
```

Alternative OAuth2 and SAML auth blocks:

```yaml
auth:
  mechanism: oauth2
  oauth2:
    introspection_url: https://idp.example.com/oauth2/introspect
    client_id: gateway-introspection
    issuer: https://idp.example.com
    audience: protected-api
    required_scopes: [api.read]
    require_expiry: true
```

```yaml
auth:
  mechanism: saml
  saml:
    metadata_url: https://idp.example.com/metadata
    root_url: https://gateway.example.com
    cert: /run/secrets/saml-sp.crt
    key: /run/secrets/saml-sp.key
    subject_attribute: uid
    groups_attribute: groups
    tenant_attribute: tenant
```

Supply `ADS_OIDC_CLIENT_SECRET` or `ADS_OAUTH2_CLIENT_SECRET` when required by
your provider; these override the corresponding configured `client_secret`.
Register the exact callback or SAML service-provider metadata with the IdP.
Browser endpoints are restricted to the configured public authority. Legacy
bearer ID-token authentication is disabled unless explicitly enabled.

Verified identity supplies subject, issuer, tenant, groups, scopes, authentication
time, and MFA context where the authentication source provides them. Arbitrary
client headers do not establish these claims. Sessions, pending login attempts,
revocation, posture caches, and request budgets are process-local. Restarting
invalidates local sessions; clustered deployments need session affinity or a
future shared session store. Revocation here is not IdP-wide logout.

Optional access checks include `require_mtls`, `required_scopes`, `require_mfa`,
and `max_auth_age_seconds`. For mTLS, configure `gateway_tls.client_ca`; the
gateway requires and validates client certificates. `auth.mechanism: mtls` can
use that verified certificate as identity. Terminating TLS at another proxy does
not provide a verified client certificate to this listener.

For external posture checks, set `access.posture_url` and optionally
`access.posture_token_env`. The service receives a POST containing `subject`,
`issuer`, and `device_id` and must return HTTP 200 with:

```json
{"compliant":true,"expires_at":"2030-01-01T00:00:00Z"}
```

Expiry must be in the future. Timeouts, redirects, invalid responses, and missing
device identity deny access. Successful posture is cached for at most one minute.
Use HTTPS; plain HTTP is permitted only for explicit loopback IP test endpoints.

CEL policies loaded through `policy_file` can inspect verified `user.subject`,
`user.tenant`, `user.groups`, `user.scopes`, `user.amr`, and
`client.verified_mtls`. `access.default_effect: block` enables default denial.
Enabling access checks defaults CEL to deny when `default_effect` is omitted.
Add `policy_file: ./policies.yaml` to the OIDC example and an explicit allow rule
such as the following in that file:

```yaml
policies:
  - id: employees
    effect: allow
    condition: '"employees" in user.groups'
```

Supported actions include `rate_limit:10` and
`redact_headers:X-Internal-Token`; invalid actions are rejected. General runtime
configuration replacement remains disabled: validate configuration and restart.

## 3. Traffic sampling workers

The `analysis` block configures bounded workers, a nonblocking queue, deterministic
sampling, per-tenant admission budgets, retries, retention, and optional journal
persistence. Queue overload drops samples rather than delaying proxy traffic.
Review `/api/analysis/stats` for drops, failures, and journal errors.

Default analysis is deterministic: it classifies web/API/known AI traffic,
upstream errors, policy blocks, and selected sensitive-data patterns. It is not
a trained content classifier. Tenant identity comes from verified authentication;
traffic without a tenant claim uses `default`.

Only bounded metadata is retained by default. Query values are redacted and
credential headers are omitted. `capture_bodies: true` explicitly enables bounded
text previews; common credential patterns are redacted, but this is not general
PII anonymization. Review retention and access before enabling previews. Streaming
responses are sampled as consumed, with findings submitted when the response
ends or closes; sampling does not wait for an entire SSE stream before forwarding.

The queue is in memory and is **not durable**. Completed findings can be written
to a synchronous journal and replayed after restart. There are at most two
journal segments bounded by `journal_max_bytes` each; retained memory is bounded
by `findings_capacity`. A crash can lose queued work. Journal write failures are
reported in stats and leave findings available in memory. Expired findings are
excluded from normal API results.

## 4. Adaptive filtering

Rules match tenant, exact host authority, path prefix, and optionally a fresh
category finding above `min_confidence`. First matching rule wins. Host/path
rules work immediately; classification rules affect later requests using fresh
findings for the same tenant, host, and escaped path. They cannot retroactively
block the request that produced the finding.

`observe` and `shadow` evaluate without blocking; `enforce` applies block actions.
A would-block result adds `X-ADS-Adaptive: shadow-block` to the response in
non-enforcing modes. Rules can expire. The optional `state_file` persists policy
versions and bounded history across restarts. Persisted state takes precedence
over initial configuration rules. Changes use optimistic version checks;
rollback creates a new version instead of rewinding the version counter.

## 5. AI assistance and egress

With `ai.enabled: true` and no `provider_url`, explanations are generated locally.
An optional provider receives the question plus finding IDs, categories,
confidence, and model versions. URLs, identities, headers, bodies, raw evidence,
and finding reasons are excluded. The question itself is sent as supplied: do
not include secrets in it.

`provider_url` is a **custom adapter contract**, not a native OpenAI or Anthropic
endpoint. It receives JSON with `model`, `task: explain_security_findings`,
`question`, `findings`, and `instructions`. Return HTTP 200 and exactly:

```json
{"summary":"Explanation","recommendations":["Suggested next step"]}
```

Configure `model`, `token_env`, and `timeout_seconds` as needed. Redirects are
rejected, responses are bounded to 64 KiB, and unknown response fields fail
validation. Explanations have no tools or policy-write authority. Provider
failures return an API error; they do not silently become successful AI results.

Optional egress controls apply only to `ai.egress.hosts`. Other destinations
continue through ordinary proxy policy. Configure an explicit allowed subset:

```yaml
ai:
  enabled: true
  egress:
    enabled: true
    hosts: [api.openai.com, api.anthropic.com]
    allowed_hosts: [api.openai.com]
    allowed_models: [your-approved-model]
    requests_per_minute: 60
    max_body_bytes: 1048576
    credential_env:
      api.openai.com: AI_UPSTREAM_TOKEN
```

Controlled destinations require HTTPS. The gate bounds request bodies, checks
JSON `model` when configured, and applies a per-tenant request budget. It removes
caller authorization, cookies, and common API-key headers before optional bearer
credential injection from the named environment variable. Vendor-specific API-key
headers are not implemented. Responses remain streamed, including SSE. Budgets
count requests, not tokens or monetary cost, and reset with the process.

## Management API

These routes require management authentication (`X-API-Key` or configured Basic
users). The management credential has cross-tenant administrative access;
`tenant` is a query filter, not tenant-scoped RBAC.

| Method and path | Purpose |
| --- | --- |
| GET `/api/analysis/findings?tenant=default&limit=50` | Fresh findings; optional `category`, maximum limit 1000 |
| GET `/api/analysis/stats` | Worker, admission, and journal counters |
| GET `/api/adaptive/policy` | Current policy and retained history |
| PUT `/api/adaptive/policy` | Replace policy with an expected version |
| POST `/api/adaptive/preview` | Evaluate input against the current policy without mutation |
| POST `/api/adaptive/rollback` | Restore a retained version as a new version |
| POST `/api/ai/explain` | Local or provider explanation of selected findings |
| POST `/api/identity/revoke` | Revoke local browser sessions for a subject, when supported |

Example policy update (use the current version returned by GET):

```sh
curl -H "X-API-Key: $ADS_API_SECRET" -H 'Content-Type: application/json' \
  -X PUT http://127.0.0.1:9090/api/adaptive/policy \
  -d '{"expected_version":1,"mode":"shadow","rules":[{"id":"review-host","host":"example.com","action":"block"}]}'
```

Preview body: `{"tenant":"default","host":"example.com","path":"/"}`.
Rollback body: `{"expected_version":2,"target_version":1}`.
Explanation body: `{"question":"Summarize recent findings","tenant":"default","limit":50}`.
Revocation body: `{"subject":"employee-subject"}`.

## Coverage and remaining work

Controls apply to HTTP traffic visible to the proxy's request/transport pipeline.
HTTPS content inspection requires trusted MITM interception or gateway TLS
termination. Opaque CONNECT, SOCKS, UDP/QUIC relays, and other non-HTTP tunnels do
not expose application bodies, models, or identities for these content controls.
Do not treat enabling analysis as inspection of all tunneled traffic.

Next work includes live IdP interoperability validation, distributed sessions and
budgets, tenant-scoped management authorization, durable work queues, richer
classifiers, vendor-native AI adapters and token accounting, and broader protocol
integration coverage. See [TODO](../TODO) and [BUGS](../BUGS).

See [Policy language direction](policy-languages.md) for CEL, scripting, and the
proposed optional OPA/Rego integration.
