# HTTP header policy

The proxy applies a final header policy after request/response policy scripts. Forward proxy traffic defaults to **no forwarding or identity disclosure**. Gateway traffic defaults to `Forwarded` and the legacy `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` fields. Both modes append a `Via` hop using the pseudonym `ads-proxy`. An absent User-Agent remains absent on the wire instead of acquiring Go's default client identifier.

Configure the top-level `headers` object:

```yaml
headers:
  forward:
    forwarded: off
    request:
      set:
        X-Application: ["example"]
      append:
        X-Trace-Tag: ["egress"]
      remove: [X-Debug]
    response:
      remove: [Server, X-Powered-By]
  gateway:
    forwarded: both
    request:
      remove: [X-Debug]
    response:
      append:
        Set-Cookie: ["gateway_marker=1; Secure; HttpOnly; SameSite=Lax"]
  trusted_proxies: ["192.0.2.0/24", "2001:db8::/32"]
  via_pseudonym: ads-proxy
  identity_upstreams: ["service.internal:8443"]
```

`forwarded` accepts `off`, `standard`, `legacy`, or `both`. The trust list is empty by default. A forwarding chain is retained only when the **immediate socket peer** belongs to a configured CIDR, and only after bounded syntax validation. The proxy appends its captured immediate peer; forwarded values never establish an authenticated identity. TLS state, original authority, original protocol, original Via and immediate peer are captured before rewrites or scripts. Malformed incoming chains are discarded. Conservative parsing may discard otherwise legal complex quoted forwarding fields. Via accepts protocol tokens with an optional protocol name, host/port or pseudonym recipients, and bounded nested comments.

Identity forwarding is separately opt-in. Only gateway requests to an explicit `identity_upstreams` authority receive `X-Authenticated-User` from the authenticated principal supplied by the proxy. Matching uses the effective upstream URL authority, case-insensitively, including the exact configured port; no wildcard, implicit port expansion, or client-controlled Host override is accepted. Forward proxy requests never receive this identity field. Client/script-supplied authenticated, tenant, device, groups, remote-user and forwarding fields are removed. Origin `Authorization` and `Cookie` are preserved unless explicitly removed; `Proxy-Authorization` is stripped from origin-bound requests. Parent CONNECT handshakes start with a fresh header map, apply the forward profile and CEL request actions, and add Via. Client credentials and cookies are never copied. Operator-configured parent credentials are injected by the parent transport after this boundary.

Operations preserve independent values, including multiple Set-Cookie fields. Each layer applies `set`, then `append`, then `remove`. Global profile operations run before per-request policy overrides. A removal from any layer wins over additions in every other layer; mandatory policy redactions run last. Built-in Via, forwarding and optional identity metadata are owned by the proxy and cannot be mutated through configuration or script header helpers. Proxy-owned fields also include Host, Connection, Upgrade, TE, Trailer, Transfer-Encoding, Content-Length, proxy authentication and identity fields. Setting/appending Authorization or Cookie is prohibited through generic mutation helpers; removing them is allowed.

Header names must be HTTP tokens; values cannot contain CR, LF, other control bytes, or DEL. An operation collection is limited to 128 names/values combined and 32 KiB of name/value text. Case-insensitive name collisions with different spellings are rejected. Trusted chain inputs have separate limits of 32 values and 8 KiB per field. Validation finishes before a mutation collection is applied. Configuration is copied into the policy so later caller mutations do not change active behavior.

Connection-nominated fields and ordinary hop-by-hop fields are removed in both directions. A captured, valid WebSocket upgrade retains only `Connection: Upgrade` and `Upgrade: websocket`; the response must also be a valid 101 upgrade. HTTP framing and trailers remain transport responsibilities. Response Via is reconstructed from the original upstream values captured before scripts, followed by the upstream protocol and proxy pseudonym. Sensitive identity and forwarding fields are stripped from responses; response cookies retain their individual values.

## Integration API

Construct with `headerpolicy.New(config)` (or validate with `Validate`). Capture once at ingress using `policy.Capture(request, gateway)`. Immediately before origin forwarding call `ApplyRequest(request, &snapshot, authenticatedIdentity, mandatoryRemovals, overrides...)`. After response scripts and response middleware call `ApplyResponse(response, &snapshot, originalUpstreamVia, overrides...)`. Capture upstream Via before response scripts. `Snapshot` fields are private and never derived again from mutable request headers. Apply the response boundary outside caches so cache hits receive the current response policy, and the request boundary before caches so cache keys see final request headers. Generic policy engines share `ValidateOperation`, `Protected`, and `ApplyOperations`.

Via follows [RFC 9110 section 7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3); forwarding trust follows [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html).

## Execution order and migration

Request authentication and CEL authorization evaluate the ingress request. Their header obligations travel in private request context through route rewrites and ICAP request replacement. Starlark and developer hooks then run; the final request boundary applies the configured profile, CEL overrides, terminal removals, and proxy-owned metadata before cache lookup or network forwarding. Changing a backend URL does not trigger a second CEL authorization decision.

Response Via is captured immediately after the upstream transport or cache returns. Starlark, developer hooks, DLP, ICAP, and response plugins run before final response operations. Cached objects store upstream headers; current response obligations apply independently on each hit. Locally generated authentication challenges and request-rejection responses keep their existing headers. Opaque CONNECT payloads are not HTTP-inspected; the forward profile applies to a parent CONNECT handshake when one exists.

This changes the old implicit `X-Authenticated-User` behavior: it is no longer sent to arbitrary origins, including intercepted HTTPS origins. Applications that require it must use gateway routes and explicitly list each backend authority in `identity_upstreams`. Authentication and CEL identity checks continue to use private verified context whether or not identity is emitted. Forwarding headers are generated from ingress metadata and replace untrusted client claims by default.

Use CEL for declarative request/response header actions (see [policy contract](policy-contract.md)); use Starlark `headers` for scalar replacement or `header_values` for individual multi-value fields (see [scripting cookbook](scripting-cookbook.md)). Tengo retains its existing decision hooks and does not expose header mutation. Rego and Cedar are not implemented.
