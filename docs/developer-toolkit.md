# Developer toolkit

Build `ads-dev` with `make build`, or:

```sh
go build -o bin/ads-dev ./cmd/ads-dev
```

Start with the included local configuration:

```sh
bin/ads-httpproxy -config examples/developer.yaml
export ADS_API_SECRET='local-development-key'
```

Or enable inspection in the proxy configuration:

```yaml
devtools:
  enabled: true
  capacity: 500
  capture_bodies: false
  max_body_bytes: 4096
  rules: []
```

The toolkit inspects outbound forward-proxy, intercepted HTTPS, and reverse
proxy/gateway requests. Captures record upstream URL, method, response protocol,
status, duration, selected headers, and optionally body previews. Duration ends
when the response body finishes or closes. WebSocket upgrades capture the
handshake only; opaque UDP/QUIC relay datagrams are not inspected. Requests
blocked before reaching the transport, cache hits, and HTTP/2 interception
paths handled directly by goproxy are not captured by this transport wrapper.

Captures remain in memory in oldest-to-newest order; capacity defaults to 500
and is capped at 10,000. IDs increase across clear operations. Query values are
redacted, URL credentials are removed, and only Content-Type, Content-Length,
Accept, Accept-Encoding, and Cache-Control headers are retained. Body capture
is opt-in, applies to text/JSON/XML/form content, and keeps at most the configured
bytes (default 4 KiB; maximum 64 KiB) per request and response. Body previews can
contain application secrets; header and query redaction does not sanitize them.

## Inspect and replay

```sh
export ADS_API_SECRET='your-api-key'
bin/ads-dev captures -api http://localhost:9090
bin/ads-dev replay -id 1 -proxy http://localhost:8080
bin/ads-dev clear
bin/ads-dev request -url http://example.com/api -header 'Accept: application/json'
bin/ads-dev request -url http://example.com/api -method POST \
  -header 'Content-Type: application/json' -data '{"hello":"world"}'
```

Automatic replay accepts GET/HEAD only, omits credentials, and rejects truncated
request previews. Supply `-url` to restore redacted query values. Use `request`
with explicit method, body, and headers for other operations. Request/replay
traffic uses the configured forward proxy by default. Use `-proxy ''` for a
direct connection. Request responses are JSON with status, protocol, headers,
body, duration, and a truncation flag (default response cap: 1 MiB).

Management operations support `-secret`, `ADS_API_SECRET`, or `-user` and
`-password`. Target/proxy TLS can trust a local PEM CA through `-ca`.

## Mock responses and fault rules

Create a JSON rule file:

```json
{
  "rules": [
    {"host":"api.example.com","path_prefix":"/slow","delay_ms":500},
    {"host":"api.example.com","path_prefix":"/failure","fail":true},
    {"host":"api.example.com","path_prefix":"/mock","method":"GET",
     "status":200,"body":"{\"environment\":\"mock\"}",
     "headers":{"Content-Type":["application/json"]}}
  ]
}
```

```sh
bin/ads-dev apply-rules -file rules.json
bin/ads-dev rules
```

Rules match the exact upstream authority (`host` or `host:port`), optional path
prefix, and optional case-sensitive method. The first match wins. A delay-only
rule continues to the upstream. Failure rules fail the transport request; mock
rules bypass the upstream and return the configured response. Existing proxy
security checks still run before transport rules. At most 100 rules are allowed;
delay is capped at 60 seconds and each mock body at 64 KiB. Changes are in-memory
and do not rewrite the proxy configuration. Apply `{"rules":[]}` to remove rules.

The management API mounts authenticated, rate-limited routes only when the
toolkit is enabled:

- `GET /api/devtools/exchanges`: list completed exchanges.
- `DELETE /api/devtools/exchanges`: clear captures.
- `GET /api/devtools/rules`: list rules.
- `PUT /api/devtools/rules`: replace rules after validating the entire request.

## QUIC and HTTP/3

There are two independently configured paths:

```yaml
# Terminate HTTP/3 at the gateway; the certificate must cover its hostname.
enable_quic: true
quic_cert: ./gateway.crt
quic_key: ./gateway.key
# Send HTTPS requests to these exact upstream authorities using HTTP/3.
quic_upstreams: ["api.example.com:443"]
```

The HTTP/3 listener uses UDP on the same actual address/port as the TCP proxy.
Alternatively, configure `autocert_cache_dir` and AutoCert application domains
instead of explicit QUIC certificate files. Upstream HTTP/3 uses normal system
certificate verification. Authorities not listed in `quic_upstreams` use the
usual HTTP transport. HTTP/3 failures are not retried over TCP, avoiding duplicate
writes. HTTP parent proxies and route-specific SOCKS chains use TCP transports;
HTTP/3 upstream configuration cannot be combined with `parent_proxy`.

To probe a gateway over HTTP/3 directly:

```sh
bin/ads-dev request -http3 -proxy '' -url https://gateway.example.com/api
```

For opaque QUIC protocols, use the fixed-target UDP relay:

```yaml
quic_relay:
  addr: "127.0.0.1:8443"
  target: "quic-origin.example.com:443"
  max_clients: 256
  idle_timeout_seconds: 60
```

Each client receives a separate upstream UDP socket. The relay preserves
payloads and does not terminate TLS, rewrite SNI, inspect content, or run HTTP
security rules. The upstream certificate must cover the hostname used by clients.
A changed client address starts a new relay session; connection migration across
relay sessions is not preserved. The relay has one configured upstream and is
independent of forward proxy routing. Bind it to the intended client network.

RFC MASQUE CONNECT-UDP/CONNECT-IP remains incomplete; these QUIC paths do not
claim MASQUE conformance. See [quic-go server](https://quic-go.net/docs/http3/server/)
and [client](https://quic-go.net/docs/http3/client/) documentation.

## Stream decoding and encoding

`decode` and `encode` run locally, without a proxy or API connection. Input is
stdin by default, a literal with `-data`, or bytes from `-file`. Output is raw
bytes without an added newline, allowing commands to be piped together.

```sh
bin/ads-dev decode -encoding base64 -data 'aGVsbG8='
bin/ads-dev decode -encoding base64url -data 'aGVsbG8'
bin/ads-dev decode -encoding form -data 'hello+world%21'
bin/ads-dev decode -encoding json-string -data '"hello\u0020world"'
bin/ads-dev decode -encoding gzip,utf8 -file response.gz
bin/ads-dev decode -encoding http -file raw-response.http
bin/ads-dev encode -encoding base64 -data 'hello'
bin/ads-dev request -url http://example.com/api -decode http
bin/ads-dev request -url http://example.com/token -decode base64,utf8
```

Supported decoders:

| Encoding | Behavior |
| --- | --- |
| `utf8`, `utf-8` | Validate UTF-8 and remove a leading BOM; `-replace-invalid` repairs invalid bytes |
| `base64`, `base64url` | Decode padded or unpadded data; ignore whitespace |
| `url`, `percent` | Percent-decode while preserving literal `+` |
| `form`, `query` | Percent-decode and convert `+` to a space |
| `hex` | Decode hex bytes, ignoring whitespace |
| `html` | Decode HTML entities |
| `json-string` | Decode a JSON string, including escaped Unicode |
| `json` | Pretty-print JSON |
| `quoted-printable` | Decode MIME quoted-printable |
| `gzip` | Decompress gzip, including checksum validation |
| `deflate` | Decompress zlib-wrapped or raw deflate |
| `deflate-raw` | Decompress raw deflate explicitly |
| `chunked` | Remove HTTP/1 chunk framing |
| `http` | Extract one raw HTTP/1 request/response body, remove transfer framing, decompress gzip/deflate Content-Encoding layers in reverse order, and convert its declared charset to UTF-8 |
| `utf16le`, `utf16be`, `latin1`, `windows-1252` | Convert text to UTF-8 |
| `jwt` | Inspect a three-part JWT's JSON header and payload; **does not verify its signature** |
| `identity` | Preserve bytes |

`encode` supports Base64/Base64URL, hex, percent/form encoding, HTML entities,
JSON strings, quoted-printable, gzip, zlib/raw deflate, chunk framing, UTF-8
validation, and identity. It does not generate HTTP messages or JWTs.
Comma-separated transformations run left to right, for example
`-encoding base64,gzip,utf8`. Automatic guessing is avoided because the same
input can be valid under multiple encodings.

`request` and `replay` accept `-decode` for response bodies. `-decode http` uses
the response's Content-Encoding and Content-Type headers; Go's transport already
removes transfer framing and may automatically decompress gzip, so those layers
are not decoded twice. Other encoding names apply the specified transformation
chain to the body. A truncated response cannot be decoded; increase
`-max-response-bytes` instead. Standalone input and each output stage default to
a 16 MiB limit, configurable with `-max-bytes` up to 64 MiB. Unsupported HTTP
compression such as Brotli returns an explicit error.
