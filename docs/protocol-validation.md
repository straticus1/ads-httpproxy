# Protocol validation and bounded load measurements

Run the request-path regression tests with the installed Go toolchain:

```sh
go test -race ./internal/proxy -run TestProtocol -count=1
go test -race ./cmd/proxybench
```

The protocol fixtures use real loopback sockets and exercise:

- HTTP/2 TLS negotiation at the gateway, immediate SSE delivery, and cancellation
  reaching the HTTP upstream.
- CONNECT rejection before TLS interception for unauthenticated callers.
- Authenticated HTTPS CONNECT with OAuth2 introspection, verified upstream TLS,
  identity propagation into decrypted requests, and no proxy credential leakage.
- HTTP/1 WebSocket upgrade, masked client/unmasked server frame forwarding, and
  upstream closure when the client disconnects.

CONNECT admission runs authentication, access, and configured metadata policies
before interception. Decrypted requests retain only the verified identity, check
its expiry, and run access/policy/content checks again. Credentials are not replayed
for each decrypted request. The interception implementation requires HTTP/1
CONNECT; HTTP/2 CONNECT is explicitly rejected. HTTP/2 gateway requests are a
separate supported path. These tests do not certify extended CONNECT, direct
HTTP/2 MITM, HTTP/3 streaming, or every WebSocket extension.

The authenticated CONNECT fixture skips verification only on its test client
connection to the ephemeral interception CA. The proxy verifies the upstream
fixture certificate against an explicit trust pool. Production clients should
trust the configured interception CA; do not disable their TLS verification.

## Load harness

Build once so compiler startup is excluded:

```sh
go build -o /tmp/proxybench ./cmd/proxybench
/tmp/proxybench -target http://127.0.0.1:8080/fixture \
  -count 10000 -concurrency 32 -timeout 5s -max-bytes 1048576
```

For a forward proxy, target a controlled origin and specify the proxy explicitly:

```sh
/tmp/proxybench -target http://127.0.0.1:18080/fixture \
  -proxy http://127.0.0.1:8080 -count 10000 -concurrency 32
```

Use only an endpoint you own or have permission to load. The harness performs GET
requests, ignores ambient proxy environment variables, verifies TLS normally,
does not follow redirects, and bounds concurrency, request count, response bytes,
and per-request time. No credentials are accepted in URLs. Authenticate a test
deployment through its supported network/client setup, or use a loopback-only
fixture with explicitly allowed local requests.

Output is one JSON report with attempted requests, completed status-code counts,
errors, bytes, elapsed seconds, requests/second, and nearest-rank p50/p95/p99
latencies in milliseconds. Latencies include response-body consumption and failed
requests. Non-2xx responses, transport/read errors, timeouts, and responses over
the byte limit count as errors. A byte-limit failure may consume one extra byte
to detect overflow. Exit status is 0 for no errors, 1 for workload errors, and 2
for invalid configuration or report output failure.

Memory fields (`client_heap_before_bytes`, `client_heap_after_bytes`,
`client_total_allocated_bytes`, `client_runtime_sys_bytes`) describe the **load
generator process**, not the proxy. Collect the proxy's process RSS and metrics
separately. Heap snapshots are not peak memory, and runtime Sys is not RSS.

This is a closed-loop workload: each worker starts its next request after the
previous response completes. It does not measure fixed-arrival-rate overload or
correct coordinated omission. Keep endpoint payload, caching, TLS, policy, logging,
machine limits, Go version, request count, and concurrency fixed when comparing
runs. Record those settings with the JSON output. Run warm-up separately if needed;
the reported run includes connection establishment. Compare direct-origin and
proxied runs using the same fixture to understand local overhead. No Squid
comparison or production capacity claim is implied by this harness.
