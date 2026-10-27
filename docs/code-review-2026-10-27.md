# Code review and backlog implementation — 2026-10-27

Reviewed the request/response pipeline, shared caching, DLP body handling,
management configuration redaction, and developer capture API/CLI. This is a
scoped review of a large repository, not a certification of every feature in
README or every checked TODO. The initial working tree was clean.

## Verified findings and fixes

| Severity | Finding | Fix and evidence |
| --- | --- | --- |
| High | `middlewareRespCache` launched a goroutine that consumed/replaced the live response body concurrently with delivery. | Replaced middleware caching with a synchronous, bounded outbound `cacheTransport`; downstream bodies remain intact. Proxy integration and race tests pass. |
| High | Cache hits returned before policy, WAF, DLP request checks, request plugins, and scripts. | Cache sits inside the wrapped outbound transport. Tests prime the cache, reject the next request through policy, and verify both script hooks and response checks still execute on hits. |
| High | Shared cache lookup ignored credentials/cookies/ranges/revalidation; arbitrary Vary responses could be shared. Normalizing query order/escaped paths collapsed distinct origin resources. | Bypass sensitive and unsupported request/response semantics. Preserve raw URL distinctions and virtual host identity. Namespace v2 ignores existing unsafe cache entries. |
| High | Zero/malformed/expired freshness fell back to defaults; Redis-to-memory promotion could extend origin freshness. | Honor explicit freshness, account for upstream age, validate embedded expiry on reads, and promote only remaining lifetime. Tests cover expired payloads even when the memory entry itself remains live. |
| Medium | DLP could panic on nil bodies, lose consumed bytes after read errors, and leak rejected upstream bodies. | Guard absent bodies, return explicit 400/502 on read failure, and close blocked/error bodies. Regression tests cover each path. |
| Medium | A single memory-cache entry could exceed its entire configured budget. | Reject oversized entries without evicting unrelated valid entries. |
| Medium | Config redaction descended into maps but not arrays. | Recursively redact nested array contents; test nested plugin secrets. |
| Medium | Cached responses discarded repeated header values; cache read failures lost partial body bytes/errors. | Preserve complete header arrays and replay consumed bytes followed by the original read error. |
| Low | Cache startup created an endless ticker goroutine that performed no cleanup. | Remove the no-op goroutine. Memory eviction/access handles expiry and maintains the configured budget. |

The cache deliberately bypasses unknown-length streams, SSE, oversized responses,
private responses, authenticated identities, and unsupported Vary dimensions.
This reduces cache hit rate in exchange for correct isolation and streaming.
Bounded cacheable responses are read before returning to downstream processing.
`CachePrivate` remains a deprecated compatibility field and no longer enables
shared storage of private content. Conditional requests go to the origin.

## Backlog work delivered

1. Added 16 regression test functions across caching, proxy/DLP integration,
   configuration redaction, capture export, and CLI query forwarding. The broad
   "tests for all internal packages" TODO remains open.
2. Added capture visibility for cache hits through wrapped transports.
3. Added authenticated HAR 1.2 export and host/method/status/since/limit filters,
   with matching `ads-dev captures` flags, documentation, and OpenAPI parameters.
   Export reuses captured redacted metadata; preview truncation and unavailable
   measurements are explicit. The CLI rejects oversized output instead of
   silently emitting incomplete JSON.

The HAR field layout follows the historical [HAR format documentation](https://webperfwg.org/specs/HAR/Overview.html).
This exporter does not measure DNS/connect/send/receive timings separately;
its timing comment identifies the aggregate duration. It does not reconstruct
omitted credentials, cookies, headers, or full bodies.

## Highest-value remaining work

1. **Cache mutation invalidation and variant purging.** `Purge` targets one key;
   successful unsafe methods do not invalidate all GET/HEAD representations.
   Mutable endpoints should use `Cache-Control: no-store`, or caching should be
   disabled until these semantics are implemented.
2. **Per-route request limiting.** `PreparedRoute.RateLimit` is populated but
   never consulted; gateway handling uses the global bandwidth limiter. A
   configured `rate_limit` currently provides no independent request limit.
3. **Listener/background-service shutdown.** The management API constructs
   listeners internally without exposing shutdown ownership. Complete lifecycle
   management before introducing runtime configuration replacement.
4. **ICAP/SOCKS/direct HTTP/2 regression coverage.** Many internal packages still
   have no unit tests. Pre-transport blocks and direct HTTP/2 interception remain
   outside developer capture coverage.

Runtime configuration updates remain disabled. Implementing safe component
replacement, draining, and rollback is larger than a management endpoint change.
MASQUE conformance and additional compression codecs remain separate features.

## Validation

Using `ASDF_GOLANG_VERSION=1.25.7` (the repository pins 1.25.2, which is not
installed on this machine):

- Baseline `go test ./...`: passed before edits.
- Final `go test ./...`: passed.
- Final `go test -race ./internal/cache ./internal/proxy ./internal/api ./internal/devtools ./cmd/ads-dev`: passed.
- Final `go vet ./...`: passed.
- `git diff --check`: passed.

The macOS linker emitted LC_DYSYMTAB warnings for race binaries; the binaries
ran successfully with no reported data races. Local TCP/UDP listener tests ran
outside the sandbox after permission was granted. Redis-backed integration,
external authentication/ICAP services, deployment, and browser HAR imports were
not exercised. Changes remain uncommitted in the working tree.
