# Header policy verification

Status: passed. Scope: HP-01 through HP-06; media phase02 unchanged.

| Requirement | Implementation evidence |
| --- | --- |
| HP-01 Separate defaults | Forward privacy/gateway forwarding profiles; wire tests in both modes |
| HP-02 Header operations | Config plus typed CEL request/response set/append/remove; publication rejection tests |
| HP-03 Trusted forwarding | Captured peer/TLS/authority, explicit CIDRs, IPv4/IPv6 and spoofing tests |
| HP-04 Protected fields | Shared validation, final sanitization, opt-in gateway identity, preserved trust context |
| HP-05 Multi-value scripting | Scalar compatibility, list-valued views, atomic conflicts, independent Set-Cookie tests |
| HP-06 Via | Bounded valid chain parsing, pseudonym, request/response and parent CONNECT fixtures |

Commands (Go 1.25.7):

- `go test ./...`: passed.
- `go test -race ./internal/headerpolicy ./internal/policy ./internal/scripting/starlark ./internal/config ./internal/proxy ./internal/cache`: passed.
- `go vet ./...`: passed.
- `go build ./...`: passed.
- `git diff --check`: passed.

Independent review resolved two findings: fresh ICAP-style requests losing private
context, and goproxy removing Connection before its nominated fields were stripped.
Regressions cover these paths. Aggregate action limits now reject invalid CEL
publication. Existing HTTP/2, WebSocket and authenticated CONNECT tests pass.
The race link emitted a non-failing macOS LC_DYSYMTAB warning.

Limits: local authentication/error responses retain existing headers; opaque
CONNECT payloads are not inspected. Tengo has no header mutation API. Rego and
Cedar remain unimplemented. Existing cache records without protocol metadata
retain their previous HTTP/1.1 fallback. No production deployment performed.
