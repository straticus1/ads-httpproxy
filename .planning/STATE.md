# Platform implementation state

User authorized the five platform areas, then approved the open-source/cloud-engine
roadmap. Each milestone is split into eight focused commits.

Phase 01-platform: complete (review fixes, cache, identity, sampling, adaptive, AI).
Engine milestone: strict Squid subset, versioned CEL contract, Basic proxy auth,
CONNECT admission/tunnel lifecycle, protocol fixtures, benchmark harness, signed
policy delivery and scoped tenant-management credentials implemented.

Verification uses Go 1.25.7. Full suite, targeted race tests, go vet and go build
passed; parent-proxy routing, TLS rejection and bounded-header regressions
also passed with race detection.
Signed release integration verifies bootstrap deny, live activation, and restart.
No live Squid comparison, production performance certification, external IdP
certification or deployment was performed.

Next: Squid differential testing and representative capacity baselines; expanded
protocol/failure coverage; explicit ingress/egress policy composition; fleet
rollouts, distributed sessions/quotas, retention isolation and usage accounting.
Rego/Cedar are not implemented. See TODO and docs/cloud-engine.md for boundaries.

## Optional media gateway plans

User requested written plans only. Phase02 planning is complete: eight plans,
sixteen tasks and six dependency waves cover MG-01 through MG-10. Context,
primary-source research, validation strategy and execution index are present.
Independent revision review passed with all six findings resolved; static
structure/ownership/link checks passed. Status: ready for implementation.
No media runtime/deployment work was performed or represented as complete.
Start with .planning/phases/02-media-gateway/02-INDEX.md and plan02-01.

## Phase 03: HTTP header policy — complete

Implemented HP-01 through HP-06: distinct forward/gateway defaults; declarative
request/response mutations; trusted forwarding chains; protected credentials,
identity and transport fields; multi-value Starlark headers; configurable Via.
CEL actions are validated before publication and enforced after request hooks;
response actions run after response middleware. Parent CONNECT gets a fresh
header policy handshake, and caches preserve upstream protocol for Via.

Independent review found and resolved lost private context across ICAP-style
request replacements and lost Connection nominees after goproxy cleanup.
Regression tests cover both. Full suite, affected-package race tests, vet and
build pass with Go 1.25.7. macOS linker emitted a non-failing LC_DYSYMTAB warning
for the race binary. Media phase02 remains plans only.

Migration: X-Authenticated-User is now gateway-only and opt-in per backend
authority. See docs/header-policy.md; TODO retains unfinished cloud/media work.
