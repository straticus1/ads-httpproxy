# Platform roadmap

1. [x] Existing review fixes and developer capture export (69a00f4)
2. [x] Shared-cache invalidation and safety
3. [x] Enterprise identity protocols and sessions
4. [x] Bounded traffic sampling and durable worker findings
5. [x] Gateway integration, zero-trust policy and lifecycle
6. [x] Adaptive content filtering controls
7. [x] AI investigation assistance and AI egress controls
8. [x] Integration verification and operations documentation

Target: 8 focused commits total, with 5–10 permitted by user.

## Next milestone: open-source engine and cloud platform

Product target: a modern open-source proxy competitive with Squid, usable as the
data-plane engine of a managed cloud proxy. Current features are foundations,
not a claim of Squid compatibility, production certification, or cloud readiness.

1. Publish a compatibility matrix and migration fixtures for squid2ads: supported
   ACL/cache/CONNECT/auth behavior, explicit rejection of unsupported directives.
2. Establish correctness and performance gates: HTTP/1.1, HTTP/2, CONNECT,
   streaming, WebSocket, ICAP and SOCKS; cancellation and shutdown under load;
   throughput, p95/p99 latency, memory per connection and cache hit behavior.
3. Unify policy inputs, decision reasons, obligations and precedence; add replay
   tests and versioned distribution. Keep CEL and Starlark; consider optional
   OPA/Rego once the common contract is stable. Defer Cedar until resource-level
   authorization requirements justify its entity model.
4. Separate management control plane from request-serving data plane: authenticated
   enrollment, signed versioned configuration, last-known-good behavior, staged
   rollouts, fleet health and rollback. No remote control-plane call per request.
5. Make tenancy enforceable: scoped administrator credentials, cache/queue/quota
   isolation, distributed sessions and budgets, tenant usage accounting, audit
   export and retention controls. Test noisy-neighbor and cross-tenant failures.
6. Add richer content classifiers and optional vendor-native AI adapters after
   inspection coverage and resource bounds are measurable.

See docs/policy-languages.md for the language decision and
 docs/enterprise-platform.md for current behavior and limitations.

## Engine milestone delivered

Strict migration subset and executable fixtures; versioned CEL decision contract;
Basic proxy auth and CONNECT admission fixes; explicit opaque tunnel mode;
HTTP/2 gateway/stream/WebSocket/CONNECT tests; bounded load harness; signed policy
push with last-known-good restoration; tenant-scoped management readers.

These are concrete foundations for steps 1–5 above. Compatibility still needs
live Squid differential tests; performance still needs comparative runs. Fleet
enrollment/rollouts, distributed state, full per-tenant resource isolation and
billing-grade usage accounting remain open. See TODO for executable next work.

## Phase 02: Optional media gateway — planned

Goal: an independently deployable, default-off media subsystem that connects
verified platform identity/policy to mature SIP, RTPengine and TURN services.
Status: plans reviewed and ready for implementation (8 plans, 16 tasks, 6 waves).
No media listener or service has been implemented.
Requirements: MG-01 through MG-10 in
`phases/02-media-gateway/02-CONTEXT.md`.
Canonical plan directory: `.planning/phases/02-media-gateway/`.
This is a parallel product expansion; existing engine/cloud backlog remains open.

Plan index: [02-INDEX.md](phases/02-media-gateway/02-INDEX.md).
Independent review: [02-REVIEW.md](phases/02-media-gateway/02-REVIEW.md).
