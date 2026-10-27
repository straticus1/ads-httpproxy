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
