---
phase: 02-media-gateway
status: planned
date: 2026-10-27
---

# Validation strategy

This describes future checks. No media integration, load test or protocol
certification has been run as part of writing these plans.

## Test layers

| Layer | Required evidence | Failure behavior |
| --- | --- | --- |
| Configuration/unit | Disabled mode creates no media listeners/goroutines/backend clients; invalid config rejected; fake-clock expiry; state transitions; redaction | Block merge |
| Concurrency/fuzz | Atomic reservation caps, tenant separation, idempotency, duplicate/out-of-order events, parser/control-message bounds, cancellation | Block merge; race detector required |
| Backend adapter | Scripted RTPengine replies, timeouts, malformed/oversized messages, cookie mismatches, partial success, cleanup retry | Deny new allocation, retain bounded cleanup debt |
| Real SIP/media | Pinned Kamailio + RTPengine; authenticated two-way flow; offer/answer; retransmissions; early media/hold/renegotiation where supported; CANCEL/BYE teardown | Mark unsupported paths explicitly; never infer success from HTTP 200 |
| Real TURN | Pinned coturn; authenticated Allocate/Refresh/CreatePermission/ChannelBind and relay; expiration, peer restrictions, quota exhaustion, transports | Missing backend fails required CI job; issuing a credential alone is not a pass |
| Recovery | Controller/backend crash, restart, duplicate callback, dropped delete reply, cleanup failure, forced drain, clock skew | Assert no unbounded allocation/reservation growth and no unauthorized reopen |
| Load | Calls/allocations, p50/p95/p99 setup latency, RTP loss/jitter, backend/controller CPU/RSS, port utilization, cleanup latency | Compare against declared environment/profile budgets, not unmeasured claims |

## Cross-cutting negative cases

- Tenant B cannot list, modify, refresh, delete or attribute usage to tenant A's
  calls/credentials by guessing identifiers, reusing raw Call-ID, spoofing headers,
  changing callback bodies or replaying an authenticated event.
- Untrusted SIP `From`/Contact/SDP does not become a platform principal. A trusted
  bridge is authorized for configured trunks/tenants, not every tenant.
- Destination validation covers literal IPs, IPv4-mapped IPv6, DNS rebinding where
  resolution is supported, SDP connection/media addresses and ICE candidates.
- Tenant allowlists explicitly distinguish permitted private enterprise peers
  from loopback/link-local/metadata/management networks. Relay control ports are
  unreachable from untrusted client/media networks.
- A timeout after backend allocation does not free the quota while leaving an
  untracked media relay. Pending cleanup continues to consume its reservation.
- Duplicate terminal events do not decrement quota twice. Late offers/answers
  cannot recreate a session after closure. Draining rejects new reservations.
- Tokens, TURN shared secrets, Digest credentials, raw SDP containing keys and
  media payloads never appear in ordinary logs, traces, metrics or config output.
- Client-selected RTP payload types, SSRCs or ports do not authorize a new peer.
  Any symmetric-RTP learning is constrained to the negotiated policy and tested.

## Repeatable execution contract

Each PLAN specifies exact future unit/integration targets and expected assertions.
The implementation must add a dedicated Linux backend integration job with
version/digest locks, bounded runtime, isolated test networks and deterministic
teardown. Mock-only jobs cannot satisfy real-backend requirements. An unavailable
container runtime or missing binaries must report a failed prerequisite for the
required integration gate, never a green skipped result.

Run unit/race tests first, then backend scenarios, then isolated load/fault tests.
Keep ordinary HTTP regression tests in the same gate to prove disabled-mode
compatibility. Repository Go commands currently require
`ASDF_GOLANG_VERSION=1.25.7` in this workspace; version changes must be deliberate.

All release claims name the tested signaling/media transports, address families,
encryption mode, backend versions, quota profile and topology. Capacity thresholds
are set after a documented baseline on designated hardware; a loopback smoke test
does not establish production capacity. Enabling public production listeners is
a later deployment action, not part of planning or automatic test execution.

## Release gate

Every MG requirement maps to a plan and a verification artifact. A restricted
first-release compatibility matrix is acceptable; an advertised mode without a
passing real-backend scenario is not. High-severity open threats, unknown cleanup
ownership, unverified hard quota promises, or an unauthenticated relay block release.
