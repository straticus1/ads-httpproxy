# Optional media gateway — planning context

Status: planning only. User requested written plans, not implementation/deployment.

## Authorized direction

Extend the standalone open-source proxy with an optional media gateway suitable
for later use in a managed cloud platform. All media listeners/services are off
by default. Existing HTTP proxy behavior must be unaffected when disabled.

Separate platform authorization/control, SIP signaling, and RTP/RTCP media.
Integrate mature SIP signaling software and RTPengine rather than implement a SIP
transaction/dialog stack or full session border controller. Include authenticated
TURN integration for WebRTC/NAT traversal, with explicit limits on revocation,
bandwidth enforcement and transport support rather than invented backend APIs.
Keep packet forwarding out of HTTP body inspection and AI workers. Encrypted
media remains opaque unless a separately configured, documented termination mode
is explicitly enabled; no recording/transcription/transcoding by default.

## Planning assumptions (recommendations, not user-mandated vendors)

Use Kamailio as the first SIP reference adapter, RTPengine for media, and coturn
for TURN, subject to official documentation, licensing and pinned interoperability
verification during implementation. OpenSIPS is an alternative behind the adapter
boundary; do not implement two SIP backends initially. Initial deployment is
single-region, single-owner per call with configured backend endpoints. No promise
of distributed quota enforcement, call migration or fleet high availability.

Plan native SIP call flow separately from standalone TURN credentials; TURN is
not automatically a SIP media relay replacement. Define who rewrites SDP, who
owns offer/answer transitions and cleanup, and how authenticated SIP/backend
identity maps to the existing immutable platform principal and tenant context.

## Requirements

- MG-01: opt-in configuration, dependency boundaries, disabled-mode regression.
- MG-02: trusted tenant identity, CEL admission, scoped media management actions.
- MG-03: bounded/idempotent session lifecycle and atomic quotas/reservations.
- MG-04: authenticated SIP integration, offer/answer and SDP relay coordination.
- MG-05: bounded RTPengine control adapter and deterministic cleanup/reconciliation.
- MG-06: authenticated short-lived TURN issuance, permissions and documented revocation limits.
- MG-07: encrypted-media modes and NAT/ICE/address-family compatibility matrix.
- MG-08: port/call/bandwidth limits and actual enforcement ownership, no open relay.
- MG-09: metadata-only audit/QoS, privacy/retention and bounded-cardinality metrics.
- MG-10: real backend integration tests, fault/load validation, drain and rollout gates.

## Non-goals for the first release

Carrier SBC feature parity; PSTN billing/emergency calling; arbitrary SIP helper
support; transparent interception; transcoding/recording/AI inspection; browser UI;
multi-region seamless call handoff; homegrown cryptography or SIP stack. Deferred
features must remain visible in the roadmap rather than disappearing from scope.

## Canonical repository references

- `.planning/ROADMAP.md`, `.planning/STATE.md`
- `docs/cloud-engine.md`, `docs/policy-contract.md`
- `internal/config/platform.go`, `internal/config/api_keys.go`
- `internal/auth/principal.go`, `internal/api/scoped.go`
- `internal/policy/contract.go`, `internal/proxy/server.go`
- `internal/proxy/connect.go`, `internal/proxy/quic.go`

Planning outputs must include concrete tasks/files, dependencies/waves, acceptance
tests, failure behavior, threat models and requirement traceability. Do not run
implementation commands or deploy/download media services as part of planning.
