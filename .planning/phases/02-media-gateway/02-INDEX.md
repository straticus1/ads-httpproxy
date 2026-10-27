# Phase 02: Optional media gateway — execution index

**Status:** planning only. Eight executable plans; no media code, deployment or backend test has been performed by this planning change. All commands are future implementation checks.

## Goal and boundary

An operator can enable an independent `cmd/ads-media` service to authorize supported SIP calls and TURN credential issuance for verified tenants, while mature external services forward packets. Disabled media opens no listeners and leaves `cmd/proxy` independent.

Reference stack: Kamailio signaling, ADS control/identity/policy, RTPengine media, coturn TURN. ADS alone issues NG commands and returns rewritten SDP to Kamailio. Initial SIP profile is authenticated configured trunks, nonforking early offers, tagged183/200, ACK without SDP, BYE/CANCEL and serialized re-INVITE/UPDATE hold/resume. Reject late offers, SDP-in-ACK, multipart bodies, forks and unverified endpoint changes. TURN is a separate allocation protocol, not an implicit SIP service.

## Dependency waves and ownership

| Plan | Wave | Depends on | Deliverable |
| --- | --- | --- | --- |
| [02-01](02-01-PLAN.md) | 1 | — | Default-off configuration and media contracts |
| [02-02](02-02-PLAN.md) | 2 | 02-01 | Verified media identity, policy and scoped APIs |
| [02-03](02-03-PLAN.md) | 3 | 02-02, 02-04 | Durable reservations and idempotent dialog lifecycle |
| [02-04](02-04-PLAN.md) | 2 | 02-01 | Bounded RTPengine control and media capability profiles |
| [02-05](02-05-PLAN.md) | 4 | 02-03 | Kamailio bridge/configuration and call scenarios (live proof in 08) |
| [02-06](02-06-PLAN.md) | 4 | 02-03 | TURN issuance with backend-enforced tenant partitions |
| [02-07](02-07-PLAN.md) | 5 | 02-05, 02-06 | Media service assembly, metadata telemetry and recovery |
| [02-08](02-08-PLAN.md) | 6 | 02-07 | Pinned real-backend tests and controlled release gates |

Same-wave pairs 02/04 and 05/06 have disjoint file ownership. Plan01 owns shared configuration/contracts; later plans consume them and must request an explicit follow-up dependency for a contract edit rather than silently racing another executor. Plan07 assembles all implementations; plan08 validates the complete real deployment. Expected execution commits follow plan/task boundaries, not a single omnibus commit.

## Shared proposed contracts

- `internal/config/media.go` owns DTOs only; never import runtime media/policy from config.
- `internal/media/contracts.go` owns typed lifecycle/backend/services in the parent package. `internal/media` may import `auth` and `policy` but never its child `api`, `rtpengine` or `turn` packages. Children implement/consume parent interfaces. `policy.MediaInput` uses policy-owned DTOs and never imports media. Only `cmd/ads-media` imports all implementations and performs dependency injection. `config` imports none of these runtimes.
- Separate certificate-authenticated SIP callback identity from tenant/operator API credentials. Trust configured peer/account/trunk mappings, not SIP From or request tenant fields.
- Persistent dialog identity binds tenant, signaling peer, raw Call-ID and original initiator From tag; transaction branch is not a reservation key. Bind the responder To tag on the first tagged answer and reject a second fork tag. The opaque public ID returned on initial offer is retained in Kamailio dialog variables; subsequent transactions use that ID plus tenant/peer/Call-ID/canonical-tag checks. Reverse-direction BYE swaps wire tags but resolves the same dialog/reservation.
- Operation identity additionally binds direction, transaction branch, CSeq/method/event/status/SDP digest; CSeq sequences are tracked independently by direction. Retransmission replays only the matching result; a new re-INVITE branch does not allocate a second call. SIP response status distinguishes provisional183 from final200.
- Durable state stores ownership/generation/reservation/cleanup metadata only. Exact SDP response replay is bounded memory; restart reconciles/deletes recovered calls before mutation/readiness. This deliberately does not promise seamless call survival.
- Media policy has typed inputs and its own default-deny policy file/version. Existing HTTP signed-policy delivery does not automatically install media policy.
- RTPengine adapter uses bounded HTTP `/ng` cookie-space-JSON and a fixed private authenticated endpoint; no client-selected flags or control URL.
- Default encrypted-passthrough intent is not an interoperability assertion. Enabling a profile requires pinned real-backend evidence; plaintext requires an explicitly permitted trusted trunk. Crypto termination/bridging, recording and transcoding are not enabled.
- Strict tenant TURN uses dedicated coturn process/realm/ports/secret. Strict RTP media bandwidth uses dedicated RTPengine pool plus tested network shaping. Shared backend profiles cannot promise hard tenant limits.
- Credential issuance, TURN allocation count, SIP call count, component/port count, negotiated bitrate and actual packet bandwidth are separate resources.
- No dynamic TURN revocation API is planned. Removing a tenant credential from configuration and restarting prevents future issuance; already-issued TURN credentials and allocations retain the measured backend lifetime. Tests must prove the distinction.

## Chosen SDP dependency

Plan04 owns `go.mod` and `go.sum` and adds `github.com/pion/sdp/v3` pinned to `v3.0.18`, using `SessionDescription.UnmarshalString`. Its [official tagged module](https://raw.githubusercontent.com/pion/sdp/v3.0.18/go.mod) declares Go1.24 and the [upstream repository](https://github.com/pion/sdp) identifies the MIT license. This planning lookup verified module provenance, not a vulnerability scan or installed runtime. Verify checksums/advisories at execution and record any required security upgrade explicitly. Pion supplies SDP structure; bounded ICE candidate attribute grammar and destination-policy checks remain ADS adapter responsibilities. No undocumented backend validation endpoint is assumed.

## Proposed tunable bounds

These are implementation defaults to validate, not measured capacity claims:

| Bound | Default |
| --- | --- |
| Callback / SDP / backend response | 64 KiB / 32 KiB / 128 KiB |
| Backend command deadline / inflight | 750 ms / 64 |
| Pending offer expiry / tombstone retention | 60 s / 300 s |
| Cleanup retry maximum delay / drain deadline | 30 s / 30 s |
| TURN credential TTL | 300 s, configurable 60–3600 s |
| Management list page | 100 maximum |
| Development RTP / TURN ports | 20000–20199 / 24000–24099, never overlapping host reserved ranges |

State/queue/tenant capacities must be finite explicit configured values. An uncertain operation retains its reservation; no silent eviction of live state. Existing sessions' expiry/drain behavior is protocol-specific and must not be conflated with credential expiry.

## Multi-source coverage audit

### Goal

| Source item | Coverage | Evidence plan |
| --- | --- | --- |
| Independently deployable default-off subsystem | COVERED | 01,07,08 |
| Verified platform identity/policy connected to mature media services | COVERED | 02,03,04,05,06 |
| Cloud-ready integration boundaries without unsupported HA claims | COVERED | 01,07,08 |

### Requirements

| Requirement | Coverage | Plans |
| --- | --- | --- |
| MG-01 | COVERED | 01, 07 |
| MG-02 | COVERED | 02, 05, 06 |
| MG-03 | COVERED | 01, 03, 07 |
| MG-04 | COVERED | 05, 08 |
| MG-05 | COVERED | 03, 04, 08 |
| MG-06 | COVERED | 06, 08 |
| MG-07 | COVERED | 04, 05, 08 |
| MG-08 | COVERED | 01, 02, 03, 04, 06, 08 |
| MG-09 | COVERED | 07, 08 |
| MG-10 | COVERED | 07, 08 |

### Context decisions and constraints

Context does not assign D-IDs; labels below are local audit labels, not additional user decisions.

| Context item | Coverage | Plans |
| --- | --- | --- |
| C01 optional/default-off and HTTP unaffected | COVERED | 01,07,08 |
| C02 separate signaling/control/media responsibilities | COVERED | 01,04,05,07 |
| C03 mature SIP/RTPengine integration, no homegrown SIP stack | COVERED | 04,05,08 |
| C04 authenticated TURN with truthful lifetime/quota limits | COVERED | 02,06,08 |
| C05 no media packet path through HTTP/AI | COVERED | 01,04,07 |
| C06 opaque encryption by default, explicit tested profiles | COVERED | 01,04,08 |
| C07 Kamailio first adapter and exact version/license verification | COVERED | 05,08 |
| C08 one region/one owner, no call-migration guarantee | COVERED | 03,07 |
| C09 one SDP/NG owner and identity mapping | COVERED | 02,03,05 |
| C10 concrete tasks, tests, threats and traceability | COVERED | all eight plans |

### Research constraints

| Research item | Coverage | Plans |
| --- | --- | --- |
| Separate process and import-cycle boundary | COVERED | 01,07 |
| Existing scoped management has no implicit media authority | COVERED | 02 |
| Native SIP trunk identity is not OIDC identity by assertion | COVERED | 02,05 |
| Branch/CSeq/retransmission/late success/cleanup semantics | COVERED | 03,05,08 |
| NG cookie framing, to-tag, bounded private authenticated transport | COVERED | 04 |
| TURN REST credential convention is not HTTP allocation/revoke API | COVERED | 06,08 |
| Refresh/secret rotation/active-allocation lifetime unverified until pinned test | COVERED | 06,08 |
| Username quotas and issue count cannot establish active-call quotas | COVERED | 01,06,08 |
| RTPengine bandwidth admission is not per-tenant shaping | COVERED | 01,04,06,08 |
| SDP/ICE/IPv4-mapped/metadata-peer restrictions | COVERED | 04,06,08 |
| RTCP/mux/component capacity, no two-ports-per-call assumption | COVERED | 01,03,04,08 |
| Silence/hold is not automatic call termination | COVERED | 03,05 |
| No raw SDP/crypto/media in durable state and telemetry | COVERED | 03,07,08 |
| Real Linux backends/NAT, dependency preflight and no green skips | COVERED | 08 |
| Exact versions/digests/licenses not verified during planning | COVERED | 08 |
| Backend loss/restart/drain and HTTP regression | COVERED | 03,07,08 |

### Explicit exclusions — not missing coverage

Carrier SBC parity, PSTN/emergency/billing, arbitrary SIP helpers/registrar, transparent interception, browser UI, transcoding/recording/transcription/AI media inspection, simultaneous OpenSIPS support, multi-region seamless handoff, distributed quotas, and homegrown SIP/SRTP/TURN stacks are outside the context boundary. SRTP termination/bridging is disabled rather than claimed by passthrough support. Late offer/forking and other rejected signaling profiles require a separately scoped extension with fixtures.

## Execution completion evidence

Each plan produces its own SUMMARY only after implementation. The release requires the real-backend report set from plan08, documented encryption/quota/transport matrix, no unresolved high-severity threats, and all MG requirements mapped to passing artifacts. Unit tests alone do not complete the media phase. See [validation](02-VALIDATION.md) and [research](02-RESEARCH.md).

