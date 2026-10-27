# Platform requirements

Approved direction: user requested all five proposed roadmap investments.

R1 Reliability: invalidate cached URL variants after successful unsafe methods,
prevent in-flight stale reads repopulating invalidated cache, enforce configured
route request limits, and shut down owned listeners/workers.
R2 Identity: verified immutable request identity (subject/issuer/groups/scopes/tenant/
authentication strength); OAuth2 resource/scope/expiry validation; OIDC browser
Authorization Code + PKCE/state/nonce/session/logout; mounted SAML SP metadata/ACS/login.
Browser flows apply to reverse gateway hosts, never arbitrary forward destinations.
R3 Zero trust: identity-aware CEL; configurable default deny; explicit policy errors;
mTLS identity where certificates are actually verified; trusted posture signals with
expiry; real header-redaction and request-rate actions; structured decision events.
R4 Workers: bounded asynchronous sampling; redacted metadata, optional bounded text
previews; per-tenant limits, queue drop/error counters, retries, stable IDs; append-only
local durable findings with bounded rotation; deterministic classification and safe
shutdown. Analysis failures do not stall proxy forwarding.
R5 Adaptive: versioned allow/block rules over findings, observe/shadow/enforce modes,
confidence/expiry/reason; authenticated admin preview/update/rollback; no worker can
silently overwrite policy. Current requests use cached/inline verdicts only.
R6 AI: authenticated investigation/explanation endpoint using bounded redacted findings;
optional configured model endpoint with timeout/size limits and no tools or mutation;
local deterministic explanation available without external credentials. AI egress
host/model allowlists, request budgets, credential stripping, streaming preservation.

Tests: unit and HTTP integration for successful and negative auth flows, policy
identity spoofing, cache invalidation/races, queue saturation/retries/isolation,
adaptive shadow/enforce/rollback/expiry, AI provider failure and egress controls.
All new features opt-in; existing configs remain valid. Operational docs must state
single-instance/session-store and distributed-system limitations accurately.

## Optional media gateway (planning only)

MG-01 through MG-10 are defined in
[phase context](phases/02-media-gateway/02-CONTEXT.md#requirements).
They cover default-off behavior, identity/policy, session reservations, SIP/SDP,
RTPengine, TURN, encrypted-media/NAT compatibility, enforced resource limits,
metadata privacy and real-backend/failure/load validation. None is implemented
by this planning change. Detailed traceability is maintained in the phase plans.
