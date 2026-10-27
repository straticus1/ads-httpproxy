# Phase 02 pre-execution plan review

Status: **VERIFICATION PASSED — pre-execution plans**. Planning review only; no media code
or backend runtime was executed. Reviewed eight plans, context, research,
validation strategy, roadmap, and execution index on 2026-10-27.

## Structural checks that pass

- MG-01 through MG-10 appear in plan requirement metadata and have substantive tasks.
- Eight plans contain two tasks each; all sixteen tasks have files, read-first,
  action, automated verification, acceptance criteria and done conditions.
- Dependency graph is acyclic and waves match dependencies.
- Same-wave pairs 02/04 and 05/06 have no declared file ownership collisions.
- Separate signaling/control/packet ownership, default-off behavior, explicit
  protocol limits, real-backend release gates and tenant partitions are planned.
- TURN credential issuance is correctly distinguished from backend allocation;
  no immediate active-allocation revocation or shared hard-bandwidth claim is made.

## Final revision review

All six initial findings are resolved in the current plans and execution index.
This is approval of plan completeness, not evidence of implemented behavior.

| Finding | Original severity | Resolution verified |
| --- | --- | --- |
| MG-REVIEW-01 | BLOCKER | Plan04 selects Pion SDP v3.0.18 and UnmarshalString, owns go.mod/go.sum, requires provenance/advisory checks, and specifies bounded connection/RTCP/ICE validation with RTPengine-only rewriting. |
| MG-REVIEW-02 | BLOCKER | Plans01/03/05 and INDEX separate stable dialog identity from branch-based operation identity, bind opaque IDs to tenant/peer/Call-ID/canonical tags, track directional CSeq and test reverse BYE/new-branch renegotiation against one reservation. |
| MG-REVIEW-03 | BLOCKER | Plan06 and INDEX explicitly use operator configuration removal/disable plus controller restart to stop future issuance; tests must distinguish this from existing credential/allocation lifetimes. No fabricated revoke endpoint remains. |
| MG-REVIEW-04 | BLOCKER | Plans02/03/07 and INDEX fix import direction: policy owns its inputs; parent media consumes interfaces without child imports; cmd/ads-media composes implementations; config remains DTO-only. |
| MG-REVIEW-05 | WARNING | All eight plans now contain artifact-specific structured from/to/via links. All sixteen tasks retain automated verification and complete task fields. |
| MG-REVIEW-06 | WARNING | Plan05 truths, artifact descriptions, objective and success criteria now claim bridge/configuration/scenario preparation. Real call verification remains a mandatory plan08 gate after plan07 assembly. |

```yaml
status: passed
plans_reviewed: 8
tasks_reviewed: 16
execution_waves: 6
unresolved_blockers: 0
unresolved_warnings: 0
issues: []
```

## Historical findings (resolved)

The following records preserve the original revision requests; they are not
outstanding findings. Resolution evidence is recorded above.

```yaml
resolved_issue_history:
  - id: MG-REVIEW-01
    severity: BLOCKER
    dimension: task_completeness
    plan: 02-04
    task: 2
    description: Mandatory SDP/ICE peer validation is left as a choice between an unspecified maintained parser and undocumented backend structured validation. The latter capability is not established, and dependency ownership is absent.
    fix_hint: Select a concrete parser/validation mechanism, assign provenance/version verification and any go.mod/go.sum edits to this plan, and define extraction of session/media connection addresses, RTCP and ICE candidates. Preserve RTPengine-only rewriting.
  - id: MG-REVIEW-02
    severity: BLOCKER
    dimension: cross_plan_data_contracts
    plans: [02-01, 02-03, 02-05]
    description: SessionKey includes the transaction branch and From tag, but later re-INVITE/UPDATE/BYE requests use new branches and the opposite dialog direction swaps tags. The index retains an opaque ID but does not define its binding checks, per-direction CSeq tracking or how these events resolve the original reservation.
    fix_hint: Separate stable dialog identity from operation identity. Specify initial lookup, server-returned ID binding, tag orientation, peer/account authorization for each direction, new transaction branches and per-direction CSeq. Test opposite-direction BYE and renegotiation preserve exactly one session/quota and reject a foreign session ID.
  - id: MG-REVIEW-03
    severity: BLOCKER
    dimension: key_links_planned
    plans: [02-01, 02-02, 02-06]
    description: TURN tasks promise revocation that stops further issuance and returns a capability description, but TurnIssuer exposes only Issue and the API has no revoke/disable operation or documented operator configuration path controlling that deny state.
    fix_hint: Define the concrete issuance-disable/re-enable authority and interface, tenant/subject scope, persistence and API/configuration path, then add tests proving disabled subjects cannot obtain replacement credentials while existing allocations retain documented lifetime limits.
  - id: MG-REVIEW-04
    severity: BLOCKER
    dimension: dependency_correctness
    plans: [02-01, 02-02, 02-03, 02-04, 02-07]
    description: The index calls internal/media/contracts.go a leaf package although it shares package media with manager/runtime. Child adapters consume these types; importing them from media runtime or importing media types from policy would create cycles.
    fix_hint: State an enforceable import graph: policy owns MediaInput/Decision without importing media; core media consumes injected interfaces and never imports child adapters/api/turn; cmd/ads-media is the composition root. Alternatively move shared DTOs to a genuinely separate leaf package and update all ownership lists.
  - id: MG-REVIEW-05
    severity: WARNING
    dimension: verification_derivation
    plans: [02-01, 02-02, 02-03, 02-04, 02-05, 02-06, 02-07, 02-08]
    description: Every must_haves.key_links field contains the same generic strings instead of artifact-specific from/to/via links. Goal-backward verification cannot trace those entries to actual wiring.
    fix_hint: Replace generic entries with structured from/to/via links for configuration, auth-to-service dispatch, manager-to-backend/store, SIP SDP responses, TURN issuance, command assembly and CI-to-real fixtures.
  - id: MG-REVIEW-06
    severity: WARNING
    dimension: verification_derivation
    plan: 02-05
    description: The plan claims a two-way working call slice, but its verification only runs Go contract tests and the process assembly/real backend execution do not occur until plans07/08.
    fix_hint: Make plan05's completion claim explicitly bridge/config/scenario preparation, with the working two-way call acceptance gate assigned to08, or move real assembly/verification earlier and express the dependency.
```

## Requirement traceability

| Requirement | Plans |
| --- | --- |
| MG-01 | 01, 07 |
| MG-02 | 02, 05, 06 |
| MG-03 | 01, 03, 07 |
| MG-04 | 05, 08 |
| MG-05 | 03, 04, 08 |
| MG-06 | 06, 08 |
| MG-07 | 04, 05, 08 |
| MG-08 | 01, 02, 03, 04, 06, 08 |
| MG-09 | 07, 08 |
| MG-10 | 07, 08 |

The research's exact-version, backend-lifetime and enforcement uncertainties are
assigned to explicit execution verification gates. They must remain unclaimed
until those gates pass; no runtime result is inferred from this planning review.
