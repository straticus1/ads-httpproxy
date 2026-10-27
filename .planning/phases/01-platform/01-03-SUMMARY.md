---
phase: 01-platform
plan: 03
subsystem: traffic-analysis
tags: [sampling, workers, privacy, durability]
requires: []
provides: [bounded-worker-manager, deterministic-classification, durable-findings]
affects: [proxy-integration, adaptive-filtering, ai-investigation]
tech-stack:
  added: []
  patterns: [bounded-channel, context-cancellation, rotated-jsonl]
key-files:
  created: [internal/analysis/types.go, internal/analysis/privacy.go, internal/analysis/analyzer.go, internal/analysis/manager.go, internal/analysis/journal.go, internal/analysis/manager_test.go]
  modified: []
decisions:
  - Sampling queues are non-durable; completed findings may be journaled.
  - Each journal path belongs to one process and is not a distributed queue.
  - Tenant and subject must originate from verified identity supplied by integration.
metrics:
  completed: 2026-10-27
  tests: 17
---

# Phase 01 Plan 03: Bounded traffic analysis workers

Implemented nonblocking traffic submission with tenant budgets, deterministic
sampling, bounded retries, privacy sanitization, and retained findings persisted
in size-bounded JSONL journal segments.

## Public integration contract

- `Validate(Config) error`, `New(Config, Analyzer) (*Manager, error)`.
- `Submit(Event) bool` never waits for queue capacity or journal I/O; an empty
  event ID receives a random ID. Caller-supplied stable IDs deduplicate retained
  findings and retries. IDs include tenant identity in their derivation.
- `Snapshot(Filter) []Finding` returns newest findings first; filters support
  tenant, category, limit, and inclusion of expired findings. Evidence maps are
  copied. Capacity and TTL are independently enforced.
- `Stats() Stats` exposes accepted/sampled/dropped/failed/retried/completed counts,
  queue depth, retained findings, and journal failures.
- `Close(context.Context) error` rejects new events and drains pending work.
  Deadline cancellation propagates to analyzers; custom analyzers must honor it.
- `Analyzer.Analyze(context.Context, Event) ([]Finding, error)` runs concurrently,
  with a five-second attempt timeout and up to three configurable retries.
- `Event.Decision` supports allow/block/error; policy blocks produce a
  `policy_block` finding with a bounded, sanitized reason.

The nil/default analyzer classifies web/JSON API/known AI API traffic and detects
server errors, policy blocks, and credential/SSN-shaped preview patterns. Each
finding carries category, confidence, reason, tenant, event identity, expiry,
policy/model versions, and bounded evidence. It performs no network requests.

## Privacy and resource behavior

URL credentials/fragments are removed and query values redacted. Only content
type/length headers are retained. Bodies are disabled by default; enabled text
previews are bounded and common credential patterns redacted. Binary previews
are excluded. Oversized identity values are rejected rather than truncated into
another tenant. Integrations must not derive tenant identity from a client header.

Worker count, queue capacity, tenant cardinality, tenant rate, retained findings,
preview bytes, analyzer output count, evidence count, and journal segment sizes
are bounded. Analyzer panics become counted failures instead of killing workers.

## Durability

Configured journals use mode 0600, synchronous append/fsync in worker context,
and one rotated `.1` segment. Startup reads at most the configured segment size
and retains only the configured finding count. An incomplete final record from
a process crash is truncated before appending; malformed complete records fail
startup. Unusable journal paths fail construction rather than silently disabling
persistence. Journal runtime failures increment `journal_errors`; findings remain
available in bounded memory.

Limitations: one process must exclusively own each journal path. Accepted samples
are not durable until analysis produces and journals findings. Retained-ID
deduplication is bounded by finding retention. Arbitrary PII in URL paths and
opt-in text previews is not comprehensively anonymized. The default rules are
deterministic classifications, not a trained threat detector. Durable audit trails
or distributed brokers need a separate sink/queue contract.

## Validation

- `ASDF_GOLANG_VERSION=1.25.7 go test ./internal/analysis`: passed.
- `ASDF_GOLANG_VERSION=1.25.7 go test -race ./internal/analysis`: passed, 17 tests.
- `git diff --check -- internal/analysis`: passed.

Tests cover saturation without blocking, tenant quotas/cardinality, stable retry
identity and deduplication, privacy and preview limits, binary exclusion, deadline
cancellation, snapshot isolation/expiry, journal restart/tail repair/rotation,
startup failures, default categories, concurrent submit/close, analyzer failures,
deterministic sampling, policy decisions, and oversized identity rejection.

## Deviations from Plan

- Added panic containment and rejection of oversized identity values as critical
  worker-process and tenant-isolation safeguards.
- Added policy decision fields at the integration owner's request so blocked
  requests can be analyzed even when no outbound transport is invoked.
- No commits or shared STATE/ROADMAP edits: the integration owner explicitly
  batches changes into the user's requested 5–10 focused commits.

## Threat Flags

| Flag | File | Description |
| --- | --- | --- |
| file-persistence | internal/analysis/journal.go | Configured local findings files may contain identity metadata; restrictive permissions and bounded recovery enforced. |
| captured-content | internal/analysis/privacy.go | Opt-in body previews can still contain arbitrary PII; only common credentials are redacted. |

## Self-Check: PASSED

All six implementation/test files and this summary exist. No placeholders or
unimplemented branches were found. No commit claimed; root owns committing.
