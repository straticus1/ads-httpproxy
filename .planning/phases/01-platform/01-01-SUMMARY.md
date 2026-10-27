---
phase: 01-platform
plan: 01
subsystem: cache
tags: [http-cache, redis, invalidation, concurrency]
requires: [review-fixes-69a00f4]
provides: [URL-variant invalidation, cross-instance generation coordination, bounded synchronous Redis writes]
affects: [proxy-transport, shutdown]
key-files:
  created: [internal/cache/invalidation.go, internal/cache/invalidation_test.go]
  modified: [internal/cache/http.go, internal/cache/redis.go, internal/cache/review_test.go, internal/proxy/cache.go]
completed: 2026-10-27
---

# Phase 01 Plan 01: Shared cache invalidation

Successful unsafe requests and administrative purges invalidate every URL representation, including in-flight fills and other Redis-connected instances' memory caches.

## Implementation

- A resource hash preserves escaped paths and raw query ordering, normalizes default ports and scheme/authority case, and groups GET/HEAD, Host, and Accept-Encoding variants.
- A bounded set of 256 generation partitions plus a global epoch controls visibility. Invalidating a partition can conservatively evict unrelated colliding resources but cannot retain the target resource.
- `Begin(req)` captures an opaque generation before the upstream call. `SetIfCurrent(req, resp, generation)` writes into that generation's namespace; a response begun before invalidation cannot populate the newly visible namespace.
- `Invalidate(req, resp)` handles successful (2xx/3xx) unsafe methods and same-origin Location/Content-Location resources. Failed writes and safe methods leave cached representations intact.
- `Purge` requires an absolute HTTP(S) URL and invalidates all variants. `PurgeAll` rotates the global epoch, including in-flight fills.
- Redis-backed reads check shared generation tokens before consulting L1. Tokens are random and recreated on absence, so a Redis reset/eviction does not recreate an old L1 namespace. Metadata cardinality is bounded at 257 keys.
- Redis writes are synchronous with a one-second deadline; no per-response background write goroutines remain. A failed invalidation disables the affected process's cache until a successful full purge.
- `HTTPCache.Close()` exposes Redis shutdown ownership for the parent integration plan.

## Validation

- `ASDF_GOLANG_VERSION=1.25.7 go test ./internal/cache` passed, including an isolated real Redis Unix-socket integration test.
- `ASDF_GOLANG_VERSION=1.25.7 go test -race ./internal/cache` passed.
- New tests verify variants, global/URL invalidation of in-flight generations, successful mutation methods, failed/safe methods, same-origin related resources, cross-instance L1 invalidation, Redis reset, and failed invalidation bypass.
- Existing expired-payload test was adjusted to insert into the current generation namespace, preserving its original intent.
- `git diff --check -- internal/cache internal/proxy/cache.go` passed.

## Integration contract

`internal/proxy/cache.go` already captures `Begin` before fetching and invokes `Invalidate` before storing. The parent should call `s.httpCache.Close()` after draining request handlers as part of shutdown.

No new configuration or dependencies are required. Existing `Set` is retained for direct callers; any caller performing asynchronous upstream work must use the Begin/SetIfCurrent pair to protect the fetch-to-store interval.

## Limitations

- Changes made directly to origins, bypassing these proxies, cannot trigger invalidation. Origin freshness directives remain necessary.
- Redis is consulted for generation metadata even on L1 hits, adding a bounded network operation; Redis errors bypass caching.
- During a partial network partition, a proxy unable to publish invalidation disables its own cache, but cannot guarantee invalidation at other still-connected instances. This is not a distributed transaction with the origin.
- Superseded data namespaces expire under their original TTL and memory budget; logical purge makes them immediately unreachable rather than synchronously deleting every data key.
- The real Redis test skips if `redis-server` is absent. No external Redis deployment was modified.

## Deviations

Root explicitly owns commits and shared STATE/ROADMAP updates to maintain the requested 5–10 coherent commit series; this executor left changes uncommitted and did not edit shared planning state.

No known stubs.

## Self-Check: PASSED

All listed files exist and package/race checks passed. Commit creation is intentionally delegated to the root orchestrator.
