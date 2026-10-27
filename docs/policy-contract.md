# Policy decision contract v1

The CEL engine exposes `Decide(context.Context, *EvalContext) Decision`. Only
`effect: allow` permits a request; callers must enforce every returned obligation
before forwarding it. `Evaluate` remains a compatibility wrapper. `Decision.Actions()`
adapts typed obligations to the existing action executor.

```json
{
  "schema_version": "v1",
  "policy_version": 3,
  "policy_id": "finance-read",
  "effect": "allow",
  "matched": true,
  "reason": "Allowed by policy finance-read",
  "obligations": [{"kind": "rate_limit", "requests_per_second": 10}]
}
```

Rules run in configured order. The first matching `allow` or `block` is terminal;
there is no implicit deny-overrides priority. `log` records a match and continues,
without executing its actions. No terminal match uses the snapshot's default
effect. Legacy new engines default to allow; deployments requiring default deny
must set `block`. Evaluation errors, canceled contexts, and invalid inputs block.
The decision reports the version held throughout that evaluation, including default
and error decisions. Runtime failures never trigger fallback to another rule.

Supported obligations are `rate_limit` (1–100000 requests per second) and
`redact_headers` (a list of valid HTTP header names). Unknown actions, invalid
arguments, nonboolean CEL expressions, duplicate IDs, and missing IDs/conditions
reject the entire replacement. CEL evaluation has a cost limit and cancellation
checks. Rule IDs and versions should identify enforcement buckets and audit events.

## Verified request input

`NewVerifiedInput(request, now)` constructs the stable input shape and takes an
explicit UTC evaluation clock for replay. Identity comes only from the private
authenticator context, never identity headers. Verified TLS chains set
`client.verified_mtls`. The `user` object includes subject, issuer, tenant, username,
groups, scopes, AMR and ACR. `request.headers` remains untrusted request data.
Replayed `EvalContext` values must come from trusted server records; callers must
not accept client-submitted identity fields as authenticated input.

`request.hostname` uses the absolute request URL authority when available,
otherwise the request authority; it is lowercase with the terminal dot removed.
`request.port` is an integer: explicit destination port, otherwise HTTP 80,
HTTPS 443, or CONNECT 443. Invalid authorities/ports fail closed.
Legacy `request.host` retains the incoming Host field for compatibility; policy
enforcement should use `request.hostname` for destination matching.
`ipInCIDR(client.ip, "10.0.0.0/8")` performs actual IP prefix matching. Invalid
addresses or prefixes produce evaluation errors, including when negated.

## Atomic publication

`Snapshot()` returns independent rule/action copies with `version`,
`default_effect`, and `schema_version`. Compiled programs are never exported.
`Replace(expectedVersion, rules, defaultEffect)` compiles and validates all rules,
then compares the expected version under the publication lock. Exactly one
competing writer for a version succeeds; stale writers get `ErrVersionConflict`.
Success increments the instance-local monotonic version. Failed validation or
version conflicts leave the complete last-known-good snapshot unchanged.
Mutating submitted rules, snapshots, or returned obligations after the call cannot
alter active policy. Callers must not concurrently mutate inputs during the call.

`ReplaceWithPersist` adds a callback receiving the next version after validation
and version comparison, before publication. The callback runs under the engine
lock and must not call engine methods. It must durably commit its file/transaction
before returning success. Failure preserves active policy/version. Persistence
implementation and startup restoration are the caller's responsibility; this
contract alone does not provide distributed consistency or persistent versions.

`LoadFromFile` accepts a bare YAML rule list or a `policies` mapping and uses the
same validated replacement path. Invalid loads retain existing rules. The legacy
`SetDefaultEffect` changes the version when the default changes; unrecognized
values fail closed to block. Administrative updates should use `Replace` to
atomically update rules and their default together.
