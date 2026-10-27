# Cloud engine boundaries

The proxy remains independently deployable. This increment adds a signed policy
ingestion boundary and tenant-scoped management credentials, not a hosted control
plane, billing service, distributed session store, or automatic fleet rollout.

## Signed policy releases

Configure the node with an audience, a dedicated state file, and trusted Ed25519
public keys. The signing private key stays off the proxy:

```sh
go run ./cmd/policy-bundle -generate-key -key ./signing.key
```

The command creates a new mode-0600 key file and prints the base64 public key.
Install that public key on the intended node group:

```yaml
control_plane:
  audience: production-eu
  state_file: /var/lib/ads/policy-bundle.json
  public_keys:
    release-2026: BASE64_PUBLIC_KEY
```

The parent directory must exist, be writable, and be dedicated to this instance.
Do not share the file across processes. With this configuration, a node without
a saved signed policy starts with default-deny until the first release arrives.
Existing local CEL rules are replaced by the signed release. Other security
layers (identity, access, WAF, adaptive, scripts) still apply independently.

A reviewed release JSON looks like:

```json
{
  "schema_version": "v1",
  "audience": "production-eu",
  "revision": 1,
  "issued_at": "2026-10-27T12:00:00Z",
  "expires_at": "2026-10-28T12:00:00Z",
  "default_effect": "block",
  "policies": [
    {"id":"employees","effect":"allow","condition":"\"employees\" in user.groups"}
  ]
}
```

Use current timestamps and a strictly increasing revision. Sign and deliver it:

```sh
go run ./cmd/policy-bundle -key signing.key -key-id release-2026 \
  -input release.json > bundle.json
curl -H "X-API-Key: $ADS_API_SECRET" -H 'Content-Type: application/json' \
  -X PUT --data-binary @bundle.json \
  https://management.example.com/api/control-plane/policy
```

The API requires global administrator authentication in addition to a trusted
signature. `GET` on the same path reports revision, local policy version, expiry,
and staleness. Payload bytes and key ID are covered by a domain-separated
signature. Wrong audience, unknown key, tampering, expired new releases,
non-increasing revisions, invalid CEL, and persistence errors reject the update.
Validation, file synchronization, atomic replacement, and directory synchronization
precede policy publication. If the rename succeeds but directory synchronization
fails, the update is not acknowledged and further updates are frozen until
restart; status exposes `update_error`. The old in-memory policy remains active,
but restart may load the new signed file. Filesystem guarantees still depend on
the host storage. A replay is rejected across normal process restarts.

Rollback means signing the previous rules under a **higher revision**. Rotate
keys by configuring overlapping trusted public keys and restarting nodes before
using the new signer. There is no private key transfer or discovery from bundles.

An already installed release remains active after expiry, including on restart,
and reports `stale: true`: expiry is an admission deadline for new releases, not
an automatic outage switch. Invalid saved signatures fail initialization.
Protect the state file: deleting or restoring old local state can roll back the
revision watermark. This is not a hardware-backed anti-rollback mechanism.

No network call or signature verification occurs per proxied request. Fleet
enrollment, staged targeting, health gates, remote fetch/polling and centralized
audit storage remain control-plane work. Delivery currently uses authenticated
push to each node.

## Tenant-scoped management credentials

Global administrator keys and Basic administrator users retain global access.
For tenant readers, generate a high-entropy key and store only its SHA-256 hex
digest in configuration. Keep the raw credential with its client:

```yaml
api_keys:
  - id: tenant-a-reader
    sha256: HEX_SHA256_OF_RANDOM_CREDENTIAL
    tenant: tenant-a
    scopes: [findings:read, ai:explain]
```

Send the raw credential as `X-API-Key`. It can call only GET
`/api/analysis/findings` and/or POST `/api/ai/explain` according to its scopes.
Omitting the tenant selects its own tenant; specifying a different tenant returns
403. It cannot access config, global stats, policy mutation, session revocation,
plugins or cache operations. When scoped keys are configured, `/metrics` also
requires global administrator authentication. Public PAC is restricted to the default policy when scoped keys are configured;
tenant/user selectors are rejected. Liveness and the dashboard remain public;
bind management to a private network.

Keys are configured locally and rotated by restart. Findings still share a
bounded process store; per-tenant sampling budgets do not reserve per-tenant
retention capacity. Data-plane distributed quotas, durable queues, cache
namespaces for every tenancy mode, billing-grade accounting and noisy-neighbor
resource isolation are not provided by these management credentials.

See [policy contract](policy-contract.md), [protocol validation](protocol-validation.md),
and [Squid compatibility](squid-compatibility.md) for the supporting engine work.
