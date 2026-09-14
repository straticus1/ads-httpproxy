# Troubleshooting

- **401 from the management API:** use `X-API-Key` or configured API Basic
  credentials. `ads-admin` and `ads-dev` accept `-secret`/`ADS_API_SECRET` or
  `-user`/`-password`; Bearer and the legacy HMAC middleware are not used by
  the running management server.
- **407 from the forward proxy:** configure the primary proxy authentication
  mechanism. With `mechanism: none`, explicitly set `allow_unauthenticated: true`
  and restrict `allowed_source_nets` for local development.
- **Startup rejects a public admin bind:** set an API secret different from
  `changeme`, configure API users, or bind `api_addr` to loopback.
- **TLS certificate errors:** check the destination hostname, CA trust, and
  certificate expiry. Trust the interception CA with `ads-dev -ca`; an HTTP/3
  listener needs a separate server certificate matching the gateway hostname.
- **HTTP/3 cannot start:** configure both `quic_cert` and `quic_key`, or AutoCert.
  Verify UDP is reachable on the proxy's TCP port and no UDP listener conflicts.
- **QUIC relay connects but TLS fails:** opaque relaying preserves the original
  TLS handshake. The upstream certificate must match the client's hostname.
- **Toolkit endpoints return 404:** enable `devtools.enabled` and restart.
- **Capture is missing:** captures appear after a response body finishes/closes.
  Pre-transport blocks, cache hits, opaque tunnels, and goproxy's direct HTTP/2
  interception path are outside transport inspection.
- **Replay fails:** capture IDs can be evicted at capacity; redacted queries need
  an explicit `-url`. Automatic replay accepts GET/HEAD, not write operations.
- **A plugin fails to load:** match the proxy's Go version, dependencies, and
  compiler flags; export `func NewPlugin() plugin.Plugin`; inspect duplicate
  names and API versions. A code upgrade needs a distinct plugin package path
  and `.so` filename because Go caches loaded libraries.
- **Runtime config update returns 501:** live replacement is disabled. Run
  `ads-admin validate -config path.yaml`, then restart the service.

`ads-admin status` tests API liveness; `stats`, `connections`, and `metrics`
provide traffic visibility. API liveness does not attest to every upstream's
health. Use `ads-dev request` to verify the actual route/proxy path.
