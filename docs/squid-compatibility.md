# Strict Squid access-control migration

`squid2ads` converts a limited, explicitly validated forward-proxy configuration into `config.yaml` and ordered CEL `policy.yaml`. It is not a general Squid replacement or a cache configuration importer. Old converter output (`policy.star`) must be regenerated; it used approximate IP checks and could silently drop restrictions.

```sh
go run ./cmd/squid2ads -input cmd/squid2ads/testdata/supported.conf -output ./ads-migrated
go run ./cmd/proxy -config ./ads-migrated/config.yaml
```

The output directory must not already exist; its parent must exist. Input errors include the source filename and line number. Unsupported input produces no output directory. The converter compiles the emitted policy before publishing the complete directory. It never overwrites existing output. Files are private (0600), and the output directory is private (0700). Output is deterministic for the same source and output path; `policy_file` is absolute so startup does not depend on the working directory. Moving the directory requires updating that path.

## Supported subset

| Squid syntax | Conversion |
| --- | --- |
| One `http_port IP:PORT`, `[IPv6]:PORT`, or `PORT` | Plain forward HTTP proxy; no modes/options. |
| `acl NAME src IP CIDR ...` | Real IPv4/IPv6 membership; prefix-length CIDRs and exact addresses. |
| `acl NAME method GET HEAD ...` | Literal uppercase method tokens. |
| `acl NAME port 80 443 8000-8010 ...` | Inclusive destination port tests; supported ports 1–65535. |
| `acl NAME dstdomain -n example.com .example.org ...` | Case-insensitive DNS-name matching without lookup; leading dot includes the apex and subdomains. Names without a leading dot match exactly. ASCII DNS names only, with a nonnumeric final label. |
| `http_access allow|deny [!]NAME ...` | Ordered first match; references on one line are ANDed, values in one ACL are ORed. Repeating the same name/type appends values. |
| `all` | The built-in always-matching ACL; cannot be redefined. |

Every reference must already be declared. With any access rules, the last must be exactly `http_access deny all`; the converter rejects implicit fallback behavior rather than changing it. With no access rules, generated policy denies everything. Squid's own documentation explains that unmatched requests otherwise invert the last rule's action. [Squid http_access reference](https://www.squid-cache.org/Doc/config/http_access/)

The supported ACL syntax follows the source/client address, destination port and method definitions. Domain ACLs require `-n` because ordinary `dstdomain` can perform reverse DNS on IP targets, which this converter does not emulate. [Squid ACL reference](https://www.squid-cache.org/Doc/config/acl/)

First-match ordering, AND across references, OR across values and accumulation of repeated ACL definitions follow Squid's documented rules. [Squid access-control guide](https://wiki.squid-cache.org/SquidFaq/SquidAcl)

## Listener and authentication behavior

The listener must be explicitly present. Loopback listeners are accepted directly. A bare port, wildcard address or non-loopback IP requires `-allow-non-loopback`; this explicitly preserves the supplied binding rather than silently changing network reachability. Squid supports additional listener forms and modes that are outside this subset. [Squid http_port reference](https://www.squid-cache.org/Doc/config/http_port/)

Generated configuration enables unauthenticated HTTP access **subject to the migrated ACL policy**, with default block. This preserves source-network ACL deployments; it does not create user authentication. Non-loopback deployments must review their ACLs and network exposure. Admin API, SOCKS, gRPC, mirror, media, FTP/SSH and QUIC listeners are disabled. Reverse proxy and statistics reporting are disabled. No TLS interception, caching, identity provider, or auxiliary service is enabled by migration.

The emitted `connect_mode: tunnel` explicitly preserves plain Squid CONNECT behavior instead of the platform's legacy interception default. The CONNECT request is checked against the migrated policy before establishing the tunnel. Encrypted traffic inside an allowed tunnel is opaque: HTTP paths, request methods, content and other application-layer information inside it are not inspected. Source, target authority and CONNECT destination-port restrictions still apply to tunnel establishment. SSL bump migration is unsupported.

## Rejected input

Everything outside the table is an error, including unused unsupported ACL definitions. Examples: `dst` DNS resolution, `srcdomain`, regex ACLs, external/proxy-auth helpers, `include`, quoted file ACLs, continuations/escapes, address ranges and dotted netmasks, IPv4-mapped network prefixes, multiple listeners, listener hostnames, interception/transparent proxy modes, SSL bump, `cache_peer`, `cache_dir`, adaptation, logging directives and delay pools. Built-ins other than `all` must be defined using supported ACL types. Do not simply delete rejected security directives; port their behavior manually and review the resulting configuration.

Limits: 4 MiB source, lines under 64 KiB, 256 access rules, 64 ACL references per rule and 256 values per named ACL. Generated expressions remain subject to the runtime CEL cost limit and fail closed on evaluation errors.

## Verification

```sh
go test -race ./cmd/squid2ads ./internal/policy
```

Tests execute emitted policies through the production CEL engine for IPv4/IPv6 ranges, duplicate ACL definitions, exact/suffix domains, port boundaries, negation, AND/OR, method checks, CONNECT restrictions, first-match allow and final deny. They also verify rejected input leaves no outputs, existing files remain intact, auxiliary listeners stay disabled and repeated generation is deterministic. This validates the documented subset; it is not differential testing against a running Squid instance.
