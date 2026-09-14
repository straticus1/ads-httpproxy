# Admin CLI

Build with `go build -o bin/ads-admin ./cmd/ads-admin`.

```sh
export ADS_API_SECRET='your-api-key'
bin/ads-admin status -api http://localhost:9090
bin/ads-admin stats -format table
bin/ads-admin connections -format yaml
bin/ads-admin config
bin/ads-admin plugins
bin/ads-admin load -path /opt/ads-httpproxy/plugins/logger.so
bin/ads-admin reload-plugin -path /opt/ads-httpproxy/plugins/logger-v2.so
bin/ads-admin unload -name logger
bin/ads-admin metrics
bin/ads-admin validate -config examples/developer.yaml
```

`status` checks `/healthz`. `stats` returns JSON statistics; `metrics` returns
raw Prometheus text. `config` reads the server's redacted configuration.
Live configuration replacement and reload are disabled by the server: validate
an updated proxy configuration and restart the service to apply it.

Use `-secret` (or `ADS_API_SECRET`) for the server's `X-API-Key` authentication.
Use `-user` and `-password` for management API Basic authentication. The default
request timeout is 30 seconds; override it with `-timeout 10s`.

## Configuration defaults

Pass `-cli-config admin.yaml` to any command. JSON is also accepted.
Explicit command flags override file defaults.

```yaml
api: https://proxy.example.com:9090
secret: your-api-key
format: table
# Alternative authentication:
# user: admin
# password: your-password
```

## Batch operations

A batch file is a JSON array of argument arrays. Commands execute sequentially
and stop at the first failure. Completed operations are not rolled back.

```json
[
  ["status"],
  ["stats", "-format", "yaml"],
  ["load", "-path", "/opt/plugins/logger.so"]
]
```

```sh
bin/ads-admin batch -cli-config admin.yaml -file commands.json
```

Batch commands inherit the enclosing command's API, credentials, format, and
timeout. Each command can override these with its own flags.

## Interactive mode

```sh
bin/ads-admin interactive -cli-config admin.yaml
```

Enter commands such as `stats -format table`; use `exit` or `quit` to leave.
Whitespace separates arguments. For paths or values containing spaces, enter
a JSON argument array, for example `["load", "-path", "/opt/my plugins/logger.so"]`.
Nested interactive and batch sessions are rejected.

## Shell completion

```sh
bin/ads-admin completion -shell bash > ads-admin.bash
source ads-admin.bash
bin/ads-admin completion -shell zsh > _ads-admin
```

For Zsh, place `_ads-admin` in a directory in `$fpath` before calling `compinit`.
Completion suggests command names.
