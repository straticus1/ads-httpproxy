# Plugin development

External plugins import `ads-httpproxy/pkg/plugin`. Existing imports of
`internal/plugin` remain compatible through type aliases.

```go
package main

import (
    "net/http"
    "ads-httpproxy/pkg/plugin"
)

type Headers struct{}
func (*Headers) Name() string { return "developer-headers" }
func (*Headers) APIVersion() string { return plugin.APIVersion }
func (*Headers) Version() string { return "1.0.0" }
func (*Headers) OnRequest(r *http.Request, _ *plugin.Context) (*http.Request, *http.Response) {
    r.Header.Set("X-Developer-Proxy", "ADS")
    return r, nil
}
func (*Headers) OnResponse(r *http.Response, _ *plugin.Context) *http.Response { return r }
func NewPlugin() plugin.Plugin { return &Headers{} }
```

Build with `go build -buildmode=plugin -o headers.so ./path/to/plugin` using the
same Go toolchain, dependency versions, and build flags as the proxy. Go shared
plugins are supported on Linux, FreeBSD, and macOS, not Windows.

```yaml
plugins:
  enabled: true
  auto_load: true
  plugin_dir: ./plugins
  plugin_list: []
  configurations:
    example-auth:
      users:
        developer: local-password
```

Directory loading visits regular `.so` files in filename order and reports load
failures rather than silently succeeding. Plugin names must be nonempty and
unique. A plugin that implements `plugin.Versioned` must use API version `1`;
plugins without version metadata remain compatible. Implement
`Configure(json.RawMessage) error` to receive name-keyed configuration before
registration. JSON and YAML configuration files support the same settings.
Configuration is isolated from the loader and rejected if the plugin does not
support it or returns an error.

Hooks run in registration order. A nil modified request/response retains the
previous value. A nonnil response from `OnRequest` intercepts the request and
stops later request hooks. Hooks can run concurrently; protect plugin-owned
mutable state. Hook execution uses a manager snapshot, allowing registration or
removal from within hooks without deadlocking.

## Loading and hot replacement

```sh
bin/ads-admin plugins
bin/ads-admin load -path /opt/plugins/headers.so
bin/ads-admin reload-plugin -path /opt/plugins/headers-v2.so
bin/ads-admin unload -name developer-headers
```

Hot replacement preserves registration order and installs the new instance only
after construction, API validation, and configuration succeed. The replacement
must have an already registered name. In-flight hooks finish using their old
snapshot. Reloading the same shared library creates a new instance of its cached
code; for new code, build from a distinct plugin package path, for example
`./plugins/headers/v2`, and use a new `.so` filename while retaining `Name()`.
Go does not unload libraries from memory; unloading removes the plugin's hooks.
There is no automatic file watching for shared-library changes.

Examples in `internal/plugin/examples` include logging, Basic authentication,
URL filtering, header injection, rate limiting, and content-type filtering.
The example authentication hook supplements the proxy's primary authentication;
it does not replace its initial access policy. Plugins execute with proxy process
privileges and should be built from trusted source.

Verify shared library behavior with `sh tests/plugin-integration.sh` from the
repository root. It builds separate plugin packages and checks configuration,
hot replacement, duplicate names, and incompatible API rejection.
