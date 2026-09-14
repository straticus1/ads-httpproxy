# Scripting cookbook

Set `script_file` to a `.star` (Starlark) or `.tengo` (Tengo) policy. Hooks execute
at the outbound transport for forward proxy and gateway traffic, after the
initial proxy middleware checks. A hook error blocks the operation. Script
reload errors preserve the previous valid program.

## Starlark: domain filtering and header overrides

```python
def on_request(req):
    if req.host == "blocked.example":
        return {"action": "block"}
    req.headers["X-Development-Proxy"] = "ADS"
    return {"action": "allow"}

def on_response(resp):
    resp.headers["X-Inspected"] = "yes"
    if resp.status_code >= 500:
        print("Upstream failure:", resp.status_code)
    return False
```

Request fields are `method`, `url`, `host`, `remote`, and mutable `headers`.
Response fields are `status_code` and mutable `headers`. Header values are
strings; invalid names or CR/LF values are rejected. Return `False`, `None`, or
`{"action":"allow"}` to allow; `True` or `{"action":"block"}` to block.
`on_request` is required; `on_response` is optional. Hooks honor request context
cancellation and have a 100,000-step execution limit. Globals are frozen to
support concurrent execution. The engine checks for file changes every five
seconds. Printing uses debug-level proxy logging.

## Tengo: request and response policy

```go
block := false
if phase == "request" {
    block = req.host == "blocked.example"
}
if phase == "response" {
    block = resp.status_code >= 500
}
```

Tengo executes a fresh clone for each hook. `phase` is `request` or `response`;
`req` provides `method`, `url`, `host`, and `remote`. `resp.status_code` is the
upstream status (zero during request processing). Assign `block = true` to block.
The Tengo standard library is available through `import`. Header modification
is supported by the Starlark hook or a plugin; Tengo policy output currently
supports the `block` decision. File watching reloads Tengo policies automatically.

For response mocking, latency injection, and connection failure simulation,
use [developer toolkit rules](developer-toolkit.md) rather than a script.
