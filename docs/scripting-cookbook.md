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

Request fields are `method`, `url`, `host`, `remote`, mutable `headers`, and
mutable `header_values`. Response fields are `status_code`, `headers`, and
`header_values`. The compatible `headers` dictionary exposes the first value
as a string; assigning a new string replaces all values for that field.
`header_values` exposes lists of strings, preserving separate lines such as
`Set-Cookie`. Untouched fields retain all original values. For example:

```python
def on_request(req):
    req.headers.pop("Authorization", None)  # Strip credentials when required.
    req.header_values["X-Labels"] = ["inspected", "allowed"]

def on_response(resp):
    resp.header_values.setdefault("Set-Cookie", []).append("seen=1; Secure; HttpOnly")
    resp.headers.pop("X-Powered-By", None)
```

Use `.pop()` in either view to remove a field; setting an empty list in
`header_values` also removes it. Views are independent snapshots: modifying
the same field through both views in one callback is an error, even if the
new values agree. Dictionary keys are case-sensitive; duplicate keys differing
only by case are rejected. Use the existing canonical field spelling when
editing a field. Invalid field names, control characters (including CR/LF),
and changes to reserved forwarding, identity, framing, or hop-by-hop fields
are rejected atomically. Scripts cannot inject credentials; removal of origin
`Authorization` and `Cookie` is allowed. Unchanged protected fields remain intact.

Return `False`, `None`, or
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
