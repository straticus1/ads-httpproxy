# ads-httpproxy Policy Script (Starlark)
# --------------------------------------
# This script is executed once on load.
# The 'on_request(req)' function is called for every request.
#
# Request Object 'req' fields:
# - req.method: "GET", "POST", etc.
# - req.url: Full URL string
# - req.host: Host header
# - req.remote: Remote IP:Port
#
# Return:
# - True: Block request
# - False: Allow request (default)

def on_request(req):
    # 1. Block by URL Keyword
    if "/admin" in req.url or "/private" in req.url:
        print("[Policy] Blocking sensitive path: " + req.url)
        return True

    # 2. Block by Method
    if req.method == "DELETE":
        print("[Policy] DELETE method not allowed from: " + req.remote)
        return True

    # 3. Host Allowlist (Walled Garden)
    allowed_hosts = ["example.com", "google.com", "my-api.internal"]
    # Logic: if we implemented strict checking
    # if req.host not in allowed_hosts:
    #     print("[Policy] Host not allowed: " + req.host)
    #     return True

    # 4. Complex Logic
    # Starlark supports functions, loops, etc.
    
    return False
