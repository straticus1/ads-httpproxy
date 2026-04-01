# dlp_blocker.star
# ThreatScript example: Block HTTP requests containing sensitive data

def on_request(req):
    """Scan HTTP requests for PII/secrets and block if found"""

    url = req["url"]
    body = req.get("body", "")
    user = req.get("user", "anonymous")

    log.info(f"Processing request: {url} from {user}")

    # Skip if no body
    if not body:
        return {"action": "allow"}

    # DLP scan
    scan = dlp.scan_text(body)

    # Check for secrets (highest priority)
    if scan["has_secrets"]:
        secret_types = scan["secrets_types"]
        log.alert(f"Secrets detected in request: {secret_types}")

        # Block immediately
        proxy.block_url(url)

        # Alert security team
        notify.slack(f"🚨 Secret leak prevented!\nUser: {user}\nURL: {url}\nTypes: {secret_types}")

        return {
            "action": "block",
            "reason": "Secrets detected in request body",
            "http_status": 403
        }

    # Check for PII
    if scan["has_pii"]:
        pii_types = scan["pii_types"]
        risk_score = scan["risk_score"]

        log.warn(f"PII detected: {pii_types} (risk={risk_score})")

        # Only block if high risk
        if risk_score > 50:
            notify.slack(f"⚠️ High-risk PII blocked\nUser: {user}\nURL: {url}\nTypes: {pii_types}")

            return {
                "action": "block",
                "reason": f"High-risk PII detected: {pii_types}",
                "http_status": 403
            }

        # Log but allow low-risk PII
        log.info(f"Low-risk PII allowed (score={risk_score})")

    # Check for financial data
    if scan["has_financial"]:
        log.alert(f"Financial data detected in request from {user}")

        # Always block credit cards in requests
        notify.slack(f"💳 Credit card data blocked\nUser: {user}\nURL: {url}")

        return {
            "action": "block",
            "reason": "Credit card data detected",
            "http_status": 403
        }

    # Allow if clean
    return {"action": "allow"}
