# combined_security.star
# ThreatScript example: Combined threat + DLP checking

def on_request(req):
    """Comprehensive security check: threat intel + DLP"""

    url = req["url"]
    body = req.get("body", "")
    user = req.get("user", "anonymous")
    client_ip = req.get("client_ip", "unknown")

    log.info(f"Security check: {url} from {user}")

    # Phase 1: Threat Intelligence
    intel = threat.check_url(url)

    if intel["blocked"] or intel["score"] > 80:
        log.alert(f"Threat blocked: {url} (score={intel['score']})")

        notify.slack(f"🚨 Threat: {url}\nUser: {user}\nScore: {intel['score']}\nCategory: {intel['category']}")

        return {
            "action": "block",
            "reason": f"Threat detected: {intel['category']}",
            "http_status": 403
        }

    # Phase 2: DLP Scan (if body present)
    if body:
        scan = dlp.scan_text(body)

        # Block secrets immediately
        if scan["has_secrets"]:
            log.critical(f"Secrets in request body: {url}")

            # Redact secrets before logging
            safe_body = dlp.redact(body)
            log.debug(f"Redacted body preview: {safe_body[:100]}")

            notify.slack(f"🔐 Secret leak prevented!\nUser: {user}\nURL: {url}\nTypes: {scan['secrets_types']}")

            return {
                "action": "block",
                "reason": "Secrets detected in request",
                "http_status": 403
            }

        # Block high-risk PII/financial
        if scan["risk_score"] > 50:
            log.alert(f"High-risk data blocked: {url} (score={scan['risk_score']})")

            return {
                "action": "block",
                "reason": f"High-risk data (score={scan['risk_score']})",
                "http_status": 403
            }

        # Warn for low-risk findings
        if scan["has_pii"] or scan["has_financial"]:
            log.warn(f"Low-risk sensitive data in request: {url}")

    # Phase 3: Additional checks
    # Could add: rate limiting, user reputation, time-based policies, etc.

    # Allow if all checks pass
    log.debug(f"Request allowed: {url}")
    return {"action": "allow"}
