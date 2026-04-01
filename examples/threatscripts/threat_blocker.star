# threat_blocker.star
# ThreatScript example: Block malicious URLs using threat intelligence

def on_request(req):
    """Check URL against threat intelligence and block if malicious"""

    url = req["url"]
    client_ip = req.get("client_ip", "unknown")
    user = req.get("user", "anonymous")

    log.info(f"Threat check: {url} from {user} ({client_ip})")

    # Check threat intelligence
    intel = threat.check_url(url)

    blocked = intel["blocked"]
    score = intel["score"]
    category = intel["category"]

    # Log threat score
    if score > 0:
        log.info(f"Threat score for {url}: {score} (category: {category})")

    # Block if malicious
    if blocked or score > 80:
        log.alert(f"Malicious URL blocked: {url} (score={score}, category={category})")

        # Alert security team
        notify.slack(f"🚨 Malicious URL blocked!\nURL: {url}\nUser: {user}\nScore: {score}\nCategory: {category}")

        # Additional notification for critical threats
        if score > 95:
            notify.webhook("https://soc.company.com/alert", {
                "severity": "critical",
                "url": url,
                "user": user,
                "client_ip": client_ip,
                "threat_score": score,
                "category": category,
                "timestamp": runtime.now()
            })

        return {
            "action": "block",
            "reason": f"Malicious URL detected: {category}",
            "http_status": 403
        }

    # Warn for suspicious URLs
    if score > 50:
        log.warn(f"Suspicious URL allowed with warning: {url} (score={score})")

    # Allow benign URLs
    return {"action": "allow"}
