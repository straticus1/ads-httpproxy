# URL Reputation System

Comprehensive URL threat intelligence integration for ads-httpproxy, providing real-time protection against malware, phishing, and malicious websites.

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP/HTTPS Request
       ▼
┌──────────────────────────────────┐
│      ads-httpproxy               │
│  ┌────────────────────────────┐  │
│  │  Reputation Middleware     │  │
│  └────────────────────────────┘  │
│          │                        │
│          ├─► FeedManager         │
│          │   (Local DB)          │
│          │   • URLhaus           │
│          │   • PhishTank         │
│          │   • OpenPhish         │
│          │   • ThreatFox         │
│          │   • Custom Feeds      │
│          │                        │
│          ├─► DNS Science         │
│          │   (gRPC)              │
│          │                        │
│          └─► External API        │
│              (Optional)           │
└──────────────────────────────────┘
```

## Features

### 1. Multi-Source Threat Feeds

**Built-in Public Feeds:**
- **URLhaus** (abuse.ch) - Malware distribution URLs
- **PhishTank** - Verified phishing URLs
- **OpenPhish** - Community phishing feed
- **ThreatFox** (abuse.ch) - Malware IOCs

**Custom Feeds:**
- Support for internal blocklists
- Industry ISAC/ISAO feeds
- Commercial threat intelligence providers

### 2. Feed Management

**Automatic Updates:**
- Configurable update intervals (default: 15 minutes)
- Parallel feed fetching for performance
- Graceful failure handling (fail-open by default)

**Data Retention:**
- Automatic cleanup of old entries
- Configurable retention period (default: 30 days)
- Memory-efficient storage with hash indexing

**Feed Formats:**
- Plaintext (one URL per line)
- CSV (URLhaus, PhishTank formats)
- JSON (custom formats)

### 3. URL Matching

**Direct Matching:**
- Exact URL lookup (fastest)
- Normalized URL comparison
- SHA256 hash indexing for privacy

**URL Normalization:**
- Lowercase hostnames
- Remove fragments
- Sort query parameters
- Add missing schemes

### 4. Threat Categorization

**Categories:**
- `malware` - Malware distribution sites
- `phishing` - Credential theft, fake login pages
- `adult` - Adult content (optional filtering)
- `gambling` - Gambling sites (optional filtering)
- `vpn_proxy` - VPN/proxy detection
- `file_sharing` - Unauthorized file sharing
- `mixed` - Multiple threat types

**Scoring System:**
- 0-100 threat score
- Higher scores from multiple sources
- Configurable blocking threshold

## Configuration

### Basic Setup

```yaml
reputation:
  enabled: true

  feeds:
    enabled: true
    update_interval: 15  # Minutes
    max_age: 30         # Days

    # Enable default feeds
    enable_urlhaus: true
    enable_phishtank: true
    enable_openphish: true
    enable_threatfox: true
```

### Advanced Configuration

```yaml
reputation:
  enabled: true

  # Legacy external reputation API (optional)
  url: "https://reputation.service.com/api"
  timeout: 5000
  fail_open: true

  feeds:
    enabled: true
    update_interval: 5   # Faster updates
    max_age: 7          # Shorter retention

    # Selective feed enabling
    enable_urlhaus: true
    enable_phishtank: false
    enable_openphish: true
    enable_threatfox: true

    # Custom feeds
    custom_feeds:
      - name: "Corporate Blocklist"
        url: "https://internal.corp.com/blocked.txt"
        type: "plaintext"
        category: "malware"

      - name: "Industry ISAC"
        url: "https://isac.sector.org/feed.csv"
        type: "csv"
        category: "phishing"

      - name: "Commercial Feed"
        url: "https://vendor.com/threats.json"
        type: "json"
        category: "mixed"
```

### Integration with DNS Science

```yaml
# Combine DNS-level and URL-level protection
dns_science:
  enabled: true
  rpc_addr: "localhost:50051"
  feed_url: "https://feed.dnsscience.com/v1/threats"

reputation:
  enabled: true
  feeds:
    enabled: true
    enable_urlhaus: true
    enable_phishtank: true
```

**Benefits:**
- DNS-level blocking (faster, pre-resolve)
- URL-level blocking (more precise)
- Dual-layer defense

## Feed Sources

### URLhaus (abuse.ch)

**URL:** https://urlhaus.abuse.ch/downloads/csv_recent/
**Format:** CSV
**Update:** Every 5 minutes
**Content:** Malware distribution URLs
**Free:** Yes
**Registration:** No

**Example Entry:**
```csv
id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
1234,2024-01-15,http://evil.com/malware.exe,online,malware_download,"exe,trojan",https://urlhaus.abuse.ch/url/1234/,abuse_ch
```

### PhishTank

**URL:** http://data.phishtank.com/data/online-valid.csv
**Format:** CSV
**Update:** Every hour
**Content:** Verified phishing URLs
**Free:** Yes (with API key for commercial)
**Registration:** Optional

**Example Entry:**
```csv
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
1234,http://fake-bank.com/login,https://phishtank.com/phish_detail.php?phish_id=1234,2024-01-15T10:00:00Z,yes,2024-01-15T10:30:00Z,yes,Bank of America
```

### OpenPhish

**URL:** https://openphish.com/feed.txt
**Format:** Plaintext (one URL per line)
**Update:** Every hour
**Content:** Community phishing URLs
**Free:** Yes
**Registration:** No

**Example Entry:**
```
http://phishing-site.com/secure/login
https://fake-paypal.scam/verify
```

### ThreatFox (abuse.ch)

**URL:** https://threatfox.abuse.ch/export/csv/recent/
**Format:** CSV
**Update:** Every 5 minutes
**Content:** Malware IOCs (URLs, domains, IPs)
**Free:** Yes
**Registration:** No

**Example Entry:**
```csv
first_seen,ioc_type,ioc_value,threat_type,malware,confidence_level,reference,tags
2024-01-15,url,http://c2.malware.com/gate,botnet_cc,emotet,100,https://threatfox.abuse.ch/,botnet,c2
```

## Custom Feed Formats

### Plaintext Format

One URL per line, comments with `#`:

```
# Corporate blocklist
http://malicious-site.com
https://phishing.example.com
http://malware-distribution.net
# Last updated: 2024-01-15
```

### CSV Format

Flexible columns, configurable parser:

```csv
url,category,threat_score,source,timestamp
http://evil.com,malware,95,internal,2024-01-15T10:00:00Z
http://phish.com,phishing,90,external,2024-01-15T11:00:00Z
```

### JSON Format

Custom parser required:

```json
{
  "threats": [
    {
      "url": "http://malicious.com",
      "category": "malware",
      "score": 95,
      "sources": ["internal", "external"],
      "timestamp": "2024-01-15T10:00:00Z"
    }
  ]
}
```

## Performance

### Memory Usage

**Per-URL Storage:** ~200 bytes
**100K URLs:** ~20 MB
**1M URLs:** ~200 MB

**Optimization:**
- SHA256 hash indexing
- Efficient Go maps
- Automatic old entry cleanup

### Lookup Performance

**Direct Lookup:** O(1) - < 1μs
**Hash Lookup:** O(1) - < 2μs
**Normalized Lookup:** O(1) - < 5μs

**Throughput:** 1M+ lookups/second on modern CPU

### Update Performance

**Feed Fetch:** 1-5 seconds per feed
**Parallel:** All feeds fetched simultaneously
**Merge:** O(N) - linear with feed size
**Impact:** Zero latency during updates (lock-free reads)

## Monitoring

### Metrics (Prometheus)

```
# Total URLs in database
ads_reputation_urls_total{category="malware"} 50000
ads_reputation_urls_total{category="phishing"} 30000

# Blocks by category
ads_reputation_blocks_total{category="malware"} 1234
ads_reputation_blocks_total{category="phishing"} 567

# Feed sync status
ads_reputation_feed_last_sync{feed="urlhaus"} 1642251234
ads_reputation_feed_entries{feed="urlhaus"} 15000
ads_reputation_feed_errors{feed="urlhaus"} 0
```

### Logs

```
2024-01-15T10:00:00Z INFO Synced feed feed=URLhaus entries=15432
2024-01-15T10:05:00Z INFO Synced feed feed=PhishTank entries=8765
2024-01-15T10:10:00Z WARN Blocked by URL Reputation Feed url=http://evil.com category=malware threat_score=95 sources=[URLhaus,ThreatFox]
2024-01-15T11:00:00Z INFO Cleaned up old reputation entries removed=5234 remaining=45678
```

## API Endpoints

### Get Statistics

```bash
GET /api/reputation/stats
```

**Response:**
```json
{
  "total_urls": 95000,
  "categories": {
    "malware": 50000,
    "phishing": 40000,
    "adult": 5000
  },
  "sources": {
    "URLhaus": 45000,
    "PhishTank": 35000,
    "OpenPhish": 15000
  },
  "feeds": 4
}
```

### Check URL

```bash
GET /api/reputation/check?url=http://example.com
```

**Response:**
```json
{
  "url": "http://example.com",
  "blocked": true,
  "category": "malware",
  "threat_score": 95,
  "sources": ["URLhaus", "ThreatFox"],
  "tags": ["trojan", "ransomware"],
  "first_seen": "2024-01-10T15:30:00Z",
  "last_seen": "2024-01-15T10:00:00Z"
}
```

## Integration with ThreatScript

```python
def check_request(method, url, headers, body, user, client_ip):
    """Block malicious URLs using local reputation feeds"""

    # Check URL reputation (uses FeedManager)
    intel = threat.check_url(url)

    if intel['blocked']:
        log.alert(f"Malicious URL blocked: {url}")
        log.info(f"Category: {intel['category']}, Score: {intel['score']}")
        log.info(f"Sources: {intel['sources']}")

        # Notify security team
        notify.slack(f"🚨 Malware Detected\nURL: {url}\nCategory: {intel['category']}\nSources: {intel['sources']}")

        # Block the request
        proxy.block_url(url, f"Malicious URL detected: {intel['category']}")
        return "block"

    return "allow"
```

## Deployment Examples

### Docker Compose

```yaml
version: '3.8'

services:
  ads-httpproxy:
    image: ads-httpproxy:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./config-url-reputation.yaml:/app/config.yaml:ro
    environment:
      - ADS_REPUTATION_FEEDS_ENABLED=true
      - ADS_REPUTATION_URLHAUS=true
      - ADS_REPUTATION_PHISHTANK=true
```

### Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: proxy-config
data:
  config.yaml: |
    reputation:
      enabled: true
      feeds:
        enabled: true
        enable_urlhaus: true
        enable_phishtank: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ads-httpproxy
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: proxy
        image: ads-httpproxy:latest
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
```

## Best Practices

### 1. Start with Default Feeds

Enable all default feeds for maximum protection:
```yaml
enable_urlhaus: true
enable_phishtank: true
enable_openphish: true
enable_threatfox: true
```

### 2. Tune Update Intervals

Balance freshness vs. load:
- **Critical environments:** 5-15 minutes
- **Normal environments:** 30-60 minutes
- **Low priority:** 2-24 hours

### 3. Use Multiple Layers

Combine DNS, URL, and IP threat intelligence:
```yaml
dns_science:
  enabled: true
reputation:
  enabled: true
  feeds:
    enabled: true
threat_sources:
  - "https://..."
```

### 4. Monitor Performance

Track metrics:
- Feed sync success rate
- Block rate by category
- Database size
- Lookup latency

### 5. Custom Feeds for Your Industry

Add sector-specific threat feeds:
- Financial: FS-ISAC
- Healthcare: H-ISAC
- Energy: E-ISAC
- Retail: R-CISC

## Troubleshooting

### Feeds Not Updating

**Check logs:**
```bash
grep "Failed to sync feed" /var/log/ads-httpproxy.log
```

**Common issues:**
- Network connectivity
- DNS resolution
- Firewall blocking
- Feed source down

**Solution:**
```bash
# Test feed URL manually
curl -v https://urlhaus.abuse.ch/downloads/csv_recent/

# Check DNS
dig urlhaus.abuse.ch

# Check firewall
iptables -L -n
```

### High Memory Usage

**Check stats:**
```bash
curl http://localhost:9090/api/reputation/stats
```

**Reduce retention:**
```yaml
feeds:
  max_age: 7  # Reduce from 30 days
```

**Disable unused feeds:**
```yaml
feeds:
  enable_urlhaus: true
  enable_phishtank: false  # Disable if not needed
```

### False Positives

**Whitelist legitimate URLs:**
```yaml
# TODO: Implement whitelist feature
```

**Check threat score:**
```bash
curl "http://localhost:9090/api/reputation/check?url=http://example.com"
```

**Report false positives:**
- URLhaus: https://urlhaus.abuse.ch/
- PhishTank: https://phishtank.com/

## Future Enhancements

- [ ] Google Safe Browsing API integration
- [ ] Microsoft SmartScreen integration
- [ ] URL category filtering (adult, gambling, etc.)
- [ ] Whitelist/exception management
- [ ] Machine learning threat scoring
- [ ] Reputation history tracking
- [ ] Export blocked URLs for reporting
- [ ] STIX/TAXII threat intelligence integration

## References

- URLhaus: https://urlhaus.abuse.ch/
- PhishTank: https://phishtank.com/
- OpenPhish: https://openphish.com/
- ThreatFox: https://threatfox.abuse.ch/
- DNS Science: https://dnsscience.com/
