# PAC (Proxy Auto-Configuration) Per-User Policies

Enterprise-grade PAC file generation with per-user, per-tenant, and per-department content filtering policies.

## Overview

The proxy automatically generates customized PAC files for each user/tenant based on their assigned policy. This enables:

- **Per-user content filtering** - Different blocking rules per employee
- **Department-level policies** - IT, Finance, HR have different access
- **Tenant isolation** - Multi-tenant deployments with separate policies
- **Time-based restrictions** - Block during work hours
- **Compliance enforcement** - Government, financial, healthcare requirements

## Architecture

```
User Browser
     │
     ├─► GET /proxy.pac?user=john.doe
     │
     ▼
PAC Handler
     │
     ├─► Look up user policy (john.doe)
     ├─► Look up tenant policy (acme-corp)
     ├─► Merge policies
     ├─► Generate custom PAC file
     │
     ▼
Custom PAC File
     │
     └─► Browser applies rules:
         - Block adult content
         - Allow business sites
         - Route through proxy for scanning
```

## Preset Policies

### Government Agency
**Use Case:** Federal/state agencies, defense contractors
**Compliance:** FISMA, FedRAMP

```go
BlockAdult:     true
BlockGambling:  true
BlockSocial:    true  // Security risk
BlockStreaming: true  // Bandwidth
BlockPiracy:    true
BlockCrypto:    true  // Prevent mining
BlockAds:       true
BlockWorkHours: true  // 8 AM - 5 PM
RequireAuth:    true
```

**Blocks:**
- Adult content (all categories)
- Social media (Facebook, Twitter, Instagram, TikTok)
- Video streaming (YouTube, Netflix, Hulu)
- Gambling sites
- Piracy/torrents
- Cryptomining
- Ad/tracking networks

### Financial Institution
**Use Case:** Banks, credit unions, investment firms
**Compliance:** GLBA, SOX, PCI-DSS

```go
BlockAdult:     true
BlockGambling:  true
BlockSocial:    true  // Prevent data leaks
BlockStreaming: true
BlockPiracy:    true
BlockCrypto:    true
BlockAds:       true
BlockWorkHours: true  // 8 AM - 6 PM
RequireAuth:    true
```

**Special Features:**
- Blocks social media to prevent insider trading leaks
- Blocks all entertainment for productivity
- Requires authentication for audit trail

### Healthcare (HIPAA)
**Use Case:** Hospitals, clinics, insurance
**Compliance:** HIPAA, HITECH

```go
BlockAdult:     true
BlockGambling:  true
BlockSocial:    false // Patient engagement allowed
BlockStreaming: true
BlockPiracy:    true
BlockCrypto:    true
BlockAds:       true
BlockWorkHours: true  // 7 AM - 7 PM (shifts)
RequireAuth:    true
```

**Special Features:**
- Allows controlled social media (patient outreach)
- Extended work hours for 24/7 operations
- All traffic logged for HIPAA audit

### Education (CIPA)
**Use Case:** K-12 schools, libraries
**Compliance:** CIPA (Children's Internet Protection Act)

```go
BlockAdult:     true  // REQUIRED by CIPA
BlockGambling:  true  // REQUIRED by CIPA
BlockSocial:    false // Educational use
BlockStreaming: false // Educational videos
BlockPiracy:    true
BlockCrypto:    true
BlockAds:       true
BlockWorkHours: false // 24/7 for online learning
RequireAuth:    false // Student access
```

**Special Features:**
- CIPA-compliant adult content filtering
- Allows YouTube for educational content
- No authentication burden for students

### Corporate
**Use Case:** General business, startups
**Compliance:** General corporate policy

```go
BlockAdult:     true
BlockGambling:  true
BlockSocial:    false // Business use OK
BlockStreaming: true  // Productivity
BlockPiracy:    true
BlockCrypto:    true
BlockAds:       false // Ads OK
BlockWorkHours: true  // 9 AM - 5 PM
RequireAuth:    true
```

## API Usage

### Get PAC File for User

```bash
# User-specific PAC file
curl http://proxy:9090/proxy.pac?user=john.doe

# Tenant-specific PAC file
curl http://proxy:9090/proxy.pac?tenant=acme-corp

# User with authentication
curl -u john.doe:password http://proxy:9090/proxy.pac
```

### Set User Policy

```bash
curl -X POST http://proxy:9090/api/pac/policy \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "john.doe",
    "policy": {
      "department": "Finance",
      "proxy_addr": "proxy.company.com",
      "proxy_port": 8080,
      "block_adult": true,
      "block_gambling": true,
      "block_social": true,
      "block_streaming": true,
      "block_piracy": true,
      "block_crypto": true,
      "block_ads": true,
      "block_work_hours": true,
      "work_hours_start": 9,
      "work_hours_end": 17,
      "require_auth": true,
      "allowed_domains": [
        "linkedin.com",
        "youtube.com"
      ],
      "blocked_domains": [
        "reddit.com"
      ]
    }
  }'
```

### Get Policy

```bash
# Get user policy
curl http://proxy:9090/api/pac/policy?user=john.doe

# Get tenant policy
curl http://proxy:9090/api/pac/policy?tenant=acme-corp

# List all policies
curl http://proxy:9090/api/pac/policy
```

### Delete Policy

```bash
# Delete user policy (falls back to tenant/default)
curl -X DELETE http://proxy:9090/api/pac/policy?user=john.doe

# Delete tenant policy
curl -X DELETE http://proxy:9090/api/pac/policy?tenant=acme-corp
```

## Configuration Examples

### Example 1: Government Agency

```yaml
# config.yaml
pac:
  enabled: true
  default_policy: "government"
  policies:
    - tenant: "agency-defense"
      preset: "government"
      proxy_addr: "proxy.defense.gov"
      proxy_port: 8080
      
      # Override for specific users
      user_overrides:
        - user_id: "admin@agency.gov"
          allowed_domains:
            - "github.com"  # Dev work
            - "stackoverflow.com"
```

### Example 2: Multi-Tenant Financial

```yaml
pac:
  enabled: true
  
  # Tenant A: Investment bank
  policies:
    - tenant: "bank-a"
      preset: "financial"
      proxy_addr: "proxy.banka.com"
      block_social: true
      block_streaming: true
      
      departments:
        - name: "Trading"
          block_social: true  # No social media
          block_streaming: true
          work_hours_start: 7
          work_hours_end: 18
          
        - name: "IT"
          block_social: false  # DevOps needs GitHub
          allowed_domains:
            - "github.com"
            - "stackoverflow.com"
            - "reddit.com"  # r/sysadmin
  
  # Tenant B: Credit union
  policies:
    - tenant: "bank-b"
      preset: "financial"
      proxy_addr: "proxy.bankb.com"
      block_social: false  # Customer engagement
      allowed_domains:
        - "facebook.com"
        - "twitter.com"
```

### Example 3: Healthcare with Shifts

```yaml
pac:
  enabled: true
  default_policy: "healthcare"
  
  policies:
    - tenant: "hospital"
      preset: "healthcare"
      proxy_addr: "proxy.hospital.org"
      
      departments:
        - name: "Emergency"
          block_work_hours: false  # 24/7
          work_hours_start: 0
          work_hours_end: 24
          
        - name: "Administration"
          block_work_hours: true
          work_hours_start: 8
          work_hours_end: 17
          
        - name: "Marketing"
          block_social: false  # Patient outreach
          allowed_domains:
            - "facebook.com"
            - "twitter.com"
            - "instagram.com"
```

### Example 4: School District (CIPA)

```yaml
pac:
  enabled: true
  default_policy: "education"
  
  policies:
    - tenant: "school-district"
      preset: "education"
      proxy_addr: "proxy.school.edu"
      
      # Student policy (default)
      block_adult: true      # CIPA required
      block_gambling: true   # CIPA required
      block_social: false    # Educational
      block_streaming: false # YouTube for learning
      
      # Staff policy
      staff_policy:
        block_adult: true
        block_gambling: true
        block_social: true     # Work time
        block_streaming: true
        work_hours_start: 8
        work_hours_end: 16
```

## Browser Configuration

### Windows Domain (GPO)

```powershell
# Group Policy: Auto-detect proxy settings
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "AutoConfigURL" `
  -Value "http://proxy.company.com/proxy.pac?user=$env:USERNAME"

# Or via GPO:
# Computer Configuration -> Administrative Templates
# -> Windows Components -> Internet Explorer
# -> Use Automatic Configuration Script
# URL: http://proxy.company.com/proxy.pac?user=%USERNAME%
```

### macOS (Configuration Profile)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.proxy.http.global</string>
            <key>ProxyAutoConfigEnable</key>
            <integer>1</integer>
            <key>ProxyAutoConfigURLString</key>
            <string>http://proxy.company.com/proxy.pac</string>
        </dict>
    </array>
</dict>
</plist>
```

### WPAD (Web Proxy Auto-Discovery)

```dns
# DNS TXT record
wpad.company.com. IN TXT "service:http://proxy.company.com/wpad.dat"

# DHCP Option 252
option wpad code 252 = text;
option wpad "http://proxy.company.com/wpad.dat";
```

## Advanced Features

### Per-User Whitelist/Blacklist

```json
{
  "user_id": "dev@company.com",
  "policy": {
    "preset": "corporate",
    "allowed_domains": [
      "github.com",
      "gitlab.com",
      "stackoverflow.com",
      "reddit.com",
      "hackernews.com"
    ],
    "blocked_domains": [
      "facebook.com",
      "twitter.com"
    ]
  }
}
```

### Time-Based Restrictions

```json
{
  "user_id": "employee@company.com",
  "policy": {
    "block_work_hours": true,
    "work_hours_start": 9,
    "work_hours_end": 17,
    "blocked_during_work": [
      "youtube.com",
      "netflix.com",
      "facebook.com"
    ]
  }
}
```

The PAC file will automatically block these sites during 9 AM - 5 PM on weekdays.

### Geographic Routing

```json
{
  "tenant": "global-corp",
  "policy": {
    "use_geo_routing": true,
    "regional_proxies": {
      "US": "proxy-us.company.com:8080",
      "EU": "proxy-eu.company.com:8080",
      "APAC": "proxy-asia.company.com:8080"
    }
  }
}
```

### Backup Proxies

```json
{
  "policy": {
    "proxy_addr": "proxy1.company.com",
    "proxy_port": 8080,
    "backup_proxies": [
      "PROXY proxy2.company.com:8080",
      "PROXY proxy3.company.com:8080",
      "DIRECT"
    ]
  }
}
```

## Integration with Accounting System

PAC policies can integrate with the accounting system for bandwidth tracking:

```yaml
# Link accounting policies to PAC policies
pac:
  policies:
    - user_id: "employee@company.com"
      accounting:
        track_bandwidth: true
        bandwidth_limit: 10485760  # 10 MB/s
        snoop_enabled: false       # No SSL interception
        
    - user_id: "suspect@company.com"
      accounting:
        track_bandwidth: true
        bandwidth_limit: 1048576   # 1 MB/s (throttled)
        snoop_enabled: true        # Enable SSL interception
        log_all_requests: true
```

## Compliance Matrix

| Policy | CIPA | FISMA | HIPAA | PCI-DSS | SOX | GLBA |
|--------|------|-------|-------|---------|-----|------|
| Government | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Financial | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Healthcare | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Education | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Corporate | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

## Monitoring & Reporting

### PAC Analytics

```bash
# Get PAC file generation stats
curl http://proxy:9090/api/pac/stats

{
  "total_policies": 1250,
  "user_policies": 1000,
  "tenant_policies": 10,
  "pac_requests_24h": 45000,
  "average_pac_size": 8192,
  "cache_hit_rate": 0.95
}
```

### Audit Log

All PAC file accesses are logged:

```
2024-01-15T10:00:00Z INFO PAC file served user=john.doe tenant=acme-corp size=8192 policy=financial
2024-01-15T10:05:00Z INFO Policy updated user=john.doe tenant=acme-corp admin=it-admin
```

## Best Practices

1. **Start with presets** - Use preset policies (government, financial, etc.) and customize
2. **Test before deploy** - Test PAC files in browsers before rolling out
3. **Use tenant policies** - Set base policy at tenant level, override per-user
4. **Monitor PAC requests** - Track which users are requesting PAC files
5. **Version control** - Keep policy changes in git for audit
6. **Gradual rollout** - Deploy new policies to test group first
7. **User communication** - Inform users about blocked categories
8. **Whitelist process** - Have a process for users to request site access

## Troubleshooting

### PAC File Not Loading

```bash
# Check if PAC endpoint is accessible
curl -v http://proxy:9090/proxy.pac

# Check logs
tail -f /var/log/ads-httpproxy.log | grep PAC
```

### Policy Not Applying

```bash
# Verify policy is set
curl http://proxy:9090/api/pac/policy?user=john.doe

# Test PAC file generation
curl http://proxy:9090/proxy.pac?user=john.doe > test.pac
cat test.pac  # Verify content
```

### Browser Not Using PAC

1. Clear browser cache
2. Disable/re-enable PAC in settings
3. Check browser console for errors
4. Test with: `chrome://net-internals/#proxy`

## Future Enhancements

- [ ] Machine learning-based policy recommendations
- [ ] Automatic category detection
- [ ] Integration with HR systems (auto-policy on hire)
- [ ] Mobile device management (MDM) integration
- [ ] Real-time policy updates without PAC reload
- [ ] User self-service policy portal
- [ ] A/B testing for policy effectiveness
