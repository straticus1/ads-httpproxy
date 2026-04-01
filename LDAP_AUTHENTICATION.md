# LDAP/Active Directory Authentication

Enterprise directory authentication support for LDAP and Active Directory environments.

## Overview

The proxy supports authentication against:

- **LDAP** (Lightweight Directory Access Protocol) - Generic LDAP servers (OpenLDAP, FreeIPA, etc.)
- **Active Directory** (Microsoft AD) - Windows domain authentication with AD-specific optimizations
- **LDAPS** - LDAP over TLS (port 636)
- **StartTLS** - Upgrade LDAP connection to TLS (port 389)
- **Global Catalog** - Multi-forest Active Directory deployments

## Features

- ✅ **User authentication** - Bind-based authentication with LDAP/AD
- ✅ **Group membership** - Require users to be in specific groups
- ✅ **TLS/SSL encryption** - LDAPS and StartTLS support
- ✅ **Custom filters** - Advanced LDAP search filters
- ✅ **Service account binding** - Read-only service account for user lookups
- ✅ **Connection pooling** - Efficient connection management
- ✅ **Timeout handling** - Configurable timeouts
- ✅ **AD-specific defaults** - Automatic sAMAccountName and AD filters

## Architecture

```
Browser Request
     │
     ├─► Proxy-Authorization: Basic <base64>
     │
     ▼
LDAP Authenticator
     │
     ├─► 1. Connect to LDAP server (TLS/StartTLS)
     ├─► 2. Bind with service account
     ├─► 3. Search for user DN
     ├─► 4. Bind with user credentials (authenticate)
     ├─► 5. Check group membership (optional)
     │
     ▼
Success/Failure
```

## Configuration

### Basic LDAP Authentication

```yaml
auth:
  mechanism: "ldap"
  ldap:
    url: "ldap://ldap.example.com:389"
    base_dn: "ou=users,dc=example,dc=com"
    bind_dn: "cn=proxy-service,ou=services,dc=example,dc=com"
    bind_password: "service-account-password"
    user_attribute: "uid"
    start_tls: true
    timeout: 10
    realm: "Corporate Proxy"
```

### Active Directory Authentication

```yaml
auth:
  mechanism: "ad"
  ldap:
    url: "ldaps://dc.corp.example.com:636"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "proxy-service@corp.example.com"
    bind_password: "ad-service-password"
    timeout: 10
    realm: "Corporate Network"
```

**AD-specific defaults** (set automatically):
- `user_attribute`: `"sAMAccountName"` (instead of `uid`)
- `user_filter`: `"(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))"`

## Configuration Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | Yes | - | LDAP server URL (`ldap://` or `ldaps://`) |
| `base_dn` | string | Yes | - | Base DN for user search |
| `bind_dn` | string | Yes | - | Service account DN for binding |
| `bind_password` | string | Yes | - | Service account password |
| `user_attribute` | string | No | `"uid"` (LDAP)<br>`"sAMAccountName"` (AD) | Attribute to match username |
| `user_filter` | string | No | Auto-generated | LDAP filter for user search |
| `require_groups` | []string | No | `[]` | List of required groups (CN or full DN) |
| `start_tls` | bool | No | `false` | Use StartTLS for encryption |
| `insecure_skip_verify` | bool | No | `false` | Skip TLS certificate verification |
| `timeout` | int | No | `10` | Connection timeout in seconds |
| `realm` | string | No | `"LDAP Authentication"` | Authentication realm |

## URL Formats

### LDAP (Plain or StartTLS)
```
ldap://ldap.example.com:389
ldap://10.0.0.10
```

### LDAPS (Direct TLS)
```
ldaps://ldap.secure.example.com:636
ldaps://dc1.corp.example.com:636
```

### Active Directory Global Catalog
```
ldaps://gc.corp.example.com:3269  # LDAPS
ldap://gc.corp.example.com:3268   # LDAP
```

## Distinguished Names (DN)

### User DN Examples

**LDAP (OpenLDAP)**:
```
uid=john.doe,ou=users,dc=example,dc=com
```

**Active Directory**:
```
CN=John Doe,OU=Users,DC=corp,DC=example,DC=com
```

**Service Principal Name (UPN)**:
```
proxy-service@corp.example.com
```

### Base DN Examples

```
ou=users,dc=example,dc=com                    # LDAP
dc=corp,dc=example,dc=com                     # AD (root)
ou=employees,dc=corp,dc=example,dc=com        # AD (OU)
cn=users,cn=accounts,dc=example,dc=com        # FreeIPA
```

## User Filters

### Default Filters

**LDAP**:
```
(uid={username})
```

**Active Directory**:
```
(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))
```

### Custom Filters

**Search by email**:
```yaml
user_filter: "(mail={username}@example.com)"
```

**Search by sAMAccountName OR userPrincipalName**:
```yaml
user_filter: "(|(sAMAccountName={username})(userPrincipalName={username}@corp.example.com))"
```

**Exclude disabled AD accounts**:
```yaml
user_filter: "(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

**POSIX accounts only**:
```yaml
user_filter: "(&(objectClass=posixAccount)(uid={username}))"
```

## Group Membership

### Require Groups

```yaml
ldap:
  require_groups:
    - "cn=proxy-users,ou=groups,dc=example,dc=com"
    - "cn=admins,ou=groups,dc=example,dc=com"
```

**How it works**:
- User must be in **at least one** of the listed groups
- Matches by **CN** (Common Name) or **full DN**
- Uses `memberOf` attribute
- Case-insensitive substring matching

### Group DN Formats

**LDAP**:
```
cn=proxy-users,ou=groups,dc=example,dc=com
```

**Active Directory**:
```
CN=Proxy Users,OU=Security Groups,DC=corp,DC=example,DC=com
```

**Shorthand** (matches substring):
```
proxy-users      # Matches any group with "proxy-users" in DN
Domain Admins    # Matches "CN=Domain Admins,..."
```

## TLS/SSL Configuration

### LDAPS (Recommended)

```yaml
ldap:
  url: "ldaps://ldap.example.com:636"
  start_tls: false  # Not needed with LDAPS
  insecure_skip_verify: false  # Verify certificates
```

### StartTLS (Upgrade Plain LDAP)

```yaml
ldap:
  url: "ldap://ldap.example.com:389"
  start_tls: true
  insecure_skip_verify: false
```

### Skip Certificate Verification (NOT RECOMMENDED)

```yaml
ldap:
  url: "ldaps://ldap.example.com:636"
  insecure_skip_verify: true  # ONLY for testing!
```

**Security Warning**: Only use `insecure_skip_verify: true` in development. Production should always verify certificates.

## Deployment Examples

### Example 1: OpenLDAP

```yaml
auth:
  mechanism: "ldap"
  ldap:
    url: "ldap://openldap.example.com:389"
    base_dn: "ou=users,dc=example,dc=com"
    bind_dn: "cn=readonly,dc=example,dc=com"
    bind_password: "readonly-password"
    user_attribute: "uid"
    user_filter: "(&(objectClass=posixAccount)(uid={username}))"
    require_groups:
      - "cn=proxy-access,ou=groups,dc=example,dc=com"
    start_tls: true
    timeout: 10
```

### Example 2: Active Directory (Single Domain)

```yaml
auth:
  mechanism: "ad"
  ldap:
    url: "ldaps://dc1.corp.example.com:636"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "proxy-service@corp.example.com"
    bind_password: "ad-service-password"
    require_groups:
      - "CN=Proxy Users,OU=Security Groups,DC=corp,DC=example,DC=com"
    timeout: 10
    realm: "Corporate Network"
```

### Example 3: Active Directory (Multi-Forest)

```yaml
auth:
  mechanism: "ad"
  ldap:
    # Use Global Catalog for cross-forest authentication
    url: "ldaps://gc.corp.example.com:3269"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "proxy-service@corp.example.com"
    bind_password: "gc-password"
    timeout: 15
```

### Example 4: FreeIPA

```yaml
auth:
  mechanism: "ldap"
  ldap:
    url: "ldaps://ipa.example.com:636"
    base_dn: "cn=users,cn=accounts,dc=example,dc=com"
    bind_dn: "uid=proxy-service,cn=users,cn=accounts,dc=example,dc=com"
    bind_password: "ipa-password"
    user_attribute: "uid"
    require_groups:
      - "cn=proxy-users,cn=groups,cn=accounts,dc=example,dc=com"
    timeout: 10
```

### Example 5: Active Directory with Redundancy

```yaml
# Primary DC
auth:
  mechanism: "ad"
  ldap:
    # Use DNS SRV record or load balancer
    url: "ldaps://ad.corp.example.com:636"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "CN=Proxy Service,OU=Service Accounts,DC=corp,DC=example,DC=com"
    bind_password: "service-password"
    timeout: 5

# If primary fails, manually configure backup DC
# (Automatic failover requires DNS SRV or load balancer)
```

## Browser Configuration

### Automatic Proxy Authentication

**Windows (Domain-joined)**:
```powershell
# Use Integrated Windows Authentication
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "ProxyEnable" -Value 1

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "ProxyServer" -Value "proxy.corp.example.com:8080"
```

**macOS/Linux**:
```bash
# Set proxy environment variables
export http_proxy="http://username:password@proxy.example.com:8080"
export https_proxy="http://username:password@proxy.example.com:8080"

# Or use PAC file
networksetup -setautoproxyurl "Wi-Fi" "http://proxy.example.com/proxy.pac"
```

### Manual Authentication

Users will be prompted for credentials:
- **Username**: LDAP username (e.g., `john.doe` or `CORP\john.doe`)
- **Password**: LDAP/AD password

## Integration with PAC Policies

Combine LDAP authentication with per-user PAC policies:

```yaml
auth:
  mechanism: "ad"
  ldap:
    url: "ldaps://dc.corp.example.com:636"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "proxy-service@corp.example.com"
    bind_password: "password"

# PAC policies can use authenticated username
# See PAC_POLICIES.md for details
```

Then set user-specific policies via API:

```bash
curl -X POST http://proxy:9090/api/pac/policy \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "john.doe",
    "policy": {
      "department": "Finance",
      "block_social": true,
      "block_streaming": true
    }
  }'
```

## Testing

### Test LDAP Connection

```bash
# Install ldapsearch (OpenLDAP client tools)
# Ubuntu/Debian: apt install ldap-utils
# macOS: brew install openldap
# RHEL/CentOS: yum install openldap-clients

# Test connection and bind
ldapsearch -x -H ldap://ldap.example.com:389 \
  -D "cn=proxy-service,dc=example,dc=com" \
  -w "password" \
  -b "dc=example,dc=com" \
  "(uid=testuser)"
```

### Test AD Connection

```bash
ldapsearch -x -H ldaps://dc.corp.example.com:636 \
  -D "proxy-service@corp.example.com" \
  -w "password" \
  -b "dc=corp,dc=example,dc=com" \
  "(sAMAccountName=testuser)"
```

### Test Proxy Authentication

```bash
# Test with curl
curl -x http://proxy.example.com:8080 \
  -U "username:password" \
  http://example.com

# Test with environment variable
export http_proxy="http://username:password@proxy.example.com:8080"
curl http://example.com
```

## Troubleshooting

### Connection Refused

**Error**: `Failed to connect to LDAP: dial tcp: connection refused`

**Solutions**:
- Check firewall rules (port 389/636/3268/3269)
- Verify LDAP server is running
- Test with `telnet ldap.example.com 389`

### TLS Handshake Failure

**Error**: `TLS handshake failed: x509: certificate signed by unknown authority`

**Solutions**:
- Install CA certificate on proxy server
- Use `insecure_skip_verify: true` (testing only)
- Verify hostname matches certificate CN/SAN

### Invalid Credentials

**Error**: `Failed to bind to LDAP: LDAP Result Code 49 "Invalid Credentials"`

**Solutions**:
- Verify `bind_dn` and `bind_password`
- Check service account is not disabled
- For AD, try UPN format: `service@corp.example.com`

### User Not Found

**Error**: `User not found in LDAP`

**Solutions**:
- Verify `base_dn` is correct
- Check `user_attribute` (`uid` vs `sAMAccountName`)
- Test search filter manually with `ldapsearch`
- Ensure user exists in search base

### Group Membership Failed

**Error**: `User not in required groups`

**Solutions**:
- Verify group DN is correct
- Check user's `memberOf` attribute
- Use case-insensitive substring match (e.g., `proxy-users` instead of full DN)
- Test: `ldapsearch -x ... -b "<userDN>" "(objectClass=*)" memberOf`

### Timeout

**Error**: `LDAP connection timeout`

**Solutions**:
- Increase `timeout` value
- Check network connectivity
- Verify LDAP server is responsive
- Use closer DC (for AD multi-site)

## Logging

### Enable Debug Logging

The LDAP authenticator logs to the proxy logger:

```
INFO  LDAP authentication successful  username=john.doe display_name=John Doe dn=cn=...
DEBUG User not found in LDAP  username=invalid-user
DEBUG LDAP authentication failed  username=john.doe error=...
ERROR Failed to connect to LDAP  error=...
ERROR Failed to bind to LDAP  error=...
```

### Audit Trail

All authentication attempts are logged with:
- Username
- Display name (from `cn` or `mail` attribute)
- User DN
- Success/failure
- Error details (if failed)

## Security Best Practices

1. **Use LDAPS** (not plain LDAP)
   - Encrypts credentials in transit
   - Use port 636 for LDAPS

2. **Service Account**
   - Use read-only service account for binding
   - Minimal permissions (just user search)
   - Rotate password regularly

3. **TLS Certificate Verification**
   - Always verify certificates in production
   - Install CA certificate on proxy server
   - Never use `insecure_skip_verify: true` in production

4. **Group-Based Access Control**
   - Restrict proxy access to specific groups
   - Use security groups, not distribution lists
   - Review group membership regularly

5. **Timeouts**
   - Set reasonable timeouts (5-15 seconds)
   - Prevent hanging connections
   - Fail open or closed based on requirements

6. **Logging**
   - Log all authentication attempts
   - Monitor failed login attempts
   - Alert on suspicious patterns

## Performance

### Benchmarks

- **Connection pooling**: Reuses LDAP connections
- **User lookup**: ~10-50ms (depends on LDAP server)
- **Authentication**: ~20-100ms (bind + search + group check)
- **Memory**: ~100KB per connection

### Optimization Tips

1. **Use local LDAP replica** for low latency
2. **Configure shorter timeouts** (5s instead of 30s)
3. **Minimize group checks** (only required groups)
4. **Use connection pooling** (built-in)
5. **Cache group membership** (future enhancement)

## Comparison: LDAP vs Other Methods

| Feature | LDAP/AD | NTLM | Kerberos | OAuth2 | SAML |
|---------|---------|------|----------|--------|------|
| **Enterprise Integration** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **SSO Support** | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Credential Passing** | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Group Membership** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Cross-Platform** | ✅ | ❌ (Windows) | ❌ (Complex) | ✅ | ✅ |
| **Browser Compatibility** | ✅ | ⚠️ (IE/Edge) | ⚠️ (Complex) | ✅ | ✅ |

## Next Steps

1. ✅ LDAP/AD authentication implemented
2. ✅ Group membership checking
3. ⏳ Connection pooling optimization
4. ⏳ Group membership caching
5. ⏳ Multi-DC failover
6. ⏳ Audit logging to SIEM

## Related Documentation

- [PAC_POLICIES.md](PAC_POLICIES.md) - Per-user PAC policies with LDAP integration
- [AUTHENTICATION.md](AUTHENTICATION.md) - Complete authentication guide
- [MULTI_TENANT.md](MULTI_TENANT.md) - Multi-tenant LDAP configurations
