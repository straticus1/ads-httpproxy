# Authentication Methods

Complete guide to all supported authentication mechanisms in ads-httpproxy.

## Overview

The proxy supports multiple enterprise authentication methods:

| Method | Type | SSO | Enterprise | Use Case |
|--------|------|-----|------------|----------|
| **None** | No auth | ❌ | ❌ | Public proxies, testing |
| **Basic** | Username/Password | ❌ | ❌ | Simple deployments |
| **LDAP** | Directory | ❌ | ✅ | OpenLDAP, FreeIPA |
| **Active Directory** | Directory | ❌ | ✅ | Microsoft AD |
| **NTLM** | Challenge/Response | ✅ | ✅ | Windows legacy |
| **Kerberos** | Ticket | ✅ | ✅ | Windows SSO |
| **OAuth2** | Token | ✅ | ✅ | Modern apps, APIs |
| **OIDC** | Token | ✅ | ✅ | SSO, Google, Azure AD |
| **SAML** | Assertion | ✅ | ✅ | Enterprise SSO |

## Quick Start

### No Authentication

```yaml
# No auth section = no authentication
addr: ":8080"
```

### LDAP/Active Directory

```yaml
auth:
  mechanism: "ldap"  # or "ad" for Active Directory
  ldap:
    url: "ldaps://ldap.example.com:636"
    base_dn: "dc=example,dc=com"
    bind_dn: "cn=proxy,dc=example,dc=com"
    bind_password: "password"
```

See [LDAP_AUTHENTICATION.md](LDAP_AUTHENTICATION.md) for full guide.

### NTLM (Windows Integrated)

```yaml
auth:
  mechanism: "ntlm"
  realm: "CORP"
  users:
    john.doe: "password"
```

### Kerberos (SSO)

```yaml
auth:
  mechanism: "kerberos"
  krb5_keytab: "/etc/krb5.keytab"
  krb5_conf: "/etc/krb5.conf"
  realm: "CORP.EXAMPLE.COM"
  service: "HTTP/proxy.corp.example.com"
```

### OAuth2 (Token Introspection)

```yaml
auth:
  mechanism: "oauth2"
  oauth2:
    introspection_url: "https://oauth.example.com/introspect"
    client_id: "proxy-client"
    client_secret: "secret"
```

### OIDC (OpenID Connect)

```yaml
auth:
  mechanism: "oidc"
  oidc:
    issuer: "https://accounts.google.com"
    client_id: "client-id.apps.googleusercontent.com"
    client_secret: "client-secret"
    redirect_url: "http://proxy.example.com:8080/oidc/callback"
    scopes:
      - "openid"
      - "profile"
      - "email"
```

### SAML (Enterprise SSO)

```yaml
auth:
  mechanism: "saml"
  saml:
    metadata_url: "https://sso.example.com/metadata.xml"
    cert: "/path/to/sp-cert.pem"
    key: "/path/to/sp-key.pem"
    root_url: "https://proxy.example.com"
```

## Authentication Flow

### LDAP/AD Flow

```
1. Browser → Proxy (no auth)
2. Proxy → Browser (407 Proxy Auth Required, WWW-Authenticate: Basic)
3. Browser → Proxy (Proxy-Authorization: Basic base64(username:password))
4. Proxy → LDAP Server (Bind with service account)
5. Proxy → LDAP Server (Search for user DN)
6. Proxy → LDAP Server (Bind with user credentials)
7. Proxy → LDAP Server (Check group membership - optional)
8. Proxy → Browser (200 OK / 403 Forbidden)
```

### NTLM Flow

```
1. Browser → Proxy (no auth)
2. Proxy → Browser (407, WWW-Authenticate: NTLM)
3. Browser → Proxy (Type 1 message)
4. Proxy → Browser (Type 2 challenge)
5. Browser → Proxy (Type 3 response)
6. Proxy validates hash
7. Proxy → Browser (200 OK / 403 Forbidden)
```

### Kerberos Flow

```
1. Browser → Proxy (no auth)
2. Proxy → Browser (407, WWW-Authenticate: Negotiate)
3. Browser → KDC (Request service ticket for HTTP/proxy)
4. KDC → Browser (Service ticket)
5. Browser → Proxy (Proxy-Authorization: Negotiate <ticket>)
6. Proxy validates ticket with keytab
7. Proxy → Browser (200 OK / 403 Forbidden)
```

### OAuth2 Flow

```
1. Browser → Proxy (Authorization: Bearer <token>)
2. Proxy → OAuth Server (Introspect token)
3. OAuth Server → Proxy (Token valid/invalid + user info)
4. Proxy → Browser (200 OK / 401 Unauthorized)
```

### OIDC Flow

```
1. Browser → Proxy (no auth)
2. Proxy → Browser (302 Redirect to IdP)
3. Browser → IdP (Login)
4. IdP → Browser (302 Redirect to callback)
5. Browser → Proxy (/oidc/callback?code=...)
6. Proxy → IdP (Exchange code for token)
7. Proxy → Browser (Set session cookie)
8. Browser → Proxy (Cookie)
9. Proxy → Browser (200 OK)
```

### SAML Flow

```
1. Browser → Proxy (no auth)
2. Proxy → Browser (SAML AuthnRequest)
3. Browser → IdP (SAML Request)
4. IdP → Browser (Login)
5. Browser → Proxy (SAML Response)
6. Proxy validates assertion
7. Proxy → Browser (200 OK / 403 Forbidden)
```

## Feature Comparison

### Group-Based Access Control

| Method | Group Support | Implementation |
|--------|---------------|----------------|
| LDAP/AD | ✅ Yes | `require_groups` in config |
| Kerberos | ⚠️ Indirect | Via LDAP lookup after auth |
| SAML | ✅ Yes | Groups in SAML assertion |
| OAuth2 | ⚠️ Custom | Via token claims |
| OIDC | ⚠️ Custom | Via ID token claims |
| NTLM | ❌ No | Username only |

### Single Sign-On (SSO)

| Method | SSO Type | Credential Passing |
|--------|----------|-------------------|
| Kerberos | ✅ Ticket-based | Windows integrated |
| NTLM | ✅ Challenge/Response | Windows integrated |
| OIDC | ✅ Web SSO | Redirect flow |
| SAML | ✅ Web SSO | Redirect flow |
| OAuth2 | ⚠️ Token-based | Manual token |
| LDAP/AD | ❌ No SSO | Prompts for password |

### Platform Support

| Method | Windows | macOS | Linux | Browser |
|--------|---------|-------|-------|---------|
| LDAP/AD | ✅ | ✅ | ✅ | All |
| OAuth2 | ✅ | ✅ | ✅ | All |
| OIDC | ✅ | ✅ | ✅ | All |
| SAML | ✅ | ✅ | ✅ | All |
| Kerberos | ✅ | ⚠️ Complex | ⚠️ Complex | IE, Edge, Firefox |
| NTLM | ✅ Native | ⚠️ Limited | ⚠️ Limited | IE, Edge |

## Multi-Method Support

### Fallback Chain

```yaml
# Primary: Kerberos SSO
# Fallback: LDAP username/password

# NOT CURRENTLY SUPPORTED - Single mechanism only
# Future enhancement for auth chain
```

### Per-Route Authentication

```yaml
routes:
  - path: "/api"
    upstream: "http://backend:8080"
    auth_method: "oauth2"  # API uses OAuth2

  - path: "/admin"
    upstream: "http://admin:8080"
    auth_method: "oidc"     # Admin uses OIDC

# Global auth applies to proxy traffic
auth:
  mechanism: "ldap"
```

## Integration Examples

### Example 1: Corporate Network (Windows)

**Requirements**:
- Windows domain (Active Directory)
- Domain-joined computers
- SSO for employees
- Username/password fallback for BYOD

**Solution**:
```yaml
# Use Kerberos for SSO
auth:
  mechanism: "kerberos"
  krb5_keytab: "/etc/HTTP-proxy.keytab"
  realm: "CORP.EXAMPLE.COM"
  service: "HTTP/proxy.corp.example.com"

# OR: Use Active Directory for username/password
auth:
  mechanism: "ad"
  ldap:
    url: "ldaps://dc.corp.example.com:636"
    base_dn: "dc=corp,dc=example,dc=com"
    bind_dn: "proxy-service@corp.example.com"
    bind_password: "password"
```

### Example 2: SaaS Application

**Requirements**:
- Multi-tenant
- OAuth2 API tokens
- Web SSO for dashboard

**Solution**:
```yaml
# API endpoints use OAuth2
auth:
  mechanism: "oauth2"
  oauth2:
    introspection_url: "https://oauth.example.com/introspect"
    client_id: "proxy-client"
    client_secret: "secret"
```

### Example 3: Educational Institution

**Requirements**:
- LDAP directory (OpenLDAP)
- Group-based access (students, faculty, staff)
- Simple username/password

**Solution**:
```yaml
auth:
  mechanism: "ldap"
  ldap:
    url: "ldaps://ldap.university.edu:636"
    base_dn: "ou=people,dc=university,dc=edu"
    bind_dn: "cn=proxy,ou=services,dc=university,dc=edu"
    bind_password: "service-password"
    require_groups:
      - "cn=students,ou=groups,dc=university,dc=edu"
      - "cn=faculty,ou=groups,dc=university,dc=edu"
      - "cn=staff,ou=groups,dc=university,dc=edu"
```

### Example 4: Healthcare (HIPAA)

**Requirements**:
- Multi-factor authentication
- SAML SSO with IdP
- Audit logging

**Solution**:
```yaml
auth:
  mechanism: "saml"
  saml:
    metadata_url: "https://idp.hospital.org/metadata.xml"
    cert: "/etc/ssl/proxy-sp-cert.pem"
    key: "/etc/ssl/proxy-sp-key.pem"
    root_url: "https://proxy.hospital.org"

# SAML IdP enforces MFA
# All auth attempts logged automatically
```

## Security Best Practices

### 1. Use Strong Authentication

| Security Level | Recommended Methods |
|----------------|---------------------|
| **High** (Finance, Healthcare) | Kerberos, SAML, OIDC with MFA |
| **Medium** (Corporate) | LDAP/AD with TLS, OAuth2 |
| **Low** (Internal testing) | Basic auth, NTLM |

### 2. Enable TLS

- **LDAP**: Always use LDAPS (`ldaps://`) or StartTLS
- **OAuth2/OIDC**: HTTPS for all IdP endpoints
- **Kerberos**: Encrypted tickets
- **SAML**: Sign assertions

### 3. Rotate Credentials

- **Service accounts**: Rotate every 90 days
- **Keytabs**: Regenerate annually
- **OAuth2 secrets**: Rotate quarterly
- **SAML certificates**: Rotate before expiry

### 4. Audit Logging

All authentication methods log:
- Username
- Auth method
- Success/failure
- Timestamp
- Source IP

Export to SIEM for monitoring.

### 5. Least Privilege

- **LDAP service account**: Read-only
- **OAuth2 client**: Minimal scopes
- **Kerberos principal**: Single service
- **SAML attributes**: Only required fields

## Troubleshooting

### Common Issues

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| 407 Proxy Auth Required | No credentials | Check browser auth settings |
| 403 Forbidden | Invalid credentials | Verify username/password |
| Connection timeout | Network/firewall | Check connectivity to auth server |
| TLS handshake failed | Certificate error | Verify CA certificates |
| User not found | Wrong base DN | Check LDAP search base |
| Group check failed | Wrong group DN | Verify group membership |
| Token expired | Clock skew | Sync NTP time |
| Kerberos ticket expired | No renewal | Check krb5.conf ticket lifetime |

### Debug Logging

Enable debug logs to troubleshoot:

```bash
# View proxy logs
tail -f /var/log/ads-httpproxy.log

# Look for authentication events
grep "authentication" /var/log/ads-httpproxy.log
grep "LDAP" /var/log/ads-httpproxy.log
grep "Kerberos" /var/log/ads-httpproxy.log
```

## Performance Considerations

### Connection Pooling

| Method | Pooling | Performance |
|--------|---------|-------------|
| LDAP/AD | ✅ Yes | ~50ms per auth |
| Kerberos | ✅ Yes | ~20ms per auth |
| OAuth2 | ❌ No | ~100ms (network) |
| OIDC | ❌ Session | ~10ms (cached) |
| SAML | ❌ Session | ~10ms (cached) |

### Caching

- **LDAP**: Connection pool, no credential cache
- **Kerberos**: Ticket cache (automatic)
- **OAuth2**: No cache (validate each request)
- **OIDC**: Session cache (cookie-based)
- **SAML**: Session cache (cookie-based)

### Scalability

| Method | Max RPS | Bottleneck |
|--------|---------|------------|
| LDAP/AD | 1000+ | LDAP server |
| Kerberos | 5000+ | CPU (ticket validation) |
| OAuth2 | 500+ | IdP introspection endpoint |
| OIDC | 10000+ | Session storage |
| SAML | 10000+ | Session storage |

## Migration Guide

### From No Auth to LDAP

1. Deploy LDAP config
2. Test with pilot users
3. Roll out via GPO/MDM
4. Monitor failed auth attempts

### From NTLM to Kerberos

1. Configure Kerberos
2. Test SSO on domain-joined machines
3. Keep NTLM as fallback temporarily
4. Disable NTLM after migration

### From Basic to OAuth2

1. Deploy OAuth2 IdP
2. Issue tokens to apps
3. Configure introspection endpoint
4. Migrate apps to use tokens
5. Disable basic auth

## Configuration Reference

See individual authentication guides:

- [LDAP_AUTHENTICATION.md](LDAP_AUTHENTICATION.md) - LDAP/AD configuration
- OAuth2 - See `examples/config-oauth2.yaml`
- OIDC - See `examples/config-oidc.yaml`
- SAML - See `examples/config-saml.yaml`
- Kerberos - See `examples/config-kerberos.yaml`

## API

### Get Current Auth Config

```bash
curl http://proxy:9090/config \
  -H "X-API-Key: secret"
```

Returns:
```json
{
  "auth": {
    "mechanism": "ldap",
    "ldap": {
      "url": "ldaps://ldap.example.com:636",
      "base_dn": "dc=example,dc=com",
      ...
    }
  }
}
```

## Future Enhancements

- [ ] Multi-method fallback chains
- [ ] LDAP group caching
- [ ] Kerberos constrained delegation
- [ ] OAuth2 token caching
- [ ] RADIUS support
- [ ] Certificate-based auth (mTLS)
- [ ] Biometric auth (WebAuthn)

## Support Matrix

| Auth Method | Status | Production Ready |
|-------------|--------|------------------|
| None | ✅ Complete | ✅ Yes |
| LDAP | ✅ Complete | ✅ Yes |
| Active Directory | ✅ Complete | ✅ Yes |
| NTLM | ✅ Complete | ⚠️ Legacy |
| Kerberos | ✅ Complete | ✅ Yes |
| OAuth2 | ✅ Complete | ✅ Yes |
| OIDC | ✅ Complete | ✅ Yes |
| SAML | ✅ Complete | ✅ Yes |
