---
phase: 01-platform
plan: 02
subsystem: identity
tags: [oidc, saml, oauth2, sessions]
requires: [existing OIDC/SAML/OAuth libraries, root-owned configuration fields]
provides: [verified principal context, browser authentication, access-token introspection]
affects: [proxy authentication, CEL policy identity, session revocation]
tech-stack:
  added: []
  patterns: [opaque bounded sessions, issuer-subject identity, PKCE and nonce binding]
key-files:
  created: [internal/auth/principal.go, internal/auth/browser_session.go, internal/auth/identity_test.go, internal/auth/saml_integration_test.go, internal/config/identity.go]
  modified: [internal/auth/oidc.go, internal/auth/oauth2.go, internal/auth/saml.go]
completed: 2026-10-27
---

# Phase 01 Plan 02: Enterprise identity

OIDC authorization-code login with PKCE, one-use browser-bound state, verified nonce and JWKS signatures; signed SAML login/ACS with replay detection; and OAuth introspection enforcing configured resource/scope/issuer/expiry requirements.

## Delivered

- Standalone `auth.mechanism: mtls` accepts only TLS verified, currently valid certificate chains, with URI SAN (or SHA256 certificate fingerprint) subject, issuer, expiry, and certificate fingerprint device identity. Presented but unverified certificates are rejected. Authentication time remains unset because HTTP requests do not expose TLS handshake time; recent-auth policy therefore fails closed for this mechanism.
- `Principal` holds stable subject/issuer, display username, groups, scopes, tenant, device ID, authentication time/strength, and expiry. `BindPrincipal` and `PrincipalFromContext` clone slices so callers cannot mutate trusted identity inadvertently. Expired principals are rejected.
- `BrowserAuthenticator.HandleBrowser(w,r) bool` handles only origin-form gateway requests on its exact configured authority. Absolute-form forward-proxy requests and CONNECT are rejected by browser handlers and cookie authentication.
- OIDC endpoints: GET `/auth/login?return=/local/path`, GET the configured redirect path, POST `/auth/logout` with exact same-origin `Origin`. Provider discovery/JWKS, auth and token endpoints require HTTPS except explicit loopback development URLs. Callback state is one-use, expires after five minutes, and binds a same-browser HTTP-only cookie. Tokens are checked for nonce, issuer, audience, expiry, and `at_hash` where present. ID tokens are not accepted as bearer API credentials unless `allow_legacy_id_tokens` is explicitly enabled.
- SAML endpoints: GET `/saml/metadata`, POST `/saml/acs`, GET `/auth/login`, POST `/auth/logout`. IdP-initiated unsolicited assertions are disabled. Uses validated RSA >=2048 or P-256 keypairs and bounded metadata/ACS bodies. A bounded assertion replay cache rejects copied assertions even if the requester retained the signed request-tracking cookie. Attribute mapping supports subject/group/tenant; stable NameID is the default subject.
- Browser sessions contain no tokens in cookies: opaque random IDs resolve to bounded, expiring instance-local principal records. Login rotates existing sessions. `RevokeSubject(subject string) int` invalidates all local sessions for that subject. SAML session lifetime is capped by assertion/session expiry.
- OAuth2 introspection is request-cancelable, timeout-bounded, refuses redirects, limits response size, requires an active stable subject, validates nbf/exp, and enforces configured audience, issuer, required scopes, and required expiry. Group/tenant/device/AMR/ACR claims come only from the introspection response.
- `config.ValidateIdentity(*AuthConfig) error` validates the new identity options; root owns calling it from global config validation.

## Verification

- `ASDF_GOLANG_VERSION=1.25.7 go test ./internal/auth`: passed.
- `ASDF_GOLANG_VERSION=1.25.7 go test -race ./internal/auth`: passed.
- Local fixtures exercise real RSA-signed OIDC tokens/JWKS and the SAML library's IdP->SP signed assertion flow, along with invalid SAML, nonce/state errors, replay, logout-origin checks, revocation, cookie isolation, and OAuth claim rejection.
- `git diff --check -- internal/auth internal/config/identity.go`: passed.

## Integration contract

Root must mount `HandleBrowser` ahead of gateway request authentication; on successful legacy authentication without a principal, root can bind a legacy principal. Never populate principal claims from untrusted request headers. Root owns session-revocation management endpoints, config.go additions and docs.

### Example OIDC configuration

```yaml
auth:
  mechanism: oidc
  oidc:
    issuer: https://idp.example/application/o/proxy/
    client_id: ads-proxy
    client_secret: replace-from-secret-store
    redirect_url: https://gateway.example/auth/callback
    scopes: [profile, groups]
    groups_claim: groups
    tenant_claim: tenant
    session_ttl_seconds: 3600
    session_capacity: 10000
```

### Example OAuth API configuration

```yaml
auth:
  mechanism: oauth2
  oauth2:
    introspection_url: https://idp.example/application/o/introspect/
    client_id: ads-proxy
    client_secret: replace-from-secret-store
    audience: ads-gateway
    issuer: https://idp.example/application/o/proxy/
    required_scopes: [gateway.access]
    require_expiry: true
```

### Example SAML configuration

```yaml
auth:
  mechanism: saml
  saml:
    metadata_url: https://idp.example/saml/metadata
    root_url: https://gateway.example
    cert: /etc/ads/sp.crt
    key: /etc/ads/sp.key
    groups_attribute: groups
    tenant_attribute: tenant
```

Register SP metadata at `/saml/metadata` with the IdP; ACS is `/saml/acs`. SAML POST binding requires HTTPS so SameSite=None tracking cookies work cross-site. HTTP loopback is permitted for fixtures/development but is not a deployment recommendation.

## Decisions and limitations

- No commits made by this executor: parent explicitly owns the requested 5–10 commit series and shared planning state.
- Sessions and SAML replay state are instance-local. Use one instance or sticky routing; restarts invalidate sessions. Distributed session/replay stores and IdP single logout/back-channel logout are not implemented.
- Browser login is explicitly entered through `/auth/login`; the gateway may return its usual auth challenge for unauthenticated application requests. No redirect of arbitrary forward-proxy destinations.
- Metadata/key rotation is loaded at startup for SAML; OIDC JWKS refresh uses the existing verifier library. Actual provider accounts and browser interoperability were not available; fixtures validate protocol integration, not provider-specific deployment settings.

## Threat Flags

| Flag | File | Description |
| --- | --- | --- |
| auth endpoint | internal/auth/oidc.go | Browser login/callback/logout; bounded pending state, host gate, PKCE, CSRF state, nonce, same-origin logout. |
| assertion endpoint | internal/auth/saml.go | SAML ACS processes untrusted XML through existing library validation; bounded input and replay cache. |
| identity network | internal/auth/oauth2.go | Operator-configured introspection endpoint receives credentials; HTTPS, redirect refusal and bounded response. |

## Self-Check: PASSED

Created files exist and targeted protocol/race tests pass. No placeholder identity or synthetic generic username is accepted as an authenticated subject. Final integration and commits are owned by root.
