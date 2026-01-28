# Cloud Proxy Service Architecture (Zscaler Model)

## Overview

Transform `ads-httpproxy` into a globally-distributed, multi-tenant cloud proxy service similar to Zscaler, providing secure web gateway (SWG), cloud access security broker (CASB), and zero-trust network access (ZTNA) capabilities.

## Architecture Components

### 1. Management Plane (Central Control)

**Location:** Centralized (multi-region for HA)

**Components:**
```
├── Admin Portal (Web UI)
│   ├── Tenant management
│   ├── Policy configuration
│   ├── User provisioning
│   ├── Analytics dashboard
│   └── Billing/licensing
│
├── Policy Engine
│   ├── Policy compiler
│   ├── Policy versioning
│   ├── Distribution service
│   └── Conflict resolution
│
├── Analytics Platform
│   ├── Metrics aggregation
│   ├── Log collection (ELK/Splunk)
│   ├── Threat intelligence feeds
│   └── ML anomaly detection
│
└── Control API
    ├── gRPC for PoP sync
    ├── REST for admin operations
    ├── GraphQL for complex queries
    └── WebSocket for real-time updates
```

**Database:**
```
- Tenant metadata (PostgreSQL)
- Policy storage (PostgreSQL + Redis cache)
- Time-series metrics (InfluxDB/TimescaleDB)
- Logs (Elasticsearch)
- User directory (LDAP/Active Directory sync)
```

### 2. Edge PoPs (Data Plane)

**Distribution:** Global (15-50+ locations)

**Each PoP Runs:**
```
┌─────────────────────────────────────────┐
│          Load Balancer (Anycast)        │
│         (GeoDNS + Anycast IPs)          │
└───────────────┬─────────────────────────┘
                │
    ┌───────────┴───────────┐
    │   Tenant Router       │  ← Routes to correct tenant
    │   (SNI inspection)    │
    └───────────┬───────────┘
                │
    ┌───────────┴───────────┐
    │                       │
┌───▼────────┐      ┌──────▼─────┐
│  Tenant A  │      │  Tenant B  │
│ ads-proxy  │      │ ads-proxy  │
│ namespace  │      │ namespace  │
└────────────┘      └────────────┘

Each tenant namespace has:
- ads-httpproxy instance
- Local policy cache
- Metrics agent
- Certificate store (tenant CA)
- Threat intelligence cache
```

**PoP Selection:**
```
Client → GeoDNS lookup → Nearest PoP IP
         (based on GeoIP + latency)
```

### 3. Client-Side Components

**Options:**

**A. PAC File (Lightweight)**
```javascript
function FindProxyForURL(url, host) {
    // Auto-discover nearest PoP
    if (isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0"))
        return "DIRECT";

    // Primary PoP
    return "PROXY us-west.ads-cloud.io:8080; " +
           // Fallback PoPs
           "PROXY us-east.ads-cloud.io:8080; " +
           "PROXY eu-west.ads-cloud.io:8080";
}
```

**B. Native Client Agent**
```
- Auto-discovers nearest PoP (latency checks)
- Caches auth tokens
- Handles certificate trust
- Provides user identity
- Reports telemetry
- Seamless failover
```

**C. GRE/IPSec Tunnel**
```
- For site-to-site connections
- Branch office connectivity
- SD-WAN integration
```

### 4. Multi-Tenancy Design

#### Isolation Models

**Level 1: Namespace Isolation (Kubernetes)**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-acme-corp
  labels:
    tenant-id: "acme-123"
---
# Each tenant gets:
- Dedicated pods
- Network policies
- Resource quotas
- Separate ingress
```

**Level 2: Process Isolation**
```go
// Each tenant = separate ads-proxy process
// Pros: Strong isolation
// Cons: Higher resource usage
```

**Level 3: Request-Level Isolation**
```go
// Single proxy, tenant ID in request context
// Pros: Most efficient
// Cons: Requires careful coding (prevent leaks)
```

#### Tenant Configuration

```go
type TenantConfig struct {
    TenantID         string
    OrgName          string

    // Authentication
    AuthMethod       AuthType  // OIDC, SAML, LDAP
    IdentityProvider string

    // Policies
    Policies         []Policy
    AllowedDomains   []string
    BlockedDomains   []string

    // Security
    EnableWAF        bool
    EnableDLP        bool
    DLPPatterns      []string
    ThreatLevel      string  // paranoid, high, medium, low

    // Custom CA (for MITM)
    CACert           []byte
    CAKey            []byte

    // Resources
    Quota            ResourceQuota
    Bandwidth        BandwidthLimit

    // Routing
    PreferredPoPs    []string
    BackupPoPs       []string
}

type ResourceQuota struct {
    MaxConnections   int
    MaxRequests      int  // per second
    MaxBandwidth     int  // bytes per second
    MaxUsers         int
}
```

### 5. Policy Distribution

**Central → Edge Flow:**
```
1. Admin creates policy in Management Portal
2. Policy Engine compiles policy
3. Policy versioned and stored (PostgreSQL)
4. Distribution service pushes to all PoPs (gRPC stream)
5. Edge PoPs cache policy locally (Redis)
6. ads-proxy hot-reloads policy (no restart)
```

**Policy Sync Protocol:**
```protobuf
service PolicySync {
  // PoP subscribes to policy updates
  rpc StreamPolicies(stream PolicyRequest) returns (stream Policy);

  // PoP fetches full policy set on startup
  rpc FetchPolicies(TenantID) returns (PolicyBundle);

  // PoP reports policy application status
  rpc ReportStatus(PolicyStatus) returns (Ack);
}
```

### 6. Identity & Authentication

**User Authentication Flow:**
```
1. User opens browser
2. PAC/agent redirects to ads-proxy
3. ads-proxy sees no session → redirect to IdP (OIDC/SAML)
4. User authenticates with IdP
5. IdP returns token/assertion
6. ads-proxy validates, creates session
7. Session cookie stored (Redis)
8. Subsequent requests include session cookie
```

**Identity Context:**
```go
type UserIdentity struct {
    TenantID     string
    UserID       string
    Email        string
    Groups       []string
    Roles        []string
    Attributes   map[string]string

    // From IdP
    IDPToken     string
    TokenExpiry  time.Time
}

// Attached to every request
type RequestContext struct {
    TenantID     string
    Identity     UserIdentity
    SourceIP     string
    PoP          string
    RequestID    string
}
```

### 7. Deployment Architecture

#### Global Distribution

```
Region          PoP Location            Anycast IP        Capacity
------          ------------            ----------        --------
US-WEST         San Francisco, CA       203.0.113.10      50k RPS
US-EAST         Ashburn, VA             203.0.113.10      50k RPS
EU-WEST         Dublin, Ireland         203.0.113.11      30k RPS
EU-CENTRAL      Frankfurt, Germany      203.0.113.11      30k RPS
APAC-SG         Singapore               203.0.113.12      20k RPS
APAC-JP         Tokyo, Japan            203.0.113.12      20k RPS
```

**Anycast Setup:**
- Same IP announced from multiple PoPs
- BGP routing sends traffic to nearest PoP
- Automatic failover if PoP goes down

#### Kubernetes Deployment

**Per-PoP Cluster:**
```yaml
# Management components
- namespace: control-plane
  - policy-sync-service
  - metrics-collector
  - tenant-router

# Tenant namespaces (one per tenant)
- namespace: tenant-{id}
  - ads-proxy deployment (3+ replicas)
  - redis (policy cache)
  - configmap (tenant config)
  - networkpolicy (isolation)
```

**Auto-Scaling:**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ads-proxy-hpa
  namespace: tenant-acme
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ads-proxy
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
```

### 8. Observability

#### Metrics Collection

**Per-PoP:**
```
ads-proxy → Prometheus → Central TimescaleDB
               ↓
         Grafana (local view)
```

**Central:**
```
All PoPs → Aggregator → InfluxDB/TimescaleDB
                ↓
           Grafana (global view)
           AI/ML Analysis
           Alerting
```

**Key Metrics:**
```
- Requests per second (per tenant, per PoP)
- Latency (p50, p95, p99)
- Error rate
- Bandwidth usage
- Active connections
- Policy violations
- Threat detections
- WAF blocks
- DLP incidents
```

#### Logging

**Architecture:**
```
ads-proxy → Fluentd/Vector → Kafka → Elasticsearch
                                  ↓
                              Splunk/DataDog
                                  ↓
                              SIEM Integration
```

**Log Format:**
```json
{
  "timestamp": "2026-01-28T08:00:00Z",
  "tenant_id": "acme-123",
  "user_id": "john@acme.com",
  "pop": "us-west",
  "request_id": "req-abc-123",
  "method": "GET",
  "url": "https://example.com/api/data",
  "status": 200,
  "latency_ms": 45,
  "bytes_sent": 1024,
  "bytes_received": 4096,
  "policy_violations": [],
  "threat_detected": false,
  "waf_action": "allow",
  "dlp_matches": []
}
```

### 9. Security Features

#### Per-Tenant Isolation

**Network Level:**
- Kubernetes NetworkPolicies
- Separate VPCs (if not K8s)
- No cross-tenant traffic

**Data Level:**
- Encrypted at rest (tenant keys)
- Encrypted in transit (TLS 1.3)
- Certificate pinning
- Separate Redis databases per tenant

**Identity Level:**
- Tenant-specific IdP integration
- JWT tokens scoped to tenant
- No user cross-contamination

#### Threat Intelligence

**Feeds:**
```
- DNS Science (real-time domain reputation)
- IP blocklists (Spamhaus, etc.)
- Malware hashes
- Phishing URLs
- C2 server IPs
- JA3 fingerprint database (known malware)
```

**Feed Update:**
```
Central → Download feeds → Push to all PoPs → Cache locally
          (every 5 minutes)
```

### 10. Business Model

#### Pricing Tiers

**Starter:** $5/user/month
- 1 Gbps bandwidth
- Basic policies
- Email support
- 3 PoPs

**Business:** $15/user/month
- 10 Gbps bandwidth
- Advanced policies (DLP, WAF)
- 24/7 support
- All PoPs
- SAML/OIDC

**Enterprise:** Custom
- Unlimited bandwidth
- Custom policies
- Dedicated support
- Private PoPs
- SLA guarantees
- Custom integrations

#### Resource Allocation

```go
type Tier struct {
    Name              string
    PricePerUser      float64
    MaxBandwidth      int64  // bytes/sec
    MaxConnections    int
    EnabledFeatures   []string
    SupportLevel      string
    PoPs              []string
}
```

### 11. Implementation Phases

#### Phase 1: Core Multi-Tenancy (2-3 months)
- [ ] Add tenant ID to all request contexts
- [ ] Implement tenant configuration store
- [ ] Build tenant router (SNI-based routing)
- [ ] Create namespace isolation in K8s
- [ ] Implement per-tenant metrics
- [ ] Build admin API for tenant CRUD

#### Phase 2: Management Plane (2-3 months)
- [ ] Build admin web portal
- [ ] Implement policy engine
- [ ] Create policy distribution service
- [ ] Build analytics aggregation
- [ ] Implement billing/licensing
- [ ] Create user provisioning system

#### Phase 3: Edge PoP Infrastructure (3-4 months)
- [ ] Deploy Kubernetes clusters (3+ regions)
- [ ] Setup Anycast networking
- [ ] Configure GeoDNS
- [ ] Implement auto-scaling
- [ ] Build PoP health monitoring
- [ ] Create failover automation

#### Phase 4: Client Components (1-2 months)
- [ ] Build PAC file generator
- [ ] Create native client agent (Windows/Mac/Linux)
- [ ] Implement auto-discovery
- [ ] Add certificate trust automation
- [ ] Build mobile clients (iOS/Android)

#### Phase 5: Enterprise Features (Ongoing)
- [ ] Advanced DLP
- [ ] Machine learning threat detection
- [ ] CASB capabilities
- [ ] ZTNA/VPN replacement
- [ ] Integration marketplace
- [ ] Custom reporting

### 12. Competitive Analysis

| Feature | Zscaler | Cloudflare Gateway | Your ads-httpproxy |
|---------|---------|-------------------|-------------------|
| Global PoPs | 150+ | 300+ | Planned: 15-50 |
| Multi-tenancy | ✅ | ✅ | To implement |
| DLP | ✅ | ✅ | ✅ Implemented |
| WAF | ✅ | ✅ | ✅ Implemented |
| CASB | ✅ | ❌ | Planned |
| ZTNA | ✅ | ✅ (Tunnels) | Planned |
| Price/user | $12-25 | $7-15 | Target: $5-15 |
| Open Source | ❌ | ❌ | ✅ Potential |

### 13. Technical Challenges

**Challenge 1: State Management**
- Users routed to different PoPs = session sync needed
- Solution: Centralized session store (Redis Cluster)

**Challenge 2: Policy Consistency**
- Policy updates must reach all PoPs
- Solution: gRPC streaming + versioning + rollback

**Challenge 3: Certificate Management**
- Per-tenant MITM CAs
- Solution: Vault/cert-manager integration

**Challenge 4: Data Residency**
- Some tenants require data to stay in region
- Solution: Per-tenant PoP restrictions

**Challenge 5: Cost at Scale**
- 100k users × 50GB/day = petabytes/month
- Solution: Aggressive caching, CDN integration

### 14. Go-to-Market Strategy

**Target Markets:**
1. **SMB (100-1000 users):**
   - Easy onboarding
   - Self-service portal
   - Fixed pricing

2. **Mid-Market (1000-10000 users):**
   - Custom policies
   - Integration support
   - Volume discounts

3. **Enterprise (10000+ users):**
   - Dedicated PoPs
   - Custom features
   - White-glove support

**Sales Channels:**
- Direct sales (enterprise)
- Self-service signup (SMB)
- Channel partners/MSPs
- Cloud marketplaces (AWS/Azure/GCP)

## Next Steps

1. **POC**: Deploy single-tenant version on K8s (1 week)
2. **Multi-tenant POC**: Add tenant isolation (2 weeks)
3. **Management Plane MVP**: Basic admin portal (4 weeks)
4. **Alpha**: 5-10 pilot customers (2 months)
5. **Beta**: Expand to 3 PoPs, 50 customers (4 months)
6. **GA**: Full production, global PoPs (6-12 months)

## References

- [Zscaler Architecture](https://www.zscaler.com/technology)
- [Cloudflare Gateway](https://www.cloudflare.com/zero-trust/products/gateway/)
- [Multi-tenancy Patterns](https://kubernetes.io/docs/concepts/security/multi-tenancy/)
- [Anycast Networking](https://blog.cloudflare.com/a-brief-anycast-primer/)
