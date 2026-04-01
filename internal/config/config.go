package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config needs to be loaded from json/yaml later.
type Config struct {
	Addr            string                    `json:"addr" yaml:"addr"`
	DataCenter      string                    `json:"data_center" yaml:"data_center"` // For Cluster Sync
	SocksAddr       string                    `json:"socks_addr" yaml:"socks_addr"`
	MirrorAddr      string                    `json:"mirror_addr" yaml:"mirror_addr"`
	CaCert          string                    `json:"ca_cert" yaml:"ca_cert"`
	CaKey           string                    `json:"ca_key" yaml:"ca_key"`
	ApiAddr         string                    `json:"api_addr" yaml:"api_addr"`
	GrpcAddr        string                    `json:"grpc_addr" yaml:"grpc_addr"`
	ApiSecret       string                    `json:"api_secret" yaml:"api_secret"`
	BandwidthLimit  float64                   `json:"bandwidth_limit" yaml:"bandwidth_limit"` // Bytes per second
	IcapUrl         string                    `json:"icap_url" yaml:"icap_url"`
	DlpPatterns     []string                  `json:"dlp_patterns" yaml:"dlp_patterns"`
	ScriptFile      string                    `json:"script_file" yaml:"script_file"`
	Auth            *AuthConfig               `json:"auth" yaml:"auth"`
	RtmpAddr        string                    `json:"rtmp_addr" yaml:"rtmp_addr"`
	RtmpTarget      string                    `json:"rtmp_target" yaml:"rtmp_target"`
	RtspAddr        string                    `json:"rtsp_addr" yaml:"rtsp_addr"`
	RtspTarget      string                    `json:"rtsp_target" yaml:"rtsp_target"`
	FtpAddr         string                    `json:"ftp_addr" yaml:"ftp_addr"`
	FtpTarget       string                    `json:"ftp_target" yaml:"ftp_target"`
	SshAddr         string                    `json:"ssh_addr" yaml:"ssh_addr"`
	SshTarget       string                    `json:"ssh_target" yaml:"ssh_target"`
	EnableReusePort bool                      `json:"enable_reuseport" yaml:"enable_reuseport"`
	EnableQUIC      bool                      `json:"enable_quic" yaml:"enable_quic"`
	ThreatFile      string                    `json:"threat_file" yaml:"threat_file"`       // Path to blocked IPs/CIDRs
	ThreatSources   []string                  `json:"threat_sources" yaml:"threat_sources"` // List of URLs to fetch threat feeds from
	GeoIPDBFile     string                    `json:"geoip_db_file" yaml:"geoip_db_file"`
	GeoIPAllow      []string                  `json:"geoip_allow" yaml:"geoip_allow"`
	GeoIPBlock      []string                  `json:"geoip_block" yaml:"geoip_block"`
	Routes          []RouteConfig             `json:"routes" yaml:"routes"`
	DNSScience      *DNSScienceConfig         `json:"dns_science" yaml:"dns_science"`
	DarkAPI         *DarkAPIConfig            `json:"dark_api" yaml:"dark_api"` // New stats reporting
	Redis           *RedisConfig              `json:"redis" yaml:"redis"`
	Peering         *PeeringConfig            `json:"peering" yaml:"peering"` // New Distributed Caching
	Reputation      *ReputationConfig         `json:"reputation" yaml:"reputation"`
	MultiTenant     *MultiTenantConfig        `json:"multi_tenant" yaml:"multi_tenant"`
	PolicyFile      string                    `json:"policy_file" yaml:"policy_file"` // Path to CEL policy file
	UpstreamGroups  map[string]*UpstreamGroup `json:"upstream_groups" yaml:"upstream_groups"`
	Chains          map[string]*ProxyChain    `json:"chains" yaml:"chains"`
	PAC             *PACConfig                `json:"pac" yaml:"pac"`
}

type UpstreamGroup struct {
	Type        string   `json:"type" yaml:"type"`                 // "round-robin", "failover", "random"
	Targets     []string `json:"targets" yaml:"targets"`           // List of upstream URLs
	HealthCheck string   `json:"health_check" yaml:"health_check"` // URL to check health (e.g. /health)
}

type ProxyChain struct {
	Proxies []string `json:"proxies" yaml:"proxies"` // List of proxy URLs (socks5://..., http://...)
}

type PACConfig struct {
	BypassDomains  []string `json:"bypass_domains" yaml:"bypass_domains"`
	BypassNetworks []string `json:"bypass_networks" yaml:"bypass_networks"`
}

type ReputationConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	URL      string `json:"url" yaml:"url"`         // http://localhost:8080
	Timeout  int    `json:"timeout" yaml:"timeout"` // Milliseconds
	FailOpen bool   `json:"fail_open" yaml:"fail_open"`
}

type PeeringConfig struct {
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	Peers     []string `json:"peers" yaml:"peers"`
	ICPPort   int      `json:"icp_port" yaml:"icp_port"`
	HTCPPort  int      `json:"htcp_port" yaml:"htcp_port"`
	Algorithm string   `json:"algorithm" yaml:"algorithm"` // "carp", "round-robin"
}

type DarkAPIConfig struct {
	ConsoleURL  string `json:"console_url" yaml:"console_url"`
	ReportStats bool   `json:"report_stats" yaml:"report_stats"`
	APIKey      string `json:"api_key" yaml:"api_key"` // Uses DNSScience key if empty, or distinct
}

type RedisConfig struct {
	Addr     string `json:"addr" yaml:"addr"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
	Enabled  bool   `json:"enabled" yaml:"enabled"`
}

// RouteConfig defines a reverse proxy route
type RouteConfig struct {
	Path       string `json:"path" yaml:"path"`
	Upstream   string `json:"upstream" yaml:"upstream"`
	RateLimit  int    `json:"rate_limit" yaml:"rate_limit"`   // Requests/second
	AuthMethod string `json:"auth_method" yaml:"auth_method"` // "none", "oidc", "basic"
	Chain      string `json:"chain" yaml:"chain"`             // Name of ProxyChain to use (optional)
}

type DNSScienceConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	APIKey          string `json:"api_key" yaml:"api_key"`
	FeedURL         string `json:"feed_url" yaml:"feed_url"`
	RefreshInterval string `json:"refresh_interval" yaml:"refresh_interval"`
	RPCAddr         string `json:"rpc_addr" yaml:"rpc_addr"`
}

type AuthConfig struct {
	Mechanism  string            `json:"mechanism" yaml:"mechanism"`     // "none", "basic", "ntlm", "kerberos"
	KRB5Keytab string            `json:"krb5_keytab" yaml:"krb5_keytab"` // Path to keytab
	KRB5Conf   string            `json:"krb5_conf" yaml:"krb5_conf"`     // Path to krb5.conf (optional, defaults to /etc/krb5.conf)
	Realm      string            `json:"realm" yaml:"realm"`             // Kerberos Realm
	Service    string            `json:"service" yaml:"service"`         // Service Principal Name (HTTP/fqdn)
	Users      map[string]string `json:"users" yaml:"users"`             // Local users for NTLM/Basic auth (username:password)
	OIDC       *OIDCConfig       `json:"oidc" yaml:"oidc"`
	OAuth2     *OAuth2Config     `json:"oauth2" yaml:"oauth2"`
	SAML       *SAMLConfig       `json:"saml" yaml:"saml"`
}

type OIDCConfig struct {
	Issuer       string   `json:"issuer" yaml:"issuer"`
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

type OAuth2Config struct {
	IntrospectionURL string `json:"introspection_url" yaml:"introspection_url"`
	ClientID         string `json:"client_id" yaml:"client_id"`
	ClientSecret     string `json:"client_secret" yaml:"client_secret"`
}

type SAMLConfig struct {
	MetadataURL string `json:"metadata_url" yaml:"metadata_url"`
	Cert        string `json:"cert" yaml:"cert"`         // Path to SP Cert
	Key         string `json:"key" yaml:"key"`           // Path to SP Key
	RootURL     string `json:"root_url" yaml:"root_url"` // External URL of the proxy (e.g. https://proxy.example.com)
}

// MultiTenantConfig configures multi-tenancy support
type MultiTenantConfig struct {
	Enabled        bool             `json:"enabled" yaml:"enabled"`                   // Enable multi-tenant mode
	Mode           string           `json:"mode" yaml:"mode"`                         // "request" (default), "namespace", "process"
	TenantHeader   string           `json:"tenant_header" yaml:"tenant_header"`       // HTTP header for tenant ID (default: X-Tenant-ID)
	TenantStore    string           `json:"tenant_store" yaml:"tenant_store"`         // "file", "redis", "postgres", "api"
	TenantStoreURL string           `json:"tenant_store_url" yaml:"tenant_store_url"` // Connection URL for tenant store
	TenantsDir     string           `json:"tenants_dir" yaml:"tenants_dir"`           // Directory for tenant configs (file mode)
	DefaultTenant  string           `json:"default_tenant" yaml:"default_tenant"`     // Default tenant ID if none provided
	Isolation      *IsolationConfig `json:"isolation" yaml:"isolation"`               // Isolation settings
}

// IsolationConfig defines tenant isolation boundaries
type IsolationConfig struct {
	NetworkPolicy   bool           `json:"network_policy" yaml:"network_policy"`       // Enforce network isolation
	ResourceQuotas  *ResourceQuota `json:"resource_quotas" yaml:"resource_quotas"`     // Default resource quotas
	SeparateCAs     bool           `json:"separate_cas" yaml:"separate_cas"`           // Separate MITM CA per tenant
	SeparateRedisDB bool           `json:"separate_redis_db" yaml:"separate_redis_db"` // Use different Redis DB per tenant
}

// ResourceQuota defines per-tenant resource limits
type ResourceQuota struct {
	MaxConnections    int     `json:"max_connections" yaml:"max_connections"`           // Max concurrent connections
	MaxBandwidthMbps  float64 `json:"max_bandwidth_mbps" yaml:"max_bandwidth_mbps"`     // Max bandwidth in Mbps
	MaxRequestsPerSec int     `json:"max_requests_per_sec" yaml:"max_requests_per_sec"` // Rate limit
}

// TenantConfig represents a single tenant's configuration
type TenantConfig struct {
	ID             string            `json:"id" yaml:"id"`
	Name           string            `json:"name" yaml:"name"`
	Enabled        bool              `json:"enabled" yaml:"enabled"`
	Policies       []string          `json:"policies" yaml:"policies"` // Policy IDs to apply
	AllowedDomains []string          `json:"allowed_domains" yaml:"allowed_domains"`
	BlockedDomains []string          `json:"blocked_domains" yaml:"blocked_domains"`
	EnableWAF      bool              `json:"enable_waf" yaml:"enable_waf"`
	EnableDLP      bool              `json:"enable_dlp" yaml:"enable_dlp"`
	DLPPatterns    []string          `json:"dlp_patterns" yaml:"dlp_patterns"`
	ThreatLevel    string            `json:"threat_level" yaml:"threat_level"` // "low", "medium", "high", "paranoid"
	Auth           *AuthConfig       `json:"auth" yaml:"auth"`                 // Tenant-specific auth
	ResourceQuota  *ResourceQuota    `json:"resource_quota" yaml:"resource_quota"`
	Metadata       map[string]string `json:"metadata" yaml:"metadata"` // Custom metadata
}

// NewConfig returns a default configuration
func NewConfig() *Config {
	return &Config{
		Addr:       ":8080",
		SocksAddr:  ":1080",
		MirrorAddr: "", // Disabled by default
		CaCert:     "", // Empty means generate/use default
		CaKey:      "",
		ApiAddr:    ":9090",
		ApiSecret:  "changeme",
		Auth: &AuthConfig{
			Mechanism: "none",
		},
		MultiTenant: &MultiTenantConfig{
			Enabled:       false, // Disabled by default
			Mode:          "request",
			TenantHeader:  "X-Tenant-ID",
			TenantStore:   "file",
			TenantsDir:    "./tenants",
			DefaultTenant: "default",
			Isolation: &IsolationConfig{
				NetworkPolicy:   false,
				SeparateCAs:     false,
				SeparateRedisDB: true,
				ResourceQuotas: &ResourceQuota{
					MaxConnections:    1000,
					MaxBandwidthMbps:  100,
					MaxRequestsPerSec: 1000,
				},
			},
		},
		Peering: &PeeringConfig{
			Enabled:   false,
			ICPPort:   3130,
			HTCPPort:  4827,
			Algorithm: "carp",
		},
		Reputation: &ReputationConfig{
			Enabled:  false,
			URL:      "http://localhost:8080",
			Timeout:  500, // 500ms default
			FailOpen: true,
		},
		DarkAPI: &DarkAPIConfig{
			ReportStats: true,
		},
	}
}

// Load reads configuration from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := NewConfig() // Start with defaults

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported configuration format: " + ext)
	}

	if err := cfg.LoadEnv(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadEnv overrides configuration from environment variables
func (c *Config) LoadEnv() error {
	if v := os.Getenv("ADS_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("ADS_SOCKS_ADDR"); v != "" {
		c.SocksAddr = v
	}
	if v := os.Getenv("ADS_MIRROR_ADDR"); v != "" {
		c.MirrorAddr = v
	}
	if v := os.Getenv("ADS_API_ADDR"); v != "" {
		c.ApiAddr = v
	}
	if v := os.Getenv("ADS_GRPC_ADDR"); v != "" {
		c.GrpcAddr = v
	}
	if v := os.Getenv("ADS_RTMP_ADDR"); v != "" {
		c.RtmpAddr = v
	}
	if v := os.Getenv("ADS_RTMP_TARGET"); v != "" {
		c.RtmpTarget = v
	}
	if v := os.Getenv("ADS_RTSP_ADDR"); v != "" {
		c.RtspAddr = v
	}
	if v := os.Getenv("ADS_RTSP_TARGET"); v != "" {
		c.RtspTarget = v
	}
	if v := os.Getenv("ADS_FTP_ADDR"); v != "" {
		c.FtpAddr = v
	}
	if v := os.Getenv("ADS_FTP_TARGET"); v != "" {
		c.FtpTarget = v
	}
	if v := os.Getenv("ADS_SSH_ADDR"); v != "" {
		c.SshAddr = v
	}
	if v := os.Getenv("ADS_SSH_TARGET"); v != "" {
		c.SshTarget = v
	}
	if v := os.Getenv("ADS_ENABLE_REUSEPORT"); v == "true" {
		c.EnableReusePort = true
	}
	if v := os.Getenv("ADS_ENABLE_QUIC"); v == "true" {
		c.EnableQUIC = true
	}
	if v := os.Getenv("ADS_THREAT_FILE"); v != "" {
		c.ThreatFile = v
	}
	if v := os.Getenv("ADS_THREAT_SOURCES"); v != "" {
		c.ThreatSources = strings.Split(v, ",")
	}
	if v := os.Getenv("ADS_GEOIP_DB"); v != "" {
		c.GeoIPDBFile = v
	}
	// Note: Comma separated lists for GeoIP Allow/Block in env vars could be added
	if v := os.Getenv("ADS_GEOIP_ALLOW"); v != "" {
		c.GeoIPAllow = strings.Split(v, ",")
	}

	// DNS Science Env Vars
	if c.DNSScience == nil {
		c.DNSScience = &DNSScienceConfig{}
	}
	if v := os.Getenv("ADS_DNSSCIENCE_ENABLED"); v == "true" {
		c.DNSScience.Enabled = true
	}
	if v := os.Getenv("ADS_DNSSCIENCE_API_KEY"); v != "" {
		c.DNSScience.APIKey = v
	}
	if v := os.Getenv("ADS_DNSSCIENCE_FEED_URL"); v != "" {
		c.DNSScience.FeedURL = v
	}
	if v := os.Getenv("ADS_DNSSCIENCE_REFRESH_INTERVAL"); v != "" {
		c.DNSScience.RefreshInterval = v
	}
	if v := os.Getenv("ADS_DNSSCIENCE_RPC_ADDR"); v != "" {
		c.DNSScience.RPCAddr = v
	}

	// Redis Env Vars
	if c.Redis == nil {
		c.Redis = &RedisConfig{}
	}
	if v := os.Getenv("ADS_REDIS_ENABLED"); v == "true" {
		c.Redis.Enabled = true
	}
	if v := os.Getenv("ADS_REDIS_ADDR"); v != "" {
		c.Redis.Addr = v
	}
	if v := os.Getenv("ADS_REDIS_PASSWORD"); v != "" {
		c.Redis.Password = v
	}

	// Multi-Tenant Env Vars
	if c.MultiTenant == nil {
		c.MultiTenant = NewConfig().MultiTenant // Use defaults
	}
	if v := os.Getenv("ADS_MULTITENANT_ENABLED"); v == "true" {
		c.MultiTenant.Enabled = true
	}
	if v := os.Getenv("ADS_MULTITENANT_MODE"); v != "" {
		c.MultiTenant.Mode = v
	}
	if v := os.Getenv("ADS_MULTITENANT_HEADER"); v != "" {
		c.MultiTenant.TenantHeader = v
	}
	if v := os.Getenv("ADS_MULTITENANT_STORE"); v != "" {
		c.MultiTenant.TenantStore = v
	}
	if v := os.Getenv("ADS_MULTITENANT_STORE_URL"); v != "" {
		c.MultiTenant.TenantStoreURL = v
	}
	if v := os.Getenv("ADS_MULTITENANT_TENANTS_DIR"); v != "" {
		c.MultiTenant.TenantsDir = v
	}
	if v := os.Getenv("ADS_MULTITENANT_DEFAULT_TENANT"); v != "" {
		c.MultiTenant.DefaultTenant = v
	}

	// Policy File
	if v := os.Getenv("ADS_POLICY_FILE"); v != "" {
		c.PolicyFile = v
	}

	// Peering Env Vars
	if c.Peering == nil {
		c.Peering = NewConfig().Peering
	}
	if v := os.Getenv("ADS_PEERING_ENABLED"); v == "true" {
		c.Peering.Enabled = true
	}
	if v := os.Getenv("ADS_PEERING_PEERS"); v != "" {
		c.Peering.Peers = strings.Split(v, ",")
	}

	// DarkAPI Env Vars
	if c.DarkAPI == nil {
		c.DarkAPI = &DarkAPIConfig{ReportStats: true}
	}
	if v := os.Getenv("ADS_DARKAPI_KEY"); v != "" {
		c.DarkAPI.APIKey = v
	}

	// Reputation Env Vars
	if c.Reputation == nil {
		c.Reputation = NewConfig().Reputation
	}
	if v := os.Getenv("ADS_REPUTATION_ENABLED"); v == "true" {
		c.Reputation.Enabled = true
	}
	if v := os.Getenv("ADS_REPUTATION_URL"); v != "" {
		c.Reputation.URL = v
	}

	return nil
}

// Validate checks configuration for errors
func (c *Config) Validate() error {
	if c.Addr == "" {
		return errors.New("addr is required")
	}
	if c.Auth != nil {
		switch c.Auth.Mechanism {
		case "kerberos":
			if c.Auth.KRB5Keytab == "" {
				return errors.New("kerberos auth requires krb5_keytab")
			}
		case "ntlm":
			if len(c.Auth.Users) == 0 {
				// Warn? Or Fail? For now, we prefer explicit users for NTLM if local.
				// But maybe they want to plug in other things later.
				// Let's just ensure mechanism is valid.
			}
		case "none", "basic":
		case "oidc":
			if c.Auth.OIDC == nil || c.Auth.OIDC.Issuer == "" || c.Auth.OIDC.ClientID == "" {
				return errors.New("oidc auth requires issuer and client_id")
			}
		case "oauth2":
			if c.Auth.OAuth2 == nil || c.Auth.OAuth2.IntrospectionURL == "" {
				return errors.New("oauth2 auth requires introspection_url")
			}
		case "saml":
			if c.Auth.SAML == nil || c.Auth.SAML.MetadataURL == "" || c.Auth.SAML.RootURL == "" {
				return errors.New("saml auth requires metadata_url and root_url")
			}
		default:
			return errors.New("unsupported auth mechanism: " + c.Auth.Mechanism)
		}
	}
	if c.RtmpAddr != "" && c.RtmpTarget == "" {
		return errors.New("rtmp_target is required when rtmp_addr is set")
	}
	if c.RtspAddr != "" && c.RtspTarget == "" {
		return errors.New("rtsp_target is required when rtsp_addr is set")
	}
	if c.FtpAddr != "" && c.FtpTarget == "" {
		return errors.New("ftp_target is required when ftp_addr is set")
	}
	if c.SshAddr != "" && c.SshTarget == "" {
		return errors.New("ssh_target is required when ssh_addr is set")
	}
	return nil
}
