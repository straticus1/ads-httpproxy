package config

// Config needs to be loaded from json/yaml later.
type Config struct {
	Addr           string   `json:"addr"`
	SocksAddr      string   `json:"socks_addr"`
	MirrorAddr     string   `json:"mirror_addr"`
	CaCert         string   `json:"ca_cert"`
	CaKey          string   `json:"ca_key"`
	ApiAddr        string   `json:"api_addr"`
	ApiSecret      string   `json:"api_secret"`
	BandwidthLimit float64  `json:"bandwidth_limit"` // Bytes per second
	IcapUrl        string   `json:"icap_url"`
	DlpPatterns    []string `json:"dlp_patterns"`
	ScriptFile     string   `json:"script_file"`
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
	}
}
