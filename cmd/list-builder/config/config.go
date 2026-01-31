package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the list-builder service
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Builder  BuilderConfig  `yaml:"builder"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type BuilderConfig struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	Lists           []ListConfig  `yaml:"lists"`
}

type ListConfig struct {
	Name    string   `yaml:"name"`
	Sources []string `yaml:"sources"` // URLs or file paths
	Type    string   `yaml:"type"`    // "ip", "cidr", "domain"
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Defaults
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Builder.RefreshInterval == 0 {
		cfg.Builder.RefreshInterval = 1 * time.Hour
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	return cfg, nil
}
