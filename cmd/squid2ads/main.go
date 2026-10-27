// squid2ads migrates an explicitly supported Squid access-control subset.
package main

import (
	"ads-httpproxy/internal/policy"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "squid2ads:", err)
		os.Exit(1)
	}
}
func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("squid2ads", flag.ContinueOnError)
	input := flags.String("input", "squid.conf", "Squid configuration to validate and migrate")
	output := flags.String("output", "ads-migrated", "New output directory (must not exist)")
	public := flags.Bool("allow-non-loopback", false, "Explicitly preserve a non-loopback/wildcard HTTP listener")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := parse(f, *public)
	if err != nil {
		return fmt.Errorf("%s: %w", *input, err)
	}
	dir, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err := publish(m, dir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Migrated %d access rules to %s; review docs/squid-compatibility.md before deployment.\n", len(m.Policies), dir)
	return nil
}

// Publish a complete directory, never an incomplete config/policy pair. Reject
// existing destinations so a failed migration cannot modify a running config.
func publish(m *migration, dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("output directory already exists: %s", dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	policies, err := yaml.Marshal(struct {
		Policies []emittedPolicy `yaml:"policies"`
	}{m.Policies})
	if err != nil {
		return err
	}
	// Absolute policy path makes invocation independent of the server's cwd.
	cfg, err := yaml.Marshal(map[string]any{
		"addr": m.Listener, "policy_file": filepath.Join(dir, "policy.yaml"),
		"connect_mode": "tunnel",
		"socks_addr":   "", "api_addr": "", "grpc_addr": "", "mirror_addr": "",
		"rtmp_addr": "", "rtsp_addr": "", "ftp_addr": "", "ssh_addr": "",
		"enable_quic": false, "enable_reuseport": false,
		"features": map[string]bool{"forward_proxy": true, "reverse_proxy": false, "browser_id": false, "masque": false},
		"auth":     map[string]any{"mechanism": "none", "allow_unauthenticated": true},
		"access":   map[string]any{"enabled": true, "default_effect": "block"},
		"dark_api": map[string]bool{"report_stats": false},
	})
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".squid2ads-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, f := range []struct {
		name string
		data []byte
	}{{"policy.yaml", policies}, {"config.yaml", cfg}} {
		if err := os.WriteFile(filepath.Join(stage, f.name), f.data, 0600); err != nil {
			return err
		}
	}
	engine, err := policy.NewEngine()
	if err != nil {
		return err
	}
	if err := engine.LoadFromFile(filepath.Join(stage, "policy.yaml")); err != nil {
		return fmt.Errorf("generated policy validation: %w", err)
	}
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("output appeared during migration: %s", dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(stage, dir)
}
