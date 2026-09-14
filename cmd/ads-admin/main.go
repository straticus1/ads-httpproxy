package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"ads-httpproxy/internal/config"
	"gopkg.in/yaml.v3"
)

type options struct {
	API      string        `json:"api" yaml:"api"`
	Secret   string        `json:"secret" yaml:"secret"`
	User     string        `json:"user" yaml:"user"`
	Password string        `json:"password" yaml:"password"`
	Format   string        `json:"format" yaml:"format"`
	Timeout  time.Duration `json:"-" yaml:"-"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run keeps flags scoped to each invocation, including interactive and batch commands.
func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ads-admin <status|stats|metrics|connections|config|plugins|load|reload-plugin|unload|validate|interactive|batch|completion> [flags]")
	}
	command := args[0]
	opts := options{API: "http://localhost:9090", Secret: os.Getenv("ADS_API_SECRET"), Format: "json", Timeout: 30 * time.Second}
	// Read defaults before parsing so explicit flags always win.
	for i, arg := range args[1:] {
		path := ""
		if strings.HasPrefix(arg, "-cli-config=") || strings.HasPrefix(arg, "--cli-config=") {
			path = strings.SplitN(arg, "=", 2)[1]
		}
		if (arg == "-cli-config" || arg == "--cli-config") && i+2 < len(args) {
			path = args[i+2]
		}
		if path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := yaml.Unmarshal(data, &opts); err != nil {
				return fmt.Errorf("admin configuration: %w", err)
			}
		}
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&opts.API, "api", opts.API, "Management API URL")
	fs.StringVar(&opts.Secret, "secret", opts.Secret, "API key (defaults to ADS_API_SECRET)")
	fs.StringVar(&opts.User, "user", opts.User, "API Basic authentication user")
	fs.StringVar(&opts.Password, "password", opts.Password, "API Basic authentication password")
	fs.StringVar(&opts.Format, "format", opts.Format, "Output format: json, yaml, table")
	fs.DurationVar(&opts.Timeout, "timeout", opts.Timeout, "HTTP request timeout")
	fs.String("cli-config", "", "Admin defaults file (JSON or YAML)")
	path := fs.String("config", "config.yaml", "Proxy configuration to validate")
	pluginPath := fs.String("path", "", "Plugin shared library path")
	name := fs.String("name", "", "Plugin name")
	file := fs.String("file", "", "Batch file: JSON array of command argument arrays")
	shell := fs.String("shell", "bash", "Completion shell: bash or zsh")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if opts.Format != "json" && opts.Format != "yaml" && opts.Format != "table" {
		return fmt.Errorf("unsupported output format: %s", opts.Format)
	}
	switch command {
	case "validate":
		if _, err := config.Load(*path); err != nil {
			return err
		}
		_, err := fmt.Fprintln(output, "Configuration valid")
		return err
	case "reload":
		return fmt.Errorf("live configuration reload is disabled by the server; validate the file and restart the service")
	case "completion":
		switch *shell {
		case "bash":
			_, err := fmt.Fprintln(output, `complete -W 'status stats metrics connections config plugins load reload-plugin unload validate interactive batch completion' ads-admin`)
			return err
		case "zsh":
			_, err := fmt.Fprintln(output, "#compdef ads-admin\n_arguments '1:command:(status stats metrics connections config plugins load reload-plugin unload validate interactive batch completion)' '*:argument:'")
			return err
		default:
			return fmt.Errorf("unsupported shell: %s", *shell)
		}
	case "interactive", "batch":
		defaults := []string{"-api", opts.API, "-secret", opts.Secret, "-user", opts.User, "-password", opts.Password, "-format", opts.Format, "-timeout", opts.Timeout.String()}
		execute := func(sub []string) error {
			if len(sub) == 0 {
				return nil
			}
			if sub[0] == "interactive" || sub[0] == "batch" {
				return fmt.Errorf("nested interactive/batch commands are not supported")
			}
			return run(append(append([]string{sub[0]}, defaults...), sub[1:]...), input, output)
		}
		if command == "batch" {
			if *file == "" {
				return fmt.Errorf("batch requires -file")
			}
			data, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			var commands [][]string
			if err := json.Unmarshal(data, &commands); err != nil {
				return err
			}
			for i, sub := range commands {
				if err := execute(sub); err != nil {
					return fmt.Errorf("batch command %d: %w", i+1, err)
				}
			}
			return nil
		}
		scanner := bufio.NewScanner(input)
		for {
			fmt.Fprint(output, "ads-admin> ")
			if !scanner.Scan() {
				return scanner.Err()
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "exit" || line == "quit" {
				return nil
			}
			var sub []string
			if strings.HasPrefix(line, "[") {
				if err := json.Unmarshal([]byte(line), &sub); err != nil {
					fmt.Fprintln(output, err)
					continue
				}
			} else {
				sub = strings.Fields(line)
			}
			if err := execute(sub); err != nil {
				fmt.Fprintln(output, err)
			}
		}
	}
	endpoints := map[string]string{"status": "/healthz", "stats": "/stats", "metrics": "/metrics", "connections": "/connections", "config": "/config", "plugins": "/plugins", "load": "/plugins/load", "reload-plugin": "/plugins/reload", "unload": "/plugins/unload"}
	endpoint, ok := endpoints[command]
	if !ok {
		return fmt.Errorf("unknown command: %s", command)
	}
	base, err := url.Parse(opts.API)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return fmt.Errorf("invalid API URL: %s", opts.API)
	}
	base.Path = strings.TrimRight(base.Path, "/") + endpoint
	base.RawQuery = ""
	base.Fragment = ""
	method := http.MethodGet
	var body io.Reader
	if command == "load" || command == "reload-plugin" || command == "unload" {
		payload := map[string]string{}
		if command == "load" || command == "reload-plugin" {
			if *pluginPath == "" {
				return fmt.Errorf("load requires -path")
			}
			payload["path"] = *pluginPath
		} else {
			if *name == "" {
				return fmt.Errorf("unload requires -name")
			}
			payload["name"] = *name
		}
		data, _ := json.Marshal(payload)
		body = strings.NewReader(string(data))
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, base.String(), body)
	if err != nil {
		return err
	}
	if opts.Secret != "" {
		req.Header.Set("X-API-Key", opts.Secret)
	}
	if opts.User != "" {
		req.SetBasicAuth(opts.User, opts.Password)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: opts.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("API returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if command == "metrics" {
		_, err := io.Copy(output, resp.Body)
		return err
	}
	var value any
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid API response: %w", err)
	}
	switch opts.Format {
	case "yaml":
		return yaml.NewEncoder(output).Encode(normalizeNumbers(value))
	case "table":
		return writeTable(output, "", value)
	default:
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
}

func normalizeNumbers(value any) any {
	switch v := value.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		n, _ := v.Float64()
		return n
	case map[string]any:
		for key, item := range v {
			v[key] = normalizeNumbers(item)
		}
	case []any:
		for i, item := range v {
			v[i] = normalizeNumbers(item)
		}
	}
	return value
}

func writeTable(w io.Writer, prefix string, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			label := key
			if prefix != "" {
				label = prefix + "." + key
			}
			if err := writeTable(w, label, v[key]); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := writeTable(w, fmt.Sprintf("%s[%d]", prefix, i), item); err != nil {
				return err
			}
		}
	default:
		_, err := fmt.Fprintf(w, "%s\t%v\n", prefix, v)
		return err
	}
	return nil
}
