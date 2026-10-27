// ads-dev is the developer companion to the proxy's opt-in toolkit.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"ads-httpproxy/internal/devtools"
	"github.com/quic-go/quic-go/http3"
)

type headers []string

func (h *headers) String() string { return strings.Join(*h, ", ") }
func (h *headers) Set(value string) error {
	if !strings.Contains(value, ":") {
		return fmt.Errorf("header must be Name: Value")
	}
	*h = append(*h, value)
	return nil
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, output io.Writer) error { return runWithInput(args, os.Stdin, output) }
func runWithInput(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ads-dev <request|replay|captures|clear|rules|apply-rules|decode|encode> [flags]")
	}
	command := args[0]
	if command == "decode" || command == "encode" {
		return runCodec(command, args[1:], input, output)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(output)
	api := fs.String("api", "http://localhost:9090", "Management API URL")
	secret := fs.String("secret", os.Getenv("ADS_API_SECRET"), "Management API key")
	user := fs.String("user", "", "Management API user")
	password := fs.String("password", "", "Management API password")
	proxy := fs.String("proxy", "http://localhost:8080", "Forward proxy URL; empty for direct requests")
	target := fs.String("url", "", "Request URL or replay URL override")
	decode := fs.String("decode", "", "Decode response body: http or a comma-separated encoding chain")
	method := fs.String("method", "GET", "Request method; optional exact method filter for captures")
	format := fs.String("format", "json", "Capture format: json or har")
	host := fs.String("host", "", "Capture host filter (exact authority including port)")
	status := fs.String("status", "", "Capture HTTP status filter; 0 for failures")
	since := fs.String("since", "", "Capture start time lower bound (RFC3339)")
	limit := fs.Int("limit", 0, "Maximum latest matching captures")
	data := fs.String("data", "", "Request body")
	file := fs.String("file", "", "Rule file: JSON object containing rules array")
	id := fs.Uint64("id", 0, "Captured exchange ID to replay")
	h3 := fs.Bool("http3", false, "Use HTTP/3 directly to the URL (requires -proxy '')")
	ca := fs.String("ca", "", "PEM trust bundle for target/proxy TLS")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	maxResponse := fs.Int64("max-response-bytes", 1<<20, "Maximum response body size")
	var hs headers
	fs.Var(&hs, "header", "Request header (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *timeout <= 0 || *maxResponse <= 0 || *maxResponse > 64<<20 {
		return fmt.Errorf("timeout must be positive; max-response-bytes must be between 1 and 67108864")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	management := func(method, path string, body io.Reader) (*http.Response, error) {
		base, err := url.Parse(*api)
		if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
			return nil, fmt.Errorf("invalid API URL")
		}
		endpoint, err := url.Parse(path)
		if err != nil {
			return nil, err
		}
		base.Path = strings.TrimRight(base.Path, "/") + endpoint.Path
		base.RawQuery = endpoint.RawQuery
		base.Fragment = ""
		req, err := http.NewRequestWithContext(ctx, method, base.String(), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-Key", *secret)
		if *user != "" {
			req.SetBasicAuth(*user, *password)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{Timeout: *timeout, CheckRedirect: noRedirect}).Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			defer resp.Body.Close()
			message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("API returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
		}
		return resp, nil
	}
	var req *http.Request
	var err error
	switch command {
	case "captures", "clear", "rules", "apply-rules":
		path := "/api/devtools/exchanges"
		verb := http.MethodGet
		var body io.Reader
		if command == "captures" {
			if *format != "json" && *format != "har" {
				return fmt.Errorf("format must be json or har")
			}
			if *limit < 0 || *limit > 10000 {
				return fmt.Errorf("limit must be between 0 and 10000")
			}
			q := url.Values{"format": {*format}}
			if *host != "" {
				q.Set("host", *host)
			}
			if *status != "" {
				q.Set("status", *status)
			}
			if *since != "" {
				q.Set("since", *since)
			}
			if *limit > 0 {
				q.Set("limit", strconv.Itoa(*limit))
			}
			fs.Visit(func(f *flag.Flag) {
				if f.Name == "method" {
					q.Set("method", *method)
				}
			})
			path += "?" + q.Encode()
		}
		if command == "clear" {
			verb = http.MethodDelete
		}
		if command == "rules" || command == "apply-rules" {
			path = "/api/devtools/rules"
		}
		if command == "apply-rules" {
			if *file == "" {
				return fmt.Errorf("apply-rules requires -file")
			}
			content, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			body = strings.NewReader(string(content))
			verb = http.MethodPut
		}
		resp, err := management(verb, path, body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		content, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		if err != nil {
			return err
		}
		if len(content) > 32<<20 {
			return fmt.Errorf("management response exceeds 32 MiB; use captures -limit to narrow results")
		}
		_, err = output.Write(content)
		return err
	case "replay":
		if *id == 0 {
			return fmt.Errorf("replay requires -id")
		}
		resp, err := management(http.MethodGet, "/api/devtools/exchanges", nil)
		if err != nil {
			return err
		}
		var result struct {
			Exchanges []devtools.Exchange `json:"exchanges"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return decodeErr
		}
		found := false
		for _, e := range result.Exchanges {
			if e.ID == *id {
				req, err = devtools.RequestFromExchange(ctx, e, *target)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("capture %s not found", strconv.FormatUint(*id, 10))
		}
		if err != nil {
			return err
		}
	case "request":
		if *target == "" {
			return fmt.Errorf("request requires -url")
		}
		req, err = http.NewRequestWithContext(ctx, *method, *target, strings.NewReader(*data))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	if req.URL.Host == "" || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return fmt.Errorf("request URL must use http or https")
	}
	for _, h := range hs {
		key, value, _ := strings.Cut(h, ":")
		req.Header.Add(strings.TrimSpace(key), strings.TrimSpace(value))
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	var transport http.RoundTripper
	if *h3 {
		if *proxy != "" {
			return fmt.Errorf("-http3 uses a direct HTTP/3 connection; pass -proxy '' and point -url at the proxy's gateway")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("HTTP/3 requires an https URL")
		}
		tr := &http3.Transport{TLSClientConfig: tlsConfig}
		defer tr.Close()
		transport = tr
	} else {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		tr.Proxy = nil
		if *proxy != "" {
			p, err := url.Parse(*proxy)
			if err != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https") {
				return fmt.Errorf("invalid proxy URL")
			}
			tr.Proxy = http.ProxyURL(p)
		}
		defer tr.CloseIdleConnections()
		transport = tr
	}
	start := time.Now()
	resp, err := (&http.Client{Transport: transport, Timeout: *timeout, CheckRedirect: noRedirect}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(io.LimitReader(resp.Body, *maxResponse+1))
	if err != nil {
		return err
	}
	truncated := int64(len(content)) > *maxResponse
	if truncated {
		content = content[:*maxResponse]
	}
	if *decode != "" {
		if truncated {
			return fmt.Errorf("cannot decode a truncated response; increase -max-response-bytes")
		}
		for _, name := range strings.Split(*decode, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "http" {
				content, err = decodeEntity(content, resp.Header, *maxResponse)
			} else {
				content, err = codec("decode", name, content, *maxResponse, false)
			}
			if err != nil {
				return fmt.Errorf("decode response %s: %w", name, err)
			}
			if int64(len(content)) > *maxResponse {
				return fmt.Errorf("decoded response exceeds max-response-bytes")
			}
		}
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{"status": resp.StatusCode, "protocol": resp.Proto, "headers": resp.Header, "body": strings.ToValidUTF8(string(content), "�"), "truncated": truncated, "duration_ms": float64(time.Since(start).Microseconds()) / 1000})
}
func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
