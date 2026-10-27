package main

import (
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/policy"
	"ads-httpproxy/pkg/logging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestEmittedPolicyExecutesSupportedSquidSemantics(t *testing.T) {
	logging.Logger = zap.NewNop()
	dir := filepath.Join(t.TempDir(), "output")
	require.NoError(t, run([]string{"-input", "testdata/supported.conf", "-output", dir}, io.Discard))
	engine, err := policy.NewEngine()
	require.NoError(t, err)
	require.NoError(t, engine.LoadFromFile(filepath.Join(dir, "policy.yaml")))
	cases := []struct {
		name, method, url, remote string
		allow                     bool
	}{
		{"ipv4 CIDR", "GET", "http://example.com/", "10.3.2.1:1234", true},
		{"IPv6 CIDR", "HEAD", "https://sub.example.com/", "[2001:db8::abcd]:1234", true},
		{"repeated ACL exact IP", "GET", "http://exact.test:8005/", "192.168.1.4:1234", true},
		{"outside CIDR", "GET", "http://example.com/", "11.0.0.1:1234", false},
		{"outside IPv6 CIDR", "GET", "http://example.com/", "[2001:db9::1]:1234", false},
		{"not string prefix", "GET", "http://evil-example.com/", "10.0.0.1:1234", false},
		{"exact excludes subdomain", "GET", "http://sub.exact.test/", "10.0.0.1:1234", false},
		{"port range lower", "GET", "http://example.com:8000/", "10.0.0.1:1234", true},
		{"port range upper", "GET", "http://example.com:8010/", "10.0.0.1:1234", true},
		{"port range outside", "GET", "http://example.com:8011/", "10.0.0.1:1234", false},
		{"AND requires method", "POST", "http://example.com/", "10.0.0.1:1234", false},
		{"CONNECT TLS", "CONNECT", "http://example.com:443", "10.0.0.1:1234", true},
		{"CONNECT unsafe port", "CONNECT", "http://example.com:80", "10.0.0.1:1234", false},
		{"DNS-free IP", "GET", "http://192.0.2.1/", "10.0.0.1:1234", false},
		{"host case", "GET", "http://EXAMPLE.COM/", "10.0.0.1:1234", true},
		{"domain root dot", "GET", "http://example.com./", "10.0.0.1:1234", true},
		{"IPv4 mapped peer", "GET", "http://example.com/", "[::ffff:10.0.0.1]:1234", true},
	}
	t.Run("Host header cannot change destination ACL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://attacker.test/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Host = "example.com"
		allowed, _, _, _ := engine.Evaluate(context.Background(), policy.NewEvalContext(req, "", ""))
		require.False(t, allowed)
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			req.RemoteAddr = tc.remote
			if tc.method == "CONNECT" {
				u, err := url.Parse(tc.url)
				require.NoError(t, err)
				req.URL = &url.URL{Host: u.Host}
				req.Host = u.Host
			}
			ctx := policy.NewEvalContext(req, "", "")
			allowed, matched, _, reason := engine.Evaluate(context.Background(), ctx)
			require.True(t, matched, reason)
			require.Equal(t, tc.allow, allowed, reason)
		})
	}
	// Preserve ordered first match: the final deny must not override earlier allows.
	cfgData, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	cfg := config.NewConfig()
	require.NoError(t, yaml.Unmarshal(cfgData, cfg))
	require.NoError(t, cfg.Validate())
	require.Equal(t, "127.0.0.1:3128", cfg.Addr)
	require.Equal(t, "tunnel", cfg.ConnectMode)
	require.Equal(t, filepath.Join(dir, "policy.yaml"), cfg.PolicyFile)
	for _, addr := range []string{cfg.ApiAddr, cfg.SocksAddr, cfg.GrpcAddr, cfg.MirrorAddr, cfg.FtpAddr, cfg.SshAddr, cfg.RtmpAddr, cfg.RtspAddr} {
		require.Empty(t, addr)
	}
	require.False(t, cfg.EnableQUIC)
	require.False(t, cfg.Features.ReverseProxy)
	require.False(t, cfg.DarkAPI.ReportStats)
	require.True(t, cfg.Access.Enabled)
	require.Equal(t, "block", cfg.Access.DefaultEffect)
	// Same source and same output location produce byte-identical artifacts.
	before, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	require.NoError(t, err)
	require.NoError(t, os.Rename(dir, dir+"-previous"))
	require.NoError(t, run([]string{"-input", "testdata/supported.conf", "-output", dir}, io.Discard))
	after, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	require.NoError(t, err)
	require.Equal(t, before, after)
	cfgAfter, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, cfgData, cfgAfter)
}

func TestInvalidMigrationWritesNothing(t *testing.T) {
	t.Run("unsupported fixture", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "result")
		err := run([]string{"-input", "testdata/unsupported.conf", "-output", out}, io.Discard)
		require.ErrorContains(t, err, "line 2")
		_, err = os.Stat(out)
		require.True(t, os.IsNotExist(err))
	})
	cases := []string{
		"acl a dst 192.0.2.1", "acl a src host.example", "acl a src 10.0.0.0/255.0.0.0", "acl a src 10.0.0.1-10.0.0.9", "acl a src ::ffff:192.0.2.1",
		"acl a dstdomain .example.com", "acl a dstdomain -n .1", "acl a dstdomain -n *.example.com", "acl a method get", "acl a port 70000", "acl a port 443-80", "acl a src \"ips.txt\"",
		"acl all src 0.0.0.0/0", "acl a method GET\nacl a src 10.0.0.1", "http_access allow unknown", "http_access allow !unknown", "http_access maybe all", "http_access allow !!all", "http_access allow",
		"http_port 127.0.0.1:3129", "http_port 3128 intercept", "cache_dir ufs /cache 100 16 256", "auth_param basic program /bin/helper", "include acl.conf", "ssl_bump allow all", "acl a url_regex .*", "acl a method GET \\\nPOST",
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "squid.conf")
			out := filepath.Join(dir, "result")
			require.NoError(t, os.WriteFile(src, []byte("http_port 127.0.0.1:3128\n"+line+"\nhttp_access deny all\n"), 0600))
			err := run([]string{"-input", src, "-output", out}, io.Discard)
			require.Error(t, err)
			require.Contains(t, err.Error(), "line ")
			_, err = os.Stat(out)
			require.True(t, os.IsNotExist(err))
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestDefaultsListenersAndExistingOutput(t *testing.T) {
	for _, input := range []string{"http_port 127.0.0.1:3128\nhttp_access deny !all", "http_port 127.0.0.1:3128\nhttp_access allow all", "http_access deny all"} {
		_, err := parse(strings.NewReader(input), false)
		require.Error(t, err)
	}
	m, err := parse(strings.NewReader("http_port [::1]:3128"), false)
	require.NoError(t, err)
	require.Equal(t, "block", m.Policies[0].Effect)
	for _, port := range []string{"3128", "0.0.0.0:3128", "[::]:3128", "192.0.2.1:3128"} {
		_, err := parseListener(port, false)
		require.Error(t, err)
		_, err = parseListener(port, true)
		require.NoError(t, err)
	}
	for _, port := range []string{"0", "65536", "localhost:3128", "[fe80::1%lo0]:3128", "bad"} {
		_, err := parseListener(port, true)
		require.Error(t, err)
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(sentinel, []byte("unchanged"), 0600))
	require.Error(t, publish(m, dir))
	got, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(got))
	_, err = parse(strings.NewReader("http_port 127.0.0.1:3128\n"+strings.Repeat("#", 70<<10)), false)
	require.Error(t, err)
}
