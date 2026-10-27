// Package headerpolicy owns the final HTTP header boundary around policy scripts.
package headerpolicy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const maxBytes = 32768
const maxFields = 128

type Operations struct {
	Set    map[string][]string `yaml:"set" json:"set"`
	Append map[string][]string `yaml:"append" json:"append"`
	Remove []string            `yaml:"remove" json:"remove"`
}
type Profile struct {
	Forwarded string     `yaml:"forwarded" json:"forwarded"`
	Request   Operations `yaml:"request" json:"request"`
	Response  Operations `yaml:"response" json:"response"`
}
type Config struct {
	Forward           Profile  `yaml:"forward" json:"forward"`
	Gateway           Profile  `yaml:"gateway" json:"gateway"`
	TrustedProxies    []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	ViaPseudonym      string   `yaml:"via_pseudonym" json:"via_pseudonym"`
	IdentityUpstreams []string `yaml:"identity_upstreams" json:"identity_upstreams"`
}
type Policy struct {
	config  Config
	trusted []netip.Prefix
}

// Snapshot contains private, copied ingress metadata; it must be captured before rewrites.
type Snapshot struct {
	gateway                         bool
	authority, proto, version, peer string
	forwarding                      http.Header
	via                             []string
	hopRemove                       []string
	websocket                       bool
}

func Protected(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "x-forwarded-") || strings.HasPrefix(n, "x-authenticated-") || strings.HasPrefix(n, "x-auth-request-") {
		return true
	}
	switch n {
	case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "content-length", "te", "trailer", "upgrade", "via", "forwarded", "x-real-ip", "proxy-authorization", "proxy-authenticate", "x-remote-user", "remote-user", "x-auth-user", "x-auth-email", "x-auth-groups", "x-tenant-id", "x-device-id", "x-device-compliant", "x-groups":
		return true
	}
	return false
}
func validValue(v string) bool {
	if !httpguts.ValidHeaderFieldValue(v) {
		return false
	}
	for _, c := range []byte(v) {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func ValidateOperation(name string, values []string, remove bool) error {
	if !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("invalid header name %q", name)
	}
	if Protected(name) {
		return fmt.Errorf("header %q is proxy-owned", name)
	}
	if !remove && (strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie")) {
		return fmt.Errorf("cannot inject credential header %q", name)
	}
	size := len(name)
	if len(values) > maxFields {
		return fmt.Errorf("too many values for %q", name)
	}
	for _, v := range values {
		size += len(v)
		if !validValue(v) {
			return fmt.Errorf("invalid value for %q", name)
		}
	}
	if size > maxBytes {
		return fmt.Errorf("header %q exceeds size limit", name)
	}
	return nil
}
func validateOps(o Operations) error {
	seen := map[string]string{}
	size, count := 0, 0
	check := func(name string, values []string, remove bool) error {
		if err := ValidateOperation(name, values, remove); err != nil {
			return err
		}
		lower := strings.ToLower(name)
		if prev, ok := seen[lower]; ok && prev != name {
			return fmt.Errorf("case collision for header %q and %q", prev, name)
		}
		seen[lower] = name
		count += 1 + len(values)
		size += len(name)
		for _, v := range values {
			size += len(v)
		}
		if count > maxFields || size > maxBytes {
			return fmt.Errorf("header operations exceed limits")
		}
		return nil
	}
	for _, m := range []map[string][]string{o.Set, o.Append} {
		for _, k := range sortedKeys(m) {
			if err := check(k, m[k], false); err != nil {
				return err
			}
		}
	}
	for _, k := range o.Remove {
		if err := check(k, nil, true); err != nil {
			return err
		}
	}
	return nil
}
func sortedKeys(m map[string][]string) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// ApplyOperations applies set, append, then remove atomically after validation.
func ApplyOperations(h http.Header, o Operations) error {
	if err := validateOps(o); err != nil {
		return err
	}
	for _, k := range sortedKeys(o.Set) {
		deleteFold(h, k)
		h[http.CanonicalHeaderKey(k)] = append([]string(nil), o.Set[k]...)
	}
	for _, k := range sortedKeys(o.Append) {
		existing := valuesFold(h, k)
		deleteFold(h, k)
		h[http.CanonicalHeaderKey(k)] = existing
		for _, v := range o.Append[k] {
			h.Add(k, v)
		}
	}
	for _, k := range o.Remove {
		deleteFold(h, k)
	}
	return nil
}
func Validate(c *Config) error { _, err := New(c); return err }
func New(c *Config) (*Policy, error) {
	p := &Policy{}
	if c != nil {
		p.config = *c
	}
	if p.config.Forward.Forwarded == "" {
		p.config.Forward.Forwarded = "off"
	}
	if p.config.Gateway.Forwarded == "" {
		p.config.Gateway.Forwarded = "both"
	}
	if p.config.ViaPseudonym == "" {
		p.config.ViaPseudonym = "ads-proxy"
	}
	if len(p.config.ViaPseudonym) > 128 || !httpguts.ValidHeaderFieldName(p.config.ViaPseudonym) {
		return nil, fmt.Errorf("via_pseudonym must be a token")
	}
	for _, profile := range []*Profile{&p.config.Forward, &p.config.Gateway} {
		switch profile.Forwarded {
		case "off", "standard", "legacy", "both":
		default:
			return nil, fmt.Errorf("invalid forwarded mode %q", profile.Forwarded)
		}
		if err := validateOps(profile.Request); err != nil {
			return nil, err
		}
		if err := validateOps(profile.Response); err != nil {
			return nil, err
		}
		profile.Request = cloneOps(profile.Request)
		profile.Response = cloneOps(profile.Response)
	}
	for _, s := range p.config.TrustedProxies {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q", s)
		}
		p.trusted = append(p.trusted, prefix)
	}
	p.config.IdentityUpstreams = append([]string(nil), p.config.IdentityUpstreams...)
	for _, s := range p.config.IdentityUpstreams {
		if s == "" || strings.ContainsAny(s, "/\\@?#* \t\r\n") || !validValue(s) {
			return nil, fmt.Errorf("invalid identity upstream authority %q", s)
		}
	}
	return p, nil
}
func cloneOps(o Operations) Operations {
	clone := func(m map[string][]string) map[string][]string {
		r := make(map[string][]string, len(m))
		for k, v := range m {
			r[k] = append([]string(nil), v...)
		}
		return r
	}
	return Operations{Set: clone(o.Set), Append: clone(o.Append), Remove: append([]string(nil), o.Remove...)}
}
func (p *Policy) Capture(req *http.Request, gateway bool) Snapshot {
	s := Snapshot{gateway: gateway, authority: req.Host, proto: "http", version: protocol(req.ProtoMajor, req.ProtoMinor), forwarding: make(http.Header), websocket: isWebsocket(req.Header)}
	if len(s.authority) > 8192 || !safeChain("X-Forwarded-Host", []string{s.authority}) {
		s.authority = ""
	}
	if req.TLS != nil {
		s.proto = "https"
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	trusted := false
	if err == nil {
		ip = ip.WithZone("").Unmap()
		s.peer = ip.String()
		for _, prefix := range p.trusted {
			if prefix.Contains(ip) {
				trusted = true
				break
			}
		}
	}
	s.via = safeVia(valuesFold(req.Header, "Via"))
	// Some proxy implementations remove Connection before our final transport.
	// Retain its nominations now so their fields cannot survive that cleanup.
	for _, value := range valuesFold(req.Header, "Connection") {
		for _, token := range strings.Split(value, ",") {
			name := strings.TrimSpace(token)
			if httpguts.ValidHeaderFieldName(name) {
				s.hopRemove = append(s.hopRemove, name)
			}
		}
	}
	if trusted {
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			v := valuesFold(req.Header, name)
			if safeChain(name, v) {
				s.forwarding[name] = append([]string(nil), v...)
			}
		}
	}
	return s
}
func protocol(major, minor int) string {
	if major < 1 || major > 3 || minor < 0 || minor > 9 {
		return "1.1"
	}
	return fmt.Sprintf("%d.%d", major, minor)
}
func deleteFold(h http.Header, name string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			delete(h, k)
		}
	}
}
func valuesFold(h http.Header, name string) []string {
	var v []string
	keys := make([]string, 0)
	for k := range h {
		if strings.EqualFold(k, name) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v = append(v, h[k]...)
	}
	return v
}
func isWebsocket(h http.Header) bool {
	if !strings.EqualFold(strings.TrimSpace(h.Get("Upgrade")), "websocket") {
		return false
	}
	for _, v := range valuesFold(h, "Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}
func sanitize(h http.Header, websocket bool) {
	for _, v := range valuesFold(h, "Connection") {
		for _, token := range strings.Split(v, ",") {
			deleteFold(h, strings.TrimSpace(token))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Authenticate", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		deleteFold(h, k)
	}
	for k := range h {
		n := strings.ToLower(k)
		if strings.HasPrefix(n, "x-forwarded-") || strings.HasPrefix(n, "x-authenticated-") || strings.HasPrefix(n, "x-auth-request-") {
			delete(h, k)
		}
	}
	for _, k := range []string{"Forwarded", "X-Real-IP", "X-Remote-User", "Remote-User", "X-Auth-User", "X-Auth-Email", "X-Auth-Groups", "X-Tenant-ID", "X-Device-ID", "X-Device-Compliant", "X-Groups"} {
		deleteFold(h, k)
	}
	if websocket {
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", "websocket")
	}
}
func (p *Policy) ApplyRequest(req *http.Request, s *Snapshot, identity string, mandatoryRemove []string, overrides ...Operations) error {
	if s == nil {
		return fmt.Errorf("missing ingress header snapshot")
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	profile := p.config.Forward
	if s.gateway {
		profile = p.config.Gateway
	}
	for _, name := range s.hopRemove {
		deleteFold(req.Header, name)
	}
	sanitize(req.Header, s.websocket)
	if err := applyLayers(req.Header, profile.Request, overrides); err != nil {
		return err
	}
	mode := profile.Forwarded
	if mode != "off" && s.peer != "" {
		if mode == "standard" || mode == "both" {
			parts := append([]string(nil), s.forwarding["Forwarded"]...)
			peer := s.peer
			if strings.Contains(peer, ":") {
				peer = "[" + peer + "]"
			}
			entry := "for=" + strconv.Quote(peer) + ";proto=" + s.proto
			if validValue(s.authority) && s.authority != "" {
				entry += ";host=" + strconv.Quote(s.authority)
			}
			parts = append(parts, entry)
			req.Header.Set("Forwarded", strings.Join(parts, ", "))
		}
		if mode == "legacy" || mode == "both" {
			for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				parts := append([]string(nil), s.forwarding[name]...)
				value := s.peer
				if name == "X-Forwarded-Host" {
					value = s.authority
				}
				if name == "X-Forwarded-Proto" {
					value = s.proto
				}
				if value != "" && validValue(value) && safeChain(name, []string{value}) {
					parts = append(parts, value)
				}
				if len(parts) > 0 {
					req.Header.Set(name, strings.Join(parts, ", "))
				}
			}
		}
	}
	if s.gateway && identity != "" && len(identity) <= 4096 && validValue(identity) && req.URL != nil {
		for _, authority := range p.config.IdentityUpstreams {
			if strings.EqualFold(req.URL.Host, authority) {
				req.Header.Set("X-Authenticated-User", identity)
				break
			}
		}
	}
	deleteFold(req.Header, "Via")
	req.Header["Via"] = append(append([]string(nil), s.via...), s.version+" "+p.config.ViaPseudonym)
	for _, name := range mandatoryRemove {
		deleteFold(req.Header, name)
	}
	if _, ok := req.Header["User-Agent"]; !ok && len(valuesFold(req.Header, "User-Agent")) == 0 {
		req.Header["User-Agent"] = []string{""}
	}
	return nil
}
func (p *Policy) ApplyResponse(resp *http.Response, s *Snapshot, originalVia []string, overrides ...Operations) error {
	if s == nil {
		return fmt.Errorf("missing ingress header snapshot")
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	websocket := s.websocket && resp.StatusCode == http.StatusSwitchingProtocols && isWebsocket(resp.Header)
	sanitize(resp.Header, websocket)
	profile := p.config.Forward
	if s.gateway {
		profile = p.config.Gateway
	}
	if err := applyLayers(resp.Header, profile.Response, overrides); err != nil {
		return err
	}
	deleteFold(resp.Header, "Via")
	resp.Header["Via"] = append(safeVia(originalVia), protocol(resp.ProtoMajor, resp.ProtoMinor)+" "+p.config.ViaPseudonym)
	return nil
}

// A removal in any layer wins over all subsequent additions.
func applyLayers(h http.Header, base Operations, overrides []Operations) error {
	layers := append([]Operations{base}, overrides...)
	for _, layer := range layers {
		if err := validateOps(layer); err != nil {
			return err
		}
	}
	for _, layer := range layers {
		if err := ApplyOperations(h, layer); err != nil {
			return err
		}
	}
	for _, layer := range layers {
		for _, name := range layer.Remove {
			deleteFold(h, name)
		}
	}
	return nil
}

func bounded(values []string) bool {
	size := 0
	if len(values) > 32 {
		return false
	}
	for _, v := range values {
		size += len(v)
		if !validValue(v) {
			return false
		}
	}
	return size <= 8192
}
func safeVia(values []string) []string {
	if !bounded(values) {
		return nil
	}
	for _, v := range values {
		parts, ok := splitVia(v)
		if !ok {
			return nil
		}
		for _, part := range parts {
			if index := strings.IndexByte(part, '('); index >= 0 {
				if index == 0 || part[index-1] != ' ' {
					return nil
				}
				part = strings.TrimSpace(part[:index])
			}
			fields := strings.Fields(part)
			if len(fields) != 2 {
				return nil
			}
			protocolParts := strings.Split(fields[0], "/")
			if len(protocolParts) > 2 {
				return nil
			}
			for _, token := range protocolParts {
				if !httpguts.ValidHeaderFieldName(token) {
					return nil
				}
			}
			if !validReceivedBy(fields[1]) {
				return nil
			}
		}
	}
	return append([]string(nil), values...)
}

// Split only at top-level commas and validate the optional final RFC comment.
// Nesting and total entries are bounded independently of the byte-size limit.
func splitVia(value string) ([]string, bool) {
	var parts []string
	start, depth := 0, 0
	escaped, commentEnded := false, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			continue
		}
		if depth > 0 {
			switch c {
			case '\\':
				escaped = true
			case '(':
				depth++
				if depth > 8 {
					return nil, false
				}
			case ')':
				depth--
				if depth == 0 {
					commentEnded = true
				}
			}
			continue
		}
		if c == ',' {
			parts = append(parts, strings.TrimSpace(value[start:i]))
			if len(parts) >= 128 {
				return nil, false
			}
			start, commentEnded = i+1, false
			continue
		}
		if commentEnded && c != ' ' {
			return nil, false
		}
		switch c {
		case '(':
			depth = 1
		case ')', '\\':
			return nil, false
		}
	}
	if depth != 0 || escaped {
		return nil, false
	}
	return append(parts, strings.TrimSpace(value[start:])), true
}

func validReceivedBy(s string) bool {
	if httpguts.ValidHeaderFieldName(s) {
		return true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return net.ParseIP(s[1:len(s)-1]) != nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	return port != "" && (httpguts.ValidHeaderFieldName(host) || net.ParseIP(host) != nil)
}
func safeChain(name string, values []string) bool {
	if !bounded(values) {
		return false
	}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return false
			}
			switch name {
			case "X-Forwarded-For":
				if _, err := netip.ParseAddr(part); err != nil {
					return false
				}
			case "X-Forwarded-Proto":
				if part != "http" && part != "https" {
					return false
				}
			case "X-Forwarded-Host":
				if strings.ContainsAny(part, " /\\@?#\";") {
					return false
				}
			case "Forwarded":
				for _, pair := range strings.Split(part, ";") {
					kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
					if len(kv) != 2 || !httpguts.ValidHeaderFieldName(kv[0]) {
						return false
					}
					value := kv[1]
					if strings.HasPrefix(value, "\"") {
						unquoted, err := strconv.Unquote(value)
						if err != nil || !validValue(unquoted) {
							return false
						}
					} else if !httpguts.ValidHeaderFieldName(value) {
						return false
					}
				}
			}
		}
	}
	return true
}
