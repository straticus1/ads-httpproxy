package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type emittedPolicy struct {
	ID        string `yaml:"id"`
	Effect    string `yaml:"effect"`
	Condition string `yaml:"condition"`
}
type migration struct {
	Listener string
	Policies []emittedPolicy
}
type acl struct {
	kind  string
	terms []string
}
type accessRule struct {
	line   int
	action string
	names  []string
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
var methodName = regexp.MustCompile(`^[A-Z][A-Z0-9_-]*$`)
var domainName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)

func parse(r io.Reader, allowPublic bool) (*migration, error) {
	m := &migration{}
	acls := map[string]acl{"all": {kind: "builtin", terms: []string{"true"}}}
	var rules []accessRule
	s := bufio.NewScanner(io.LimitReader(r, (4<<20)+1))
	s.Buffer(make([]byte, 4096), 64<<10)
	line, total := 0, 0
	for s.Scan() {
		line++
		total += len(s.Text()) + 1
		fail := func(message string, args ...any) (*migration, error) {
			return nil, fmt.Errorf("line %d: %s", line, fmt.Sprintf(message, args...))
		}
		if total > 4<<20 {
			return fail("configuration exceeds 4 MiB")
		}
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text, _, _ = strings.Cut(text, "#")
		if strings.ContainsAny(text, "\"'\\") {
			return fail("quoted values, escapes and continuations unsupported; use literal inline ACL values")
		}
		p := strings.Fields(text)
		if len(p) == 0 {
			continue
		}
		switch p[0] {
		case "http_port":
			if len(p) != 2 || m.Listener != "" {
				return fail("exactly one http_port with no mode/options is supported")
			}
			listener, err := parseListener(p[1], allowPublic)
			if err != nil {
				return fail("%v", err)
			}
			m.Listener = listener
		case "acl":
			if len(p) < 4 || !identifier.MatchString(p[1]) {
				return fail("expected acl NAME TYPE VALUE... with an ASCII ACL name")
			}
			if p[1] == "all" {
				return fail("built-in ACL all cannot be redefined")
			}
			if old, ok := acls[p[1]]; ok && old.kind != p[2] {
				return fail("ACL %q changes type from %s to %s", p[1], old.kind, p[2])
			}
			terms, err := aclTerms(p[2], p[3:])
			if err != nil {
				return fail("ACL %q: %v", p[1], err)
			}
			a := acls[p[1]]
			a.kind = p[2]
			a.terms = append(a.terms, terms...)
			if len(a.terms) > 256 {
				return fail("ACL %q exceeds 256 values", p[1])
			}
			acls[p[1]] = a
		case "http_access":
			if len(p) < 3 || (p[1] != "allow" && p[1] != "deny") {
				return fail("expected http_access allow|deny [!]ACL...")
			}
			if len(p) > 66 || len(rules) >= 256 {
				return fail("maximum 256 access rules and 64 ACL references per rule")
			}
			for _, name := range p[2:] {
				name = strings.TrimPrefix(name, "!")
				if _, ok := acls[name]; !ok {
					return fail("unknown ACL %q; define it before http_access", name)
				}
			}
			rules = append(rules, accessRule{line, p[1], p[2:]})
		default:
			return fail("unsupported directive %q; migrate it manually (nothing was written)", p[0])
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("line %d: reading configuration: %w", line+1, err)
	}
	if m.Listener == "" {
		return nil, fmt.Errorf("line %d: missing explicit http_port", line+1)
	}
	if len(rules) > 0 {
		last := rules[len(rules)-1]
		if last.action != "deny" || len(last.names) != 1 || last.names[0] != "all" {
			return nil, fmt.Errorf("line %d: final http_access must be 'deny all'; implicit Squid defaults are not migrated", last.line)
		}
	}
	for _, rule := range rules {
		var conditions []string
		for _, ref := range rule.names {
			name := strings.TrimPrefix(ref, "!")
			term := "(" + strings.Join(acls[name].terms, " || ") + ")"
			if strings.HasPrefix(ref, "!") {
				term = "!" + term
			}
			conditions = append(conditions, term)
		}
		effect := "allow"
		if rule.action == "deny" {
			effect = "block"
		}
		m.Policies = append(m.Policies, emittedPolicy{fmt.Sprintf("squid-line-%d", rule.line), effect, strings.Join(conditions, " && ")})
	}
	if len(rules) == 0 {
		m.Policies = []emittedPolicy{{"squid-no-access", "block", "true"}}
	}
	return m, nil
}

func parseListener(value string, allowPublic bool) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Contains(value, ":") {
			return "", fmt.Errorf("invalid http_port %q; use IP:PORT or [IPv6]:PORT", value)
		}
		port = value
		host = ""
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid http_port %q", value)
	}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return "", fmt.Errorf("http_port requires a literal unscoped IP, not a hostname")
		}
		if !ip.IsLoopback() && !allowPublic {
			return "", fmt.Errorf("non-loopback http_port requires -allow-non-loopback after network review")
		}
	} else if !allowPublic {
		return "", fmt.Errorf("wildcard http_port requires -allow-non-loopback, or explicitly choose 127.0.0.1:%d", n)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func aclTerms(kind string, args []string) ([]string, error) {
	var terms []string
	if kind == "dstdomain" {
		if len(args) < 2 || args[0] != "-n" {
			return nil, fmt.Errorf("dstdomain requires explicit -n (reverse DNS unsupported)")
		}
		args = args[1:]
	}
	for _, value := range args {
		switch kind {
		case "src":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				ip, e := netip.ParseAddr(value)
				if e != nil || ip.Zone() != "" {
					return nil, fmt.Errorf("src %q requires literal IP or prefix-length CIDR; ranges/DNS/netmask notation unsupported", value)
				}
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			}
			if prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("IPv4-mapped source prefixes unsupported; use IPv4 CIDR")
			}
			terms = append(terms, fmt.Sprintf("ipInCIDR(client.ip, %s)", strconv.Quote(prefix.Masked().String())))
		case "method":
			if !methodName.MatchString(value) {
				return nil, fmt.Errorf("invalid/unsupported method %q; use uppercase literal method tokens", value)
			}
			terms = append(terms, "request.method == "+strconv.Quote(value))
		case "port":
			lo, hi, rangePort := strings.Cut(value, "-")
			if !rangePort {
				hi = lo
			}
			a, e1 := strconv.Atoi(lo)
			b, e2 := strconv.Atoi(hi)
			if e1 != nil || e2 != nil || a < 1 || b > 65535 || b < a {
				return nil, fmt.Errorf("invalid port %q; expected 1..65535 or inclusive LOW-HIGH", value)
			}
			terms = append(terms, fmt.Sprintf("(request.port >= %d && request.port <= %d)", a, b))
		case "dstdomain":
			domain := strings.ToLower(strings.TrimPrefix(value, "."))
			if len(domain) > 253 || !domainName.MatchString(domain) {
				return nil, fmt.Errorf("unsupported domain %q; use ASCII DNS names (no wildcards)", value)
			}
			labels := strings.Split(domain, ".")
			last := labels[len(labels)-1]
			if !strings.ContainsAny(last, "abcdefghijklmnopqrstuvwxyz") {
				return nil, fmt.Errorf("numeric domain suffix %q unsupported with -n; use DNS names", value)
			}
			for _, label := range labels {
				if len(label) > 63 {
					return nil, fmt.Errorf("domain label exceeds 63 bytes")
				}
			}
			if _, err := netip.ParseAddr(domain); err == nil {
				return nil, fmt.Errorf("dstdomain IP literals unsupported; use DNS names")
			}
			term := "request.hostname == " + strconv.Quote(domain)
			if strings.HasPrefix(value, ".") {
				term = "(" + term + " || request.hostname.endsWith(" + strconv.Quote("."+domain) + "))"
			}
			terms = append(terms, term)
		default:
			return nil, fmt.Errorf("unsupported ACL type %q; supported: src, method, port, dstdomain -n", kind)
		}
	}
	return terms, nil
}
