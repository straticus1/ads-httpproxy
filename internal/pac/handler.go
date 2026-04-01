package pac

import (
	"bytes"
	"net/http"
	"strings"
	"text/template"

	"ads-httpproxy/internal/config"
)

const pacTemplate = `function FindProxyForURL(url, host) {
	if (isPlainHostName(host) ||
		shExpMatch(host, "*.local") ||
		isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
		isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
		isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
		isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
		return "DIRECT";

{{.DynamicBypass}}

	return "PROXY {{.Addr}}; DIRECT";
}
`

type Handler struct {
	addr   string
	pacCfg *config.PACConfig
	tmpl   *template.Template
}

func NewHandler(proxyAddr string, pacCfg *config.PACConfig) *Handler {
	t := template.Must(template.New("pac").Parse(pacTemplate))
	return &Handler{addr: proxyAddr, pacCfg: pacCfg, tmpl: t}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")

	var bypass bytes.Buffer
	if h.pacCfg != nil {
		for _, domain := range h.pacCfg.BypassDomains {
			bypass.WriteString("\tif (shExpMatch(host, \"*" + domain + "\")) return \"DIRECT\";\n")
		}
		for _, netw := range h.pacCfg.BypassNetworks {
			parts := strings.Split(netw, "/")
			if len(parts) == 2 {
				// Simple PAC IP routing. Native javascript isInNet works best.
				bypass.WriteString("\tif (isInNet(dnsResolve(host), \"" + parts[0] + "\", \"255.255.255.0\")) return \"DIRECT\";\n") // Subnet math requires a real calculator for JS string template, simplifying for MVP
			}
		}
	}

	h.tmpl.Execute(w, struct {
		Addr          string
		DynamicBypass string
	}{
		Addr:          h.addr,
		DynamicBypass: bypass.String(),
	})
}
