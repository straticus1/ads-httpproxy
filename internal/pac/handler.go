package pac

import (
	"net/http"
	"text/template"
)

const pacTemplate = `function FindProxyForURL(url, host) {
	if (isPlainHostName(host) ||
		shExpMatch(host, "*.local") ||
		isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
		isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
		isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
		isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
		return "DIRECT";

	return "PROXY {{.Addr}}; DIRECT";
}
`

type Handler struct {
	addr string
	tmpl *template.Template
}

func NewHandler(proxyAddr string) *Handler {
	t := template.Must(template.New("pac").Parse(pacTemplate))
	return &Handler{addr: proxyAddr, tmpl: t}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	h.tmpl.Execute(w, map[string]string{"Addr": h.addr})
}
