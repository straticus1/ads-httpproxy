package examples

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAuthPlugin(t *testing.T) {
	p := &AuthPlugin{}
	if err := p.Configure(json.RawMessage(`{"users":{"dev":"secret"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"secret", "incorrect"} {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("dev:"+password)))
		_, response := p.OnRequest(req, nil)
		if password == "secret" {
			if response != nil || req.Header.Get("Proxy-Authorization") != "" {
				t.Fatal("valid credentials failed or forwarded")
			}
		} else {
			if response == nil || response.StatusCode != 407 {
				t.Fatal("invalid credentials accepted")
			}
			response.Body.Close()
		}
	}
}
