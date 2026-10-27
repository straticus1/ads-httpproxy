package config

import (
	"testing"

	"ads-httpproxy/internal/headerpolicy"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHeaderConfigurationValidation(t *testing.T) {
	c := NewConfig()
	require.NoError(t, yaml.Unmarshal([]byte(`headers:
  via_pseudonym: edge-east
  trusted_proxies: ["192.0.2.0/24"]
  forward:
    forwarded: off
    request:
      remove: [Authorization]
  gateway:
    response:
      append:
        Set-Cookie: ["a=1", "b=2"]
`), c))
	require.NoError(t, c.Validate())
	require.Equal(t, []string{"a=1", "b=2"}, c.Headers.Gateway.Response.Append["Set-Cookie"])
	for _, invalid := range []*headerpolicy.Config{
		{ViaPseudonym: "edge\r\nInjected: true"},
		{TrustedProxies: []string{"*"}},
		{Forward: headerpolicy.Profile{Forwarded: "trust-everyone"}},
		{Gateway: headerpolicy.Profile{Request: headerpolicy.Operations{Set: map[string][]string{"X-Authenticated-User": {"admin"}}}}},
		{Forward: headerpolicy.Profile{Response: headerpolicy.Operations{Set: map[string][]string{"Content-Length": {"0"}}}}},
	} {
		c.Headers = invalid
		require.Error(t, c.Validate())
	}
}
