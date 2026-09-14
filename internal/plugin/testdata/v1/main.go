package main

import (
	"ads-httpproxy/pkg/plugin"
	"encoding/json"
	"net/http"
)

type example struct{ Value string }

func (*example) Name() string                          { return "integration-plugin" }
func (*example) APIVersion() string                    { return "1" }
func (*example) Version() string                       { return "one" }
func (p *example) Configure(raw json.RawMessage) error { return json.Unmarshal(raw, p) }
func (p *example) OnRequest(req *http.Request, _ *plugin.Context) (*http.Request, *http.Response) {
	req.Header.Set("X-Plugin", "one:"+p.Value)
	return req, nil
}
func (*example) OnResponse(resp *http.Response, _ *plugin.Context) *http.Response { return resp }
func NewPlugin() plugin.Plugin                                                    { return &example{} }
