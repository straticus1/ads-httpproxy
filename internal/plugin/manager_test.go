package plugin

import (
	"net/http"
	"testing"
)

type testPlugin struct {
	name      string
	onRequest func(*http.Request, *Context) (*http.Request, *http.Response)
}

func (p *testPlugin) Name() string { return p.name }
func (p *testPlugin) OnRequest(r *http.Request, c *Context) (*http.Request, *http.Response) {
	if p.onRequest != nil {
		return p.onRequest(r, c)
	}
	return r, nil
}
func (p *testPlugin) OnResponse(r *http.Response, c *Context) *http.Response { return r }
func TestManagerRegistrationAndReentrantRemoval(t *testing.T) {
	m := NewManager()
	if err := m.Register(nil); err == nil {
		t.Fatal("nil accepted")
	}
	var typedNil *testPlugin
	if err := m.Register(typedNil); err == nil {
		t.Fatal("typed nil accepted")
	}
	if err := m.Register(&testPlugin{}); err == nil {
		t.Fatal("empty name accepted")
	}
	p := &testPlugin{name: "first"}
	if err := m.Register(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(p); err == nil {
		t.Fatal("duplicate accepted")
	}
	p.onRequest = func(r *http.Request, c *Context) (*http.Request, *http.Response) {
		if err := m.Remove("first"); err != nil {
			t.Error(err)
		}
		return r, nil
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if got, resp := m.HandleRequest(req, &Context{}); got != req || resp != nil {
		t.Fatal("request changed")
	}
	if len(m.List()) != 0 {
		t.Fatal("reentrant removal failed")
	}
	if err := m.Remove("missing"); err == nil {
		t.Fatal("missing removal succeeded")
	}
}
func TestManagerBlocksAndTransforms(t *testing.T) {
	m := NewManager()
	updated, _ := http.NewRequest("GET", "http://modified.com", nil)
	m.Register(&testPlugin{name: "modify", onRequest: func(r *http.Request, c *Context) (*http.Request, *http.Response) { return updated, nil }})
	response := &http.Response{StatusCode: 403}
	m.Register(&testPlugin{name: "block", onRequest: func(r *http.Request, c *Context) (*http.Request, *http.Response) {
		if r != updated {
			t.Error("modified request lost")
		}
		return nil, response
	}})
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if got, resp := m.HandleRequest(req, &Context{}); got != nil || resp != response {
		t.Fatal("block ignored")
	}
}
func TestDirectoryLoadingDoesNotReportFalseSuccess(t *testing.T) {
	loader := NewLoader(NewManager())
	if err := loader.LoadFromDirectory(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := loader.LoadFromDirectory("/nonexistent-plugin-directory"); err == nil {
		t.Fatal("missing directory silently accepted")
	}
}

func TestReplacementPreservesOrderAndRejectsInvalidPlugin(t *testing.T) {
	m := NewManager()
	first := &testPlugin{name: "first"}
	second := &testPlugin{name: "second"}
	m.Register(first)
	m.Register(second)
	snapshot := m.snapshot()
	replacement := &testPlugin{name: "first"}
	if err := m.Replace(replacement); err != nil {
		t.Fatal(err)
	}
	if m.snapshot()[0] != replacement || m.snapshot()[1] != second || snapshot[0] != first {
		t.Fatal("replacement changed order or in-flight snapshot")
	}
	if err := m.Replace(&testPlugin{name: "missing"}); err == nil {
		t.Fatal("missing replacement accepted")
	}
	if err := m.Replace(nil); err == nil {
		t.Fatal("nil replacement accepted")
	}
}
