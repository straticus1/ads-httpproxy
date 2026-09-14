package starlark

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStarlarkHooksAndFailedReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.star")
	script := `def on_request(req):
    req.headers["X-Developer"] = "yes"
    if req.host == "blocked.example":
        return {"action": "block"}
    return {"action": "allow"}
def on_response(resp):
    resp.headers["X-Response"] = "yes"
    return False
`
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://allowed.example", nil)
			if err := engine.OnRequest(context.Background(), req); err != nil {
				t.Error(err)
			}
			if req.Header.Get("X-Developer") != "yes" {
				t.Error("header mutation missing")
			}
		}()
	}
	wg.Wait()
	req, _ := http.NewRequest("GET", "http://blocked.example", nil)
	if err := engine.OnRequest(context.Background(), req); err != context.Canceled {
		t.Fatalf("block: %v", err)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := engine.OnResponse(context.Background(), resp); err != nil || resp.Header.Get("X-Response") != "yes" {
		t.Fatalf("response hook: %v", err)
	}
	if err := os.WriteFile(path, []byte("x = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err == nil {
		t.Fatal("bad reload accepted")
	}
	if err := engine.OnRequest(context.Background(), req); err != context.Canceled {
		t.Fatal("failed reload replaced working script")
	}
	engine.Close() // Close is idempotent.
}
