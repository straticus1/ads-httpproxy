package tengo

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestTengoRequestResponseAndConcurrentExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.tengo")
	script := `block := false
if phase == "request" { block = req.host == "blocked.example" }
if phase == "response" { block = resp.status_code == 500 }
`
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://allowed.example", nil)
			if err := engine.OnRequest(context.Background(), req); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	req, _ := http.NewRequest("GET", "http://blocked.example", nil)
	if err := engine.OnRequest(context.Background(), req); err != context.Canceled {
		t.Fatalf("block: %v", err)
	}
	if err := engine.OnResponse(context.Background(), &http.Response{StatusCode: 500, Request: req}); err != context.Canceled {
		t.Fatalf("response block: %v", err)
	}
	if err := os.WriteFile(path, []byte("not valid syntax"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err == nil {
		t.Fatal("bad reload accepted")
	}
	if err := engine.OnRequest(context.Background(), req); err != context.Canceled {
		t.Fatal("failed reload replaced working program")
	}
}
