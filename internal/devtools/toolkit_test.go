package devtools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCaptureBoundedAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "request-data" {
			t.Errorf("body changed: %s", body)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "secret=123")
		io.WriteString(w, "response-data")
	}))
	defer server.Close()
	toolkit := New(&Config{Enabled: true, Capacity: 2, CaptureBodies: true, MaxBodyBytes: 5})
	client := &http.Client{Transport: toolkit.Wrap(nil)}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", server.URL+"/test?token=secret", strings.NewReader("request-data"))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "response-data" {
			t.Fatal(string(body))
		}
	}
	entries := toolkit.List()
	if len(entries) != 2 || entries[0].ID != 2 {
		t.Fatalf("ring: %+v", entries)
	}
	for _, entry := range entries {
		if strings.Contains(entry.URL, "secret") || entry.RequestHeaders.Get("Authorization") != "" || entry.ResponseHeaders.Get("Set-Cookie") != "" {
			t.Fatal("capture leaked credentials")
		}
		if entry.RequestBody != "reque" || entry.ResponseBody != "respo" || !entry.RequestTruncated || !entry.ResponseTruncated {
			t.Fatalf("preview: %+v", entry)
		}
	}
	entries[0].RequestHeaders.Set("Content-Type", "changed")
	if toolkit.List()[0].RequestHeaders.Get("Content-Type") == "changed" {
		t.Fatal("list aliased stored headers")
	}
	toolkit.Clear()
	if len(toolkit.List()) != 0 {
		t.Fatal("clear failed")
	}
}

func TestBodiesDisabledAndBinaryExcluded(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		toolkit := New(&Config{Enabled: true, CaptureBodies: enabled})
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader("binary-secret")), Request: r}, nil
		})
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		resp, err := toolkit.Wrap(next).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if toolkit.List()[0].ResponseBody != "" {
			t.Fatal("binary body captured")
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRulesAndCancellation(t *testing.T) {
	called := false
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("real"))}, nil
	})
	toolkit := New(&Config{Enabled: true, CaptureBodies: true, Rules: []Rule{{Host: "example.com", PathPrefix: "/mock", Status: 503, Body: "mock"}}})
	req, _ := http.NewRequest("GET", "http://example.com/mock", nil)
	resp, err := toolkit.Wrap(next).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if called || resp.StatusCode != 503 || string(body) != "mock" || !toolkit.List()[0].Mocked {
		t.Fatal("mock failed")
	}
	req, _ = http.NewRequest("GET", "http://example.com/real", nil)
	resp, err = toolkit.Wrap(next).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !called {
		t.Fatal("nonmatch blocked upstream")
	}
	if err := toolkit.SetRules([]Rule{{Host: "example.com", DelayMS: 1000}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	start := time.Now()
	if _, err := toolkit.Wrap(next).RoundTrip(req); err != context.Canceled {
		t.Fatalf("error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation ignored")
	}
	if err := toolkit.SetRules([]Rule{{Host: "example.com", Fail: true}}); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("GET", "http://example.com", nil)
	if _, err := toolkit.Wrap(next).RoundTrip(req); err == nil {
		t.Fatal("failure rule ignored")
	}
	if err := toolkit.SetRules([]Rule{{Host: "example.com", Status: 101}}); err == nil {
		t.Fatal("invalid rule accepted")
	}
}
func TestConcurrentCapture(t *testing.T) {
	toolkit := New(&Config{Enabled: true, Capacity: 10, Rules: []Rule{{Host: "example.com", Status: 200, Body: "mock"}}})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			resp, err := toolkit.Wrap(nil).RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			toolkit.List()
		}()
	}
	wg.Wait()
	if len(toolkit.List()) != 10 {
		t.Fatal("wrong ring size")
	}
}
func TestRuleAPIAndReplay(t *testing.T) {
	toolkit := New(&Config{Enabled: true})
	for _, body := range []string{`{"rules":[{"host":"example.com","status":201,"body":"mock"}]}`, `{"rules":[]} {}`, `{"rules":[{"host":"example.com","headers":{"X-Test":["bad\r\nvalue"]}}]}`} {
		req := httptest.NewRequest("PUT", "/api/devtools/rules", strings.NewReader(body))
		w := httptest.NewRecorder()
		toolkit.HandleRules(w, req)
		want := 400
		if strings.Contains(body, `"status":201`) {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
	u, _ := url.Parse("http://example.com/?secret=123")
	if _, err := RequestFromExchange(context.Background(), Exchange{Method: "GET", URL: safeURL(u)}, ""); err == nil {
		t.Fatal("redacted query replayed")
	}
	if _, err := RequestFromExchange(context.Background(), Exchange{Method: "POST", URL: "http://example.com"}, ""); err == nil {
		t.Fatal("write replayed automatically")
	}
	req, err := RequestFromExchange(context.Background(), Exchange{Method: "GET", URL: safeURL(u)}, "http://example.com/?secret=new")
	if err != nil || req.URL.Query().Get("secret") != "new" {
		t.Fatal("override failed")
	}
}
