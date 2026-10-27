package starlark

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func headerTestEngine(t *testing.T, body string) *StarlarkEngine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "headers.star")
	// Use a shared argument name to exercise both hook entry points.
	script := "def mutate(h):\n" + body + "\ndef on_request(req):\n    mutate(req)\ndef on_response(resp):\n    mutate(resp)\n"
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func TestHeaderViewsMutations(t *testing.T) {
	engine := headerTestEngine(t, `    h.header_values["Set-Cookie"].append("c=3; HttpOnly")
    h.headers["X-Replace"] = "new"
    h.headers.pop("X-Remove")
    h.header_values.pop("X-Multi-Remove")
    h.header_values["X-Added"] = ["one", "two"]
    h.headers.pop("Authorization")
`)
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprint("response=", response), func(t *testing.T) {
			headers := http.Header{"Set-Cookie": {"a=1", "b=2"}, "X-Replace": {"old", "older"}, "X-Remove": {"x"}, "X-Multi-Remove": {"x", "y"}, "Authorization": {"Bearer old"}, "Via": {"1.1 trusted"}, "X-Unchanged": {"first", "second"}}
			var got http.Header
			if response {
				resp := &http.Response{Header: headers}
				if err := engine.OnResponse(context.Background(), resp); err != nil {
					t.Fatal(err)
				}
				got = resp.Header
			} else {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header = headers
				if err := engine.OnRequest(context.Background(), req); err != nil {
					t.Fatal(err)
				}
				got = req.Header
			}
			want := http.Header{"Set-Cookie": {"a=1", "b=2", "c=3; HttpOnly"}, "X-Replace": {"new"}, "X-Added": {"one", "two"}, "Via": {"1.1 trusted"}, "X-Unchanged": {"first", "second"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v; want %#v", got, want)
			}
		})
	}
}

func TestHeaderViewsRejectInvalidMutationsAtomically(t *testing.T) {
	for name, body := range map[string]string{
		"conflict":          "h.headers[\"X-Test\"] = \"scalar\"\n    h.header_values[\"X-Test\"] = [\"multi\"]",
		"case collision":    "h.headers[\"x-test\"] = \"collision\"",
		"CRLF":              `h.headers["X-Test"] = "bad\r\nInjected: yes"`,
		"NUL":               `h.header_values["X-Test"] = ["bad\x00value"]`,
		"field name":        `h.headers["Bad Name"] = "bad"`,
		"wrong list type":   `h.header_values["X-Test"] = "bad"`,
		"wrong member type": `h.header_values["X-Test"] = [3]`,
		"identity":          `h.headers["X-Authenticated-User"] = "admin"`,
		"proxy credentials": `h.headers["Proxy-Authorization"] = "Basic forged"`,
		"framing":           `h.header_values["Content-Length"] = ["900"]`,
		"remove Via":        `h.headers.pop("Via")`,
	} {
		t.Run(name, func(t *testing.T) {
			engine := headerTestEngine(t, "    h.headers[\"X-Added\"] = \"must not apply\"\n    "+body+"\n")
			for _, response := range []bool{false, true} {
				original := http.Header{"X-Test": {"old", "duplicate"}, "Via": {"1.1 trusted"}}
				want := original.Clone()
				var err error
				if response {
					resp := &http.Response{Header: original}
					err = engine.OnResponse(context.Background(), resp)
					original = resp.Header
				} else {
					req, _ := http.NewRequest("GET", "http://example.com", nil)
					req.Header = original
					err = engine.OnRequest(context.Background(), req)
					original = req.Header
				}
				if err == nil {
					t.Fatal("accepted invalid mutation")
				}
				if !reflect.DeepEqual(original, want) {
					t.Fatalf("failed mutation modified headers: %#v", original)
				}
			}
		})
	}
}

func TestHeaderViewsNoopAndNil(t *testing.T) {
	engine := headerTestEngine(t, "    pass\n")
	headers := http.Header{"Set-Cookie": {"a=1", "b=2"}, "X-Empty": nil, "Content-Length": {"12"}, "Proxy-Authorization": {"secret"}}
	resp := &http.Response{Header: headers}
	want := headers.Clone()
	if err := engine.OnResponse(context.Background(), resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Header, want) {
		t.Fatal("no-op changed headers")
	}
	if &resp.Header["Set-Cookie"][0] != &headers["Set-Cookie"][0] {
		t.Fatal("untouched slice replaced")
	}
	if err := engine.OnResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	setter := headerTestEngine(t, "    h.header_values[\"X-New\"] = [\"yes\"]\n")
	resp = &http.Response{}
	if err := setter.OnResponse(context.Background(), resp); err != nil || resp.Header.Get("X-New") != "yes" {
		t.Fatalf("nil header map: %v", err)
	}
}
