package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodecRoundTrips(t *testing.T) {
	original := []byte("héllo + / & \"世界\"\r\n")
	for _, encoding := range []string{"base64", "base64url", "hex", "url", "form", "html", "json-string", "quoted-printable", "gzip", "deflate", "deflate-raw", "chunked"} {
		t.Run(encoding, func(t *testing.T) {
			encoded, err := codec("encode", encoding, original, 1<<20, false)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := codec("decode", encoding, encoded, 1<<20, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, decoded) {
				t.Fatalf("decoded %q, want %q", decoded, original)
			}
		})
	}
}
func TestCodecSemantics(t *testing.T) {
	cases := []struct{ encoding, input, want string }{
		{"base64", "aGVsbG8", "hello"}, {"base64url", "aGVsbG8=", "hello"},
		{"url", "a+b%20c", "a+b c"}, {"form", "a+b%20c", "a b c"},
		{"utf8", "\xef\xbb\xbfhello", "hello"}, {"utf16le", "h\x00\xe9\x00", "hé"},
		{"utf16be", "\x00h\x00\xe9", "hé"}, {"latin1", "caf\xe9", "café"}, {"windows-1252", "\x80", "€"},
	}
	for _, tc := range cases {
		decoded, err := codec("decode", tc.encoding, []byte(tc.input), 1000, false)
		if err != nil || string(decoded) != tc.want {
			t.Fatalf("%s: %q %v", tc.encoding, decoded, err)
		}
	}
	if _, err := codec("decode", "utf8", []byte{255}, 100, false); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if value, err := codec("decode", "utf8", []byte{255}, 100, true); err != nil || string(value) != "�" {
		t.Fatal("UTF-8 repair failed")
	}
}
func TestDecodeHTTPFramingCompressionAndCharset(t *testing.T) {
	entity, err := codec("encode", "gzip", []byte("caf\xe9"), 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	chunked, err := codec("encode", "chunked", entity, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n"), chunked...)
	result, err := codec("decode", "http", message, 1000, false)
	if err != nil || string(result) != "café" {
		t.Fatalf("body %q: %v", result, err)
	}
	request := []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
	result, err = codec("decode", "http", request, 1000, false)
	if err != nil || string(result) != "hello" {
		t.Fatalf("request body %q: %v", result, err)
	}
	nested, _ := codec("encode", "deflate", []byte("stacked"), 1000, false)
	nested, _ = codec("encode", "gzip", nested, 1000, false)
	result, err = decodeEntity(nested, http.Header{"Content-Encoding": []string{"deflate, gzip"}}, 1000)
	if err != nil || string(result) != "stacked" {
		t.Fatalf("stacked: %q %v", result, err)
	}
}
func TestDecodingRejectsMalformedAndOversizedInput(t *testing.T) {
	for _, tc := range []struct{ encoding, input string }{{"base64", "***"}, {"hex", "xyz"}, {"url", "%xy"}, {"gzip", "not gzip"}, {"deflate", "not deflate"}, {"chunked", "ZZ\r\n"}, {"http", "HTTP/bad\r\n"}, {"json-string", "{bad}"}, {"jwt", "one.two"}, {"unknown", "hello"}} {
		if _, err := codec("decode", tc.encoding, []byte(tc.input), 1000, false); err == nil {
			t.Fatalf("invalid %s accepted", tc.encoding)
		}
	}
	compressed, _ := codec("encode", "gzip", []byte(strings.Repeat("x", 10000)), 20000, false)
	if _, err := codec("decode", "gzip", compressed, 100, false); err == nil {
		t.Fatal("decompression limit ignored")
	}
	if _, err := decodeEntity([]byte("body"), http.Header{"Content-Encoding": []string{"br"}}, 100); err == nil {
		t.Fatal("unsupported HTTP encoding silently accepted")
	}
}
func TestCodecCLIInputSourcesAndChains(t *testing.T) {
	var output bytes.Buffer
	if err := runWithInput([]string{"decode", "-encoding", "base64,utf8"}, strings.NewReader("aMOpbGxv"), &output); err != nil || output.String() != "héllo" {
		t.Fatalf("stdin/chain: %s %v", output.String(), err)
	}
	path := filepath.Join(t.TempDir(), "encoded")
	if err := os.WriteFile(path, []byte("hello%20world"), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runWithInput([]string{"decode", "-encoding", "url", "-file", path}, strings.NewReader("ignored"), &output); err != nil || output.String() != "hello world" {
		t.Fatal("file input failed", err)
	}
	output.Reset()
	if err := runWithInput([]string{"encode", "-encoding", "base64", "-data", "hello"}, strings.NewReader("ignored"), &output); err != nil || output.String() != "aGVsbG8=" {
		t.Fatal("literal encode failed", err)
	}
	for _, args := range [][]string{{"decode", "-data", "", "-file", path}, {"decode", "-max-bytes", "0"}, {"decode", "-max-bytes", "3", "-data", "hello"}} {
		if err := runWithInput(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatalf("expected error: %v", args)
		}
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"dev"}`))
	decoded, err := codec("decode", "jwt", []byte(header+"."+payload+"."), 1000, false)
	if err != nil || !strings.Contains(string(decoded), `"signature_verified": false`) {
		t.Fatal("JWT decode missing verification status", err)
	}
}
func TestLiveResponseDecoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "aMOpbGxv") }))
	defer server.Close()
	var output bytes.Buffer
	if err := run([]string{"request", "-url", server.URL, "-proxy", "", "-decode", "base64,utf8"}, &output); err != nil || !strings.Contains(output.String(), `"body": "héllo"`) {
		t.Fatalf("live decode: %s %v", output.String(), err)
	}
	if err := run([]string{"request", "-url", server.URL, "-proxy", "", "-decode", "base64", "-max-response-bytes", "3"}, &bytes.Buffer{}); err == nil {
		t.Fatal("truncated response decoded")
	}
}

func TestLiveHTTPDecodeHandlesAutomaticAndExplicitGzip(t *testing.T) {
	compressed, err := codec("encode", "gzip", []byte("café"), 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(compressed)
	}))
	defer server.Close()
	for _, explicit := range []bool{false, true} {
		args := []string{"request", "-url", server.URL, "-proxy", "", "-decode", "http"}
		if explicit {
			args = append(args, "-header", "Accept-Encoding: gzip")
		}
		var output bytes.Buffer
		if err := run(args, &output); err != nil || !strings.Contains(output.String(), `"body": "café"`) {
			t.Fatalf("explicit gzip %v: %s %v", explicit, output.String(), err)
		}
	}
	compressed[len(compressed)-1] ^= 1
	if _, err := codec("decode", "gzip", compressed, 1000, false); err == nil {
		t.Fatal("gzip checksum corruption accepted")
	}
}
