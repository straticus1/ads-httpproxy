package devtools

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func BenchmarkCapture(b *testing.B) {
	for _, bodies := range []bool{false, true} {
		name := "metadata"
		if bodies {
			name = "body-preview"
		}
		b.Run(name, func(b *testing.B) {
			toolkit := New(&Config{Enabled: true, Capacity: 500, CaptureBodies: bodies})
			next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("benchmark response")), Request: r}, nil
			})
			transport := toolkit.Wrap(next)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequest("GET", "http://example.com/test", nil)
				resp, err := transport.RoundTrip(req)
				if err != nil {
					b.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
}
