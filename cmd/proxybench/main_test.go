package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunCountsSuccessAndBoundsBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) }))
	defer s.Close()
	o := options{Target: s.URL, Count: 20, Concurrency: 4, Timeout: time.Second, MaxBytes: 10}
	r, err := run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Requests != 20 || r.Errors != 0 || r.Bytes != 100 || r.StatusCodes[200] != 20 || r.P99Milliseconds < r.P50Milliseconds || r.RequestsPerSecond <= 0 {
		t.Fatalf("bad report: %+v", r)
	}
	o.MaxBytes = 2
	r, err = run(context.Background(), o)
	if err != nil || r.Errors != 20 {
		t.Fatalf("body bound not enforced: %+v %v", r, err)
	}
}

func TestRunCountsStatusAndRejectsInvalidLimits(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer s.Close()
	o := options{Target: s.URL, Count: 3, Concurrency: 1, Timeout: time.Second, MaxBytes: 10}
	r, err := run(context.Background(), o)
	if err != nil || r.Errors != 3 || r.StatusCodes[503] != 3 {
		t.Fatalf("bad failure report: %+v %v", r, err)
	}
	o.Concurrency = 4
	if _, err = run(context.Background(), o); err == nil {
		t.Fatal("invalid concurrency accepted")
	}
}
