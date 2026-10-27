// proxybench runs a bounded HTTP workload and reports client-side measurements.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type options struct {
	Target, Proxy      string
	Count, Concurrency int
	Timeout            time.Duration
	MaxBytes           int64
}
type report struct {
	Requests             int         `json:"requests"`
	Errors               int         `json:"errors"`
	Bytes                int64       `json:"bytes"`
	DurationSeconds      float64     `json:"duration_seconds"`
	RequestsPerSecond    float64     `json:"requests_per_second"`
	P50Milliseconds      float64     `json:"p50_ms"`
	P95Milliseconds      float64     `json:"p95_ms"`
	P99Milliseconds      float64     `json:"p99_ms"`
	StatusCodes          map[int]int `json:"status_codes"`
	ClientHeapBefore     uint64      `json:"client_heap_before_bytes"`
	ClientHeapAfter      uint64      `json:"client_heap_after_bytes"`
	ClientTotalAllocated uint64      `json:"client_total_allocated_bytes"`
	ClientRuntimeSys     uint64      `json:"client_runtime_sys_bytes"`
}

func validURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("expected http(s) URL without userinfo or fragment")
	}
	return u, nil
}

func run(ctx context.Context, o options) (report, error) {
	if _, err := validURL(o.Target); err != nil {
		return report{}, err
	}
	if o.Count < 1 || o.Count > 1000000 || o.Concurrency < 1 || o.Concurrency > 1024 || o.Concurrency > o.Count || o.Timeout <= 0 || o.Timeout > time.Minute || o.MaxBytes < 1 || o.MaxBytes > 1<<30 {
		return report{}, fmt.Errorf("invalid limits: count 1..1000000, concurrency 1..min(count,1024), timeout (0,1m], max-bytes 1..1GiB")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // Reproducible: ignore ambient HTTP_PROXY/HTTPS_PROXY.
	tr.MaxIdleConns = o.Concurrency
	tr.MaxIdleConnsPerHost = o.Concurrency
	tr.MaxConnsPerHost = o.Concurrency
	if o.Proxy != "" {
		u, err := validURL(o.Proxy)
		if err != nil {
			return report{}, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	durations := make([]time.Duration, o.Count)
	statuses := make([]int, o.Count)
	sizes := make([]int64, o.Count)
	failed := make([]bool, o.Count)
	var next atomic.Int64
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < o.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= o.Count {
					return
				}
				began := time.Now()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Target, nil)
				if err == nil {
					var resp *http.Response
					resp, err = client.Do(req)
					if resp != nil {
						statuses[i] = resp.StatusCode
						sizes[i], err = io.Copy(io.Discard, io.LimitReader(resp.Body, o.MaxBytes+1))
						closeErr := resp.Body.Close()
						if err == nil {
							err = closeErr
						}
						if sizes[i] > o.MaxBytes {
							err = fmt.Errorf("response exceeds byte limit")
						}
					}
				}
				durations[i] = time.Since(began)
				failed[i] = err != nil || statuses[i] < 200 || statuses[i] >= 300
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	r := report{Requests: o.Count, DurationSeconds: elapsed.Seconds(), RequestsPerSecond: float64(o.Count) / elapsed.Seconds(), StatusCodes: map[int]int{}, ClientHeapBefore: before.HeapAlloc, ClientHeapAfter: after.HeapAlloc, ClientTotalAllocated: after.TotalAlloc - before.TotalAlloc, ClientRuntimeSys: after.Sys}
	for i, status := range statuses {
		if failed[i] {
			r.Errors++
		}
		if status != 0 {
			r.StatusCodes[status]++
		}
		r.Bytes += sizes[i]
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	percentile := func(p float64) float64 {
		return float64(durations[int(math.Ceil(p*float64(len(durations))))-1]) / float64(time.Millisecond)
	}
	r.P50Milliseconds = percentile(.5)
	r.P95Milliseconds = percentile(.95)
	r.P99Milliseconds = percentile(.99)
	return r, nil
}

func main() {
	var o options
	flag.StringVar(&o.Target, "target", "", "required target URL (GET)")
	flag.StringVar(&o.Proxy, "proxy", "", "optional HTTP(S) forward proxy URL")
	flag.IntVar(&o.Count, "count", 1000, "total requests, maximum 1000000")
	flag.IntVar(&o.Concurrency, "concurrency", 10, "concurrent workers, maximum 1024")
	flag.DurationVar(&o.Timeout, "timeout", 10*time.Second, "per-request timeout, maximum 1m")
	flag.Int64Var(&o.MaxBytes, "max-bytes", 16<<20, "maximum response bytes per request")
	flag.Parse()
	r, err := run(context.Background(), o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err = json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if r.Errors > 0 {
		os.Exit(1)
	}
}
