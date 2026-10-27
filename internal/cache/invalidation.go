package cache

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const generationPartitions = 256

// Generation is an opaque snapshot captured before an upstream fetch begins.
// An invalidation changes the namespace used by subsequent readers, so an old
// in-flight response can never repopulate the currently visible cache.
type Generation struct {
	resource  string
	epoch     string
	partition string
	valid     bool
}

// Begin must be called before fetching a response that might be stored.
func (hc *HTTPCache) Begin(req *http.Request) Generation {
	if hc == nil || !hc.config.Enabled || !cacheableRequest(req) || hc.invalidationsFailed.Load() {
		return Generation{}
	}
	resource, partition := resourceKey(req)
	if hc.redis != nil {
		epoch, generation, err := hc.redis.generations(partition)
		if err != nil {
			return Generation{}
		}
		return Generation{resource: resource, epoch: epoch, partition: generation, valid: true}
	}
	hc.generationMu.RLock()
	defer hc.generationMu.RUnlock()
	return Generation{resource: resource, epoch: strconv.FormatUint(hc.epoch, 10), partition: strconv.FormatUint(hc.generations[partition], 10), valid: true}
}

func resourceKey(req *http.Request) (string, byte) {
	scheme, host := req.URL.Scheme, req.URL.Host
	if host == "" {
		host = req.Host
	}
	if scheme == "" {
		scheme = "http"
		if req.TLS != nil {
			scheme = "https"
		}
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	data, _ := json.Marshal([]string{strings.ToLower(scheme), canonicalAuthority(scheme, host), path, req.URL.RawQuery, strconv.FormatBool(req.URL.ForceQuery)})
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), hash[0]
}

func canonicalAuthority(scheme, host string) string {
	u := &url.URL{Scheme: strings.ToLower(scheme), Host: strings.ToLower(host)}
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		host = u.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return host
	}
	return u.Host
}

func (hc *HTTPCache) generationKey(req *http.Request, generation Generation) string {
	return hc.GenerateKey(req) + ":" + generation.epoch + ":" + generation.partition
}

func (hc *HTTPCache) purgeRequest(req *http.Request) error {
	_, partition := resourceKey(req)
	if hc.redis != nil {
		if err := hc.redis.bumpGeneration(partition); err != nil {
			hc.invalidationsFailed.Store(true)
			return err
		}
	}
	hc.generationMu.Lock()
	hc.generations[partition]++
	hc.generationMu.Unlock()
	return nil
}

// Invalidate removes representations after a successful unsafe method. Related
// Location/Content-Location resources are invalidated only on the same origin.
func (hc *HTTPCache) Invalidate(req *http.Request, resp *http.Response) error {
	if hc == nil || !hc.config.Enabled || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return nil
	}
	err := hc.purgeRequest(req)
	for _, header := range []string{"Location", "Content-Location"} {
		for _, value := range resp.Header.Values(header) {
			reference, parseErr := url.Parse(value)
			if parseErr != nil {
				continue
			}
			target := req.URL.ResolveReference(reference)
			if target.User != nil || !strings.EqualFold(target.Scheme, req.URL.Scheme) || canonicalAuthority(target.Scheme, target.Host) != canonicalAuthority(req.URL.Scheme, req.URL.Host) {
				continue
			}
			copy := req.Clone(req.Context())
			copy.URL = target
			err = errors.Join(err, hc.purgeRequest(copy))
		}
	}
	return err
}

// Close releases the optional shared cache connection.
func (hc *HTTPCache) Close() error {
	if hc == nil {
		return nil
	}
	return hc.redis.Close()
}
