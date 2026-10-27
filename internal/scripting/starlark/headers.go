package starlark

import (
	"fmt"
	"net/http"
	"slices"
	"sort"

	"ads-httpproxy/internal/headerpolicy"
	"go.starlark.net/starlark"
	"golang.org/x/net/http/httpguts"
)

// Both views are independent snapshots: changing one never silently overwrites
// a change to the other. Keep the scalar view for existing policy scripts.
func headerViews(headers http.Header) (*starlark.Dict, *starlark.Dict) {
	scalar, multi := starlark.NewDict(len(headers)), starlark.NewDict(len(headers))
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := headers[key]
		first := ""
		if len(values) > 0 {
			first = values[0]
		}
		_ = scalar.SetKey(starlark.String(key), starlark.String(first))
		items := make([]starlark.Value, len(values))
		for i, value := range values {
			items[i] = starlark.String(value)
		}
		_ = multi.SetKey(starlark.String(key), starlark.NewList(items))
	}
	return scalar, multi
}

func parseHeaderView(dict *starlark.Dict, multi bool) (http.Header, error) {
	parsed := make(http.Header, dict.Len())
	for _, item := range dict.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok || !httpguts.ValidHeaderFieldName(key) {
			return nil, fmt.Errorf("invalid script header name")
		}
		key = http.CanonicalHeaderKey(key)
		if _, exists := parsed[key]; exists {
			return nil, fmt.Errorf("script header case collision: %s", key)
		}
		if !multi {
			value, ok := starlark.AsString(item[1])
			if !ok {
				return nil, fmt.Errorf("script header %s must be a string", key)
			}
			parsed[key] = []string{value}
			continue
		}
		list, ok := item[1].(*starlark.List)
		if !ok {
			return nil, fmt.Errorf("script header_values %s must be a list of strings", key)
		}
		values := make([]string, list.Len())
		for i := range values {
			value, ok := starlark.AsString(list.Index(i))
			if !ok {
				return nil, fmt.Errorf("script header_values %s must contain strings", key)
			}
			values[i] = value
		}
		parsed[key] = values
	}
	return parsed, nil
}

func mergeHeaders(original http.Header, scalar, multi *starlark.Dict) (http.Header, error) {
	beforeScalar, beforeMulti := headerViews(original)
	oldScalar, err := parseHeaderView(beforeScalar, false)
	if err != nil {
		return nil, err
	}
	oldMulti, err := parseHeaderView(beforeMulti, true)
	if err != nil {
		return nil, err
	}
	newScalar, err := parseHeaderView(scalar, false)
	if err != nil {
		return nil, err
	}
	newMulti, err := parseHeaderView(multi, true)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, view := range []http.Header{oldScalar, newScalar, newMulti} {
		for key := range view {
			keys[key] = true
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	changes := make(http.Header)
	for _, key := range ordered {
		scalarChanged := headerChanged(oldScalar, newScalar, key)
		multiChanged := headerChanged(oldMulti, newMulti, key)
		if !scalarChanged && !multiChanged {
			continue
		}
		if scalarChanged && multiChanged {
			return nil, fmt.Errorf("script changed %s in both headers and header_values", key)
		}
		values := newScalar[key]
		if multiChanged {
			values = newMulti[key]
		}
		if err := headerpolicy.ValidateOperation(key, values, len(values) == 0); err != nil {
			return nil, err
		}
		changes[key] = values
	}
	// Validation is atomic. Untouched slices, including duplicate Set-Cookie
	// values and nil slices, retain their original representation.
	if len(changes) == 0 {
		return original, nil
	}
	result := make(http.Header, len(original)+len(changes))
	for key, values := range original {
		result[key] = values
	}
	for key, values := range changes {
		for existing := range result {
			if http.CanonicalHeaderKey(existing) == key {
				delete(result, existing)
			}
		}
		if len(values) > 0 {
			result[key] = values
		}
	}
	return result, nil
}

func headerChanged(before, after http.Header, key string) bool {
	old, had := before[key]
	current, has := after[key]
	return had != has || !slices.Equal(old, current)
}
