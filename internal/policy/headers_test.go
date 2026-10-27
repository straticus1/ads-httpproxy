package policy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"ads-httpproxy/internal/headerpolicy"
	"github.com/stretchr/testify/require"
)

func TestHeaderActionCollectionLimitsPreventPublication(t *testing.T) {
	e, err := NewEngine()
	require.NoError(t, err)
	for _, prefix := range []string{"", "response_"} {
		var fields, values, bytes []string
		for i := 0; i < 65; i++ {
			fields = append(fields, fmt.Sprintf("%sset_header:X-Field-%d:v", prefix, i))
		}
		for i := 0; i < 128; i++ {
			values = append(values, prefix+"append_header:X-Value:v")
		}
		for i := 0; i < 4; i++ {
			bytes = append(bytes, prefix+"append_header:X-Value:"+strings.Repeat("v", 10000))
		}
		for _, actions := range [][]string{fields, values, bytes} {
			called := false
			_, err := e.ReplaceWithPersist(0, []*Policy{{ID: "oversized", Effect: "allow", Condition: "true", Actions: actions}}, "allow", func(uint64) error { called = true; return nil })
			require.Error(t, err)
			require.False(t, called)
			require.Zero(t, e.Snapshot().Version)
		}
	}
}

func TestHeaderObligationRoundTripAndEnforcement(t *testing.T) {
	actions := []string{
		"set_header:X-Route:https://upstream.example:8443/path",
		"append_header:X-Tag:first", "append_header:X-Tag:second",
		"set_header:X-Tag:old", "set_header:X-Tag:base",
		"remove_header:X-Secret", "append_header:X-Secret:discard",
		"redact_headers:Authorization,Cookie", "rate_limit:12",
		"response_set_header:X-Response:yes",
		"response_append_header:Set-Cookie:a=1; Path=/",
		"response_append_header:Set-Cookie:b=2; Path=/",
		"response_remove_header:Server",
		"set_header:X-Empty:",
	}
	obligations, err := parseObligations(actions)
	require.NoError(t, err)
	require.Equal(t, actions, (Decision{Obligations: obligations}).Actions())
	request, response, err := HeaderActions(actions)
	require.NoError(t, err)
	h := http.Header{"Authorization": {"secret"}, "Cookie": {"secret"}}
	require.NoError(t, headerpolicy.ApplyOperations(h, request))
	require.Equal(t, "https://upstream.example:8443/path", h.Get("X-Route"))
	require.Equal(t, []string{"base", "first", "second"}, h.Values("X-Tag"))
	require.Empty(t, h.Values("X-Secret"))
	require.Empty(t, h.Values("Authorization"))
	require.Empty(t, h.Values("Cookie"))
	require.Equal(t, []string{""}, h.Values("X-Empty"))
	h = http.Header{"Server": {"upstream"}}
	require.NoError(t, headerpolicy.ApplyOperations(h, response))
	require.Equal(t, []string{"a=1; Path=/", "b=2; Path=/"}, h.Values("Set-Cookie"))
	require.Equal(t, "yes", h.Get("X-Response"))
	require.Empty(t, h.Values("Server"))
}

func TestInvalidHeaderActionsNeverPublish(t *testing.T) {
	e, err := NewEngine()
	require.NoError(t, err)
	_, err = e.Replace(0, []*Policy{{ID: "good", Effect: "allow", Condition: "true", Actions: []string{"set_header:X-Policy:good"}}}, "block")
	require.NoError(t, err)
	want := e.Snapshot()
	for _, action := range []string{
		"set_header:X-Test", "set_header::value", "set_header:Bad Name:value",
		"set_header:X-Test:bad\r\nInjected:yes", "append_header:X-Test:bad\x00value",
		"remove_header:X-Test:extra", "remove_header:",
		"set_header:Host:evil", "set_header:Content-Length:0",
		"append_header:Connection:keep-alive", "set_header:Authorization:secret",
		"append_header:Cookie:a=1", "set_header:X-Authenticated-User:admin",
		"set_header:Via:fake", "set_header:Set-Cookie:a=1",
		"response_set_header:Transfer-Encoding:chunked",
		"response_append_header:X-Test:bad\nvalue", "unknown_header:X-Test:v",
		"redact_headers:", "redact_headers:X-Good,bad name",
	} {
		t.Run(action, func(t *testing.T) {
			called := false
			_, err := e.ReplaceWithPersist(1, []*Policy{{ID: "bad", Effect: "allow", Condition: "true", Actions: []string{action}}}, "allow", func(uint64) error { called = true; return nil })
			require.Error(t, err)
			require.False(t, called)
			require.Equal(t, want, e.Snapshot())
			_, _, err = HeaderActions([]string{action})
			require.Error(t, err)
		})
	}
	d := e.Decide(context.Background(), &EvalContext{})
	require.Equal(t, []string{"set_header:X-Policy:good"}, d.Actions())
	d.Obligations[0].Values[0] = "mutated"
	require.Equal(t, []string{"set_header:X-Policy:good"}, e.Decide(context.Background(), &EvalContext{}).Actions())
}
