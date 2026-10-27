package policy

import (
	"ads-httpproxy/pkg/logging"
	"context"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityPolicyDefaultDenyAndActions(t *testing.T) {
	logging.Logger = zap.NewNop()
	e, err := NewEngine()
	require.NoError(t, err)
	e.SetDefaultEffect("block")
	p := filepath.Join(t.TempDir(), "policies.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`policies:
- id: finance
  effect: allow
  condition: 'user.issuer == "trusted" && "finance" in user.groups && "read" in user.scopes && client.verified_mtls'
  actions: ["redact_headers:Authorization,X-Secret", "rate_limit:10"]
`), 0600))
	require.NoError(t, e.LoadFromFile(p))
	ctx := &EvalContext{User: UserInfo{Issuer: "trusted", Groups: []string{"finance"}, Scopes: []string{"read"}}, Client: ClientInfo{VerifiedMTLS: true}}
	allowed, matched, actions, _ := e.Evaluate(context.Background(), ctx)
	require.True(t, allowed)
	require.True(t, matched)
	require.Len(t, actions, 2)
	ctx.User.Issuer = "untrusted"
	allowed, _, _, _ = e.Evaluate(context.Background(), ctx)
	require.False(t, allowed)
}
func TestPolicyErrorsAndUnknownActionsFailClosed(t *testing.T) {
	logging.Logger = zap.NewNop()
	e, err := NewEngine()
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(p, []byte("policies:\n- id: bad\n  effect: allow\n  condition: 'user.missing == true'\n"), 0600))
	require.NoError(t, e.LoadFromFile(p))
	allowed, _, _, _ := e.Evaluate(context.Background(), &EvalContext{})
	require.False(t, allowed)
	for _, condition := range []string{"1", "true"} {
		action := ""
		if condition == "true" {
			action = "\n  actions: [launch_shell]"
		}
		require.NoError(t, os.WriteFile(p, []byte("policies:\n- id: invalid\n  effect: allow\n  condition: '"+condition+"'"+action+"\n"), 0600))
		require.Error(t, e.LoadFromFile(p))
	}
}
