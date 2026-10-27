package policy

import (
	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIPInCIDRUsesNetworksAndErrorsOnMalformedInputs(t *testing.T) {
	env, err := cel.NewEnv(CIDREnvOption(), cel.Variable("ip", cel.StringType), cel.Variable("network", cel.StringType))
	require.NoError(t, err)
	ast, issues := env.Compile("ipInCIDR(ip, network)")
	require.NoError(t, issues.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)
	for _, tc := range []struct {
		ip, network string
		want        bool
		invalid     bool
	}{
		{"10.255.1.2", "10.0.0.0/8", true, false}, {"11.0.0.1", "10.0.0.0/8", false, false},
		{"2001:db8::1", "2001:db8::/32", true, false}, {"2001:db9::1", "2001:db8::/32", false, false},
		{"::ffff:10.1.2.3", "10.0.0.0/8", true, false}, {"10.1.2.3", "::/0", false, false},
		{"not-an-ip", "0.0.0.0/0", false, true}, {"127.0.0.1", "broken", false, true},
		{"fe80::1%lo0", "fe80::/10", false, true}, {"127.0.0.1", "::ffff:127.0.0.1/128", false, true},
	} {
		t.Run(tc.ip+"_"+tc.network, func(t *testing.T) {
			out, _, err := program.Eval(map[string]any{"ip": tc.ip, "network": tc.network})
			if tc.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, out.Value())
			}
		})
	}
	// Negating a malformed address must not produce an allow decision.
	ast, issues = env.Compile("!ipInCIDR(ip, network)")
	require.NoError(t, issues.Err())
	program, err = env.Program(ast)
	require.NoError(t, err)
	_, _, err = program.Eval(map[string]any{"ip": "", "network": "10.0.0.0/8"})
	require.Error(t, err)
}
