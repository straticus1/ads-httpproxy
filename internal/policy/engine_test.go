package policy

import (
	"context"
	"os"
	"testing"

	"ads-httpproxy/pkg/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLoadFromFileCompilesAndAppliesPolicies(t *testing.T) {
	logging.Logger = zap.NewNop()
	file, err := os.CreateTemp(t.TempDir(), "policies-*.yaml")
	require.NoError(t, err)
	_, err = file.WriteString("policies:\n  - id: block-admin\n    effect: block\n    condition: request.path.startsWith('/admin')\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	engine, err := NewEngine()
	require.NoError(t, err)

	require.NoError(t, engine.LoadFromFile(file.Name()))
	allowed, matched, _, reason := engine.Evaluate(context.Background(), &EvalContext{Request: ClientRequest{Path: "/admin/users"}})
	require.False(t, allowed)
	require.True(t, matched)
	require.Contains(t, reason, "block-admin")
}

func TestLoadFromFileRejectsInvalidExpression(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "policies-*.yaml")
	require.NoError(t, err)
	_, err = file.WriteString("policies:\n  - id: broken\n    effect: block\n    condition: request.\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	engine, err := NewEngine()
	require.NoError(t, err)

	require.Error(t, engine.LoadFromFile(file.Name()))
}
