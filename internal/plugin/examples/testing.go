package examples

import (
	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// initTestLogger initializes the logger for tests
func initTestLogger() {
	if logging.Logger == nil {
		logging.Logger, _ = zap.NewDevelopment()
	}
}
