package logging

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.Logger

func Init() error {
	level := zapcore.InfoLevel
	if v := os.Getenv("ADS_LOG_LEVEL"); v != "" {
		if err := level.UnmarshalText([]byte(v)); err != nil {
			level = zapcore.InfoLevel
		}
	}

	cfg := zap.NewDevelopmentConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	var err error
	Logger, err = cfg.Build()
	return err
}

func Sync() {
	if Logger != nil {
		_ = Logger.Sync()
	}
}
