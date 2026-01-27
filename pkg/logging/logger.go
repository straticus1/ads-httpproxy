package logging

import (
	"go.uber.org/zap"
)

var Logger *zap.Logger

func Init() error {
	var err error
	// For production, use NewProduction() for JSON format and performance
	// For development, use NewDevelopment() for human-readable output
	Logger, err = zap.NewDevelopment()
	if err != nil {
		return err
	}
	return nil
}

func Sync() {
	if Logger != nil {
		_ = Logger.Sync()
	}
}
