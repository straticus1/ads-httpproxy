package dlp

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

// ViolationReport represents a single DLP violation event.
type ViolationReport struct {
	Timestamp  time.Time              `json:"timestamp"`
	Action     string                 `json:"action"`
	Reason     string                 `json:"reason"`
	URL        string                 `json:"url,omitempty"`
	Filename   string                 `json:"filename,omitempty"`
	Violations []string               `json:"violations"`
	Categories []string               `json:"categories,omitempty"`
	Evidence   map[string]interface{} `json:"evidence,omitempty"`
}

// Reporter handles structuring and persisting DLP violations.
type Reporter struct {
	mu   sync.Mutex
	file *os.File
}

// NewReporter initializes the DLP reporter appending to the specified file.
func NewReporter(logPath string) (*Reporter, error) {
	if logPath == "" {
		return &Reporter{}, nil // No-op reporter if path is empty
	}

	fl, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Reporter{file: fl}, nil
}

// Record logs the violation report as JSONL.
func (r *Reporter) Record(report ViolationReport) {
	if r.file == nil {
		return
	}

	data, err := json.Marshal(report)
	if err != nil {
		logging.Logger.Error("Failed to serialize DLP report", zap.Error(err))
		return
	}
	data = append(data, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.file.Write(data); err != nil {
		logging.Logger.Error("Failed to write DLP report to file", zap.Error(err))
	}
}

// Close closes the underlying file descriptor.
func (r *Reporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
