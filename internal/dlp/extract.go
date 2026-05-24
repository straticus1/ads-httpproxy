package dlp

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"

	"ads-httpproxy/pkg/logging"
	"go.uber.org/zap"
)

var (
	ErrArchiveTooLarge = errors.New("decompressed archive exceeds maximum extraction limit (zip bomb protection)")
)

// ScannerFunc is a function signature for passing payloads back to the engine.
type ScannerFunc func(filename string, data []byte) *ScanResult

// Extractor implements secure payload extraction.
type Extractor struct {
	MaxUnpackSize int64
}

func NewExtractor(maxSize int64) *Extractor {
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}
	return &Extractor{MaxUnpackSize: maxSize}
}

// ExtractAndScan attempts to identify magic bytes, decompress, and invoke the scanner recursively.
// Returns true if it was an archive, along with any resulting violations.
func (e *Extractor) ExtractAndScan(filename string, payload []byte, scanHook ScannerFunc) (bool, *ScanResult) {
	// ZIP Magic Bytes (PK\x03\x04)
	if len(payload) > 4 && payload[0] == 0x50 && payload[1] == 0x4B && payload[2] == 0x03 && payload[3] == 0x04 {
		return true, e.scanZip(filename, payload, scanHook)
	}

	// GZIP Magic Bytes (\x1F\x8B)
	if len(payload) > 2 && payload[0] == 0x1F && payload[1] == 0x8B {
		return true, e.scanGzip(filename, payload, scanHook)
	}

	return false, nil
}

func (e *Extractor) scanZip(parentName string, payload []byte, scanHook ScannerFunc) *ScanResult {
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		logging.Logger.Debug("Failed to parse zip payload", zap.Error(err))
		return nil
	}

	var totalUnpacked int64

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		var buf bytes.Buffer
		n, err := io.CopyN(&buf, rc, e.MaxUnpackSize-totalUnpacked+1)
		rc.Close()

		totalUnpacked += n
		if totalUnpacked > e.MaxUnpackSize {
			logging.Logger.Warn("DLP Zip extraction aborted: exceeds max unpack size", zap.String("file", parentName))
			// Return a blocked scan result immediately
			res := &ScanResult{
				Blocked: true,
				Reason:  ErrArchiveTooLarge.Error(),
				Action:  "block",
			}
			return res
		}

		if err != nil && err != io.EOF {
			continue
		}

		// Perform scan on the inner file
		innerRes := scanHook(parentName+"::"+file.Name, buf.Bytes())
		if innerRes != nil && innerRes.Blocked {
			return innerRes // short-circuit if violation found inside
		}
	}

	return nil
}

func (e *Extractor) scanGzip(parentName string, payload []byte, scanHook ScannerFunc) *ScanResult {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		logging.Logger.Debug("Failed to parse gzip payload", zap.Error(err))
		return nil
	}
	defer reader.Close()

	var buf bytes.Buffer
	n, err := io.CopyN(&buf, reader, e.MaxUnpackSize+1)

	if n > e.MaxUnpackSize {
		logging.Logger.Warn("DLP Gzip extraction aborted: exceeds max unpack size", zap.String("file", parentName))
		res := &ScanResult{
			Blocked: true,
			Reason:  ErrArchiveTooLarge.Error(),
			Action:  "block",
		}
		return res
	}

	if err != nil && err != io.EOF {
		return nil
	}

	// For gzip, we just interpret the decompressed stream as one blob
	innerRes := scanHook(parentName+"::decompressed", buf.Bytes())
	if innerRes != nil && innerRes.Blocked {
		return innerRes
	}

	return nil
}
