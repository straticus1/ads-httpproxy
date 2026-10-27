package analysis

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// journal keeps a current file plus one rotated segment, each at most max bytes.
// A journal path is exclusive to one process; it is not a distributed queue.
type journal struct {
	path      string
	max, size int64
	file      *os.File
}

func openJournal(path string, max int64, capacity int) (*journal, []Finding, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, fmt.Errorf("analysis journal directory: %w", err)
	}
	retained := make([]Finding, 0)
	for _, name := range []string{path + ".1", path} {
		items, validBytes, incomplete, err := readSegment(name, max, capacity)
		if err != nil {
			return nil, nil, err
		}
		if incomplete && name == path {
			if err := os.Truncate(path, validBytes); err != nil {
				return nil, nil, fmt.Errorf("repair analysis journal tail: %w", err)
			}
		}
		retained = append(retained, items...)
		if len(retained) > capacity {
			retained = retained[len(retained)-capacity:]
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("open analysis journal: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("analysis journal must be a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, nil, err
	}
	return &journal{path: path, max: max, size: info.Size(), file: f}, retained, nil
}

func readSegment(path string, max int64, capacity int) ([]Finding, int64, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, 0, false, fmt.Errorf("analysis journal segment is not regular or exceeds configured bound: %s", path)
	}
	r := bufio.NewReaderSize(f, 65536)
	var result []Finding
	var valid int64
	for {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			return nil, 0, false, fmt.Errorf("analysis journal record exceeds 65536 bytes")
		}
		if err == io.EOF {
			return result, valid, len(line) > 0, nil
		}
		if err != nil {
			return nil, 0, false, err
		}
		var finding Finding
		if err := json.Unmarshal(bytes.TrimSpace(line), &finding); err != nil {
			return nil, 0, false, fmt.Errorf("invalid analysis journal record: %w", err)
		}
		if finding.ID == "" || finding.Tenant == "" || finding.Category == "" || finding.CreatedAt.IsZero() || finding.ExpiresAt.IsZero() {
			return nil, 0, false, fmt.Errorf("analysis journal record missing required fields")
		}
		result = append(result, finding)
		if len(result) > capacity {
			copy(result, result[1:])
			result = result[:capacity]
		}
		valid += int64(len(line))
	}
}

func (j *journal) append(f Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if int64(len(data)) > j.max || len(data) > 65536 {
		return fmt.Errorf("analysis finding exceeds journal record bound")
	}
	if j.file == nil {
		return fmt.Errorf("analysis journal is closed")
	}
	if j.size+int64(len(data)) > j.max {
		if err := j.file.Close(); err != nil {
			return err
		}
		j.file = nil
		if err := os.Rename(j.path, j.path+".1"); err != nil {
			j.file, _ = os.OpenFile(j.path, os.O_APPEND|os.O_WRONLY, 0600)
			return err
		}
		j.file, err = os.OpenFile(j.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		j.size = 0
	}
	n, err := j.file.Write(data)
	j.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return j.file.Sync()
}

func (j *journal) close() error {
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}
