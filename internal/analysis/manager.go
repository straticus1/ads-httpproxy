package analysis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type budget struct {
	minute int64
	count  int
}
type counters struct {
	received, sampledOut, accepted, budget, queue, tenant, closed atomic.Uint64
	errors, retries, completed, journalErrors                     atomic.Uint64
}

type Manager struct {
	cfg        Config
	analyzer   Analyzer
	queue      chan Event
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	mu         sync.Mutex // submission/lifecycle only; never held during analyzer or file I/O
	closed     bool
	budgets    map[string]budget
	stats      counters
	findingsMu sync.RWMutex
	findings   []Finding
	ids        map[string]struct{}
	journal    *journal
	closeErr   error
}

func New(cfg Config, analyzer Analyzer) (*Manager, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	cfg = defaults(cfg)
	if analyzer == nil {
		analyzer = DefaultAnalyzer{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{cfg: cfg, analyzer: analyzer, queue: make(chan Event, cfg.QueueCapacity), ctx: ctx, cancel: cancel, done: make(chan struct{}), budgets: make(map[string]budget), ids: make(map[string]struct{})}
	if cfg.JournalPath != "" {
		j, retained, err := openJournal(cfg.JournalPath, cfg.JournalMaxBytes, cfg.FindingsCapacity)
		if err != nil {
			cancel()
			return nil, err
		}
		m.journal = j
		for _, f := range retained {
			m.retain(f)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.worker() }()
	}
	go func() {
		wg.Wait()
		m.findingsMu.Lock()
		if m.journal != nil {
			m.closeErr = m.journal.close()
		}
		m.findingsMu.Unlock()
		cancel()
		close(m.done)
	}()
	return m, nil
}

// Submit never waits for queue capacity or disk I/O. False means disabled,
// sampled out, budget/cardinality exceeded, queue full, or shutdown has begun.
func (m *Manager) Submit(event Event) bool {
	if m == nil {
		return false
	}
	m.stats.received.Add(1)
	if len(event.Tenant) > 128 || len(event.ID) > 128 || len(event.Subject) > 256 {
		m.stats.errors.Add(1)
		return false
	}
	if !m.cfg.Enabled {
		m.stats.sampledOut.Add(1)
		return false
	}
	e := sanitize(event, m.cfg)
	if e.ID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			m.stats.errors.Add(1)
			return false
		}
		e.ID = hex.EncodeToString(id[:])
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	sample := sha256.Sum256([]byte(e.Tenant + "\x00" + e.ID))
	if m.cfg.SampleRate < 1 && float64(binary.BigEndian.Uint64(sample[:8]))/float64(math.MaxUint64) >= m.cfg.SampleRate {
		m.stats.sampledOut.Add(1)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		m.stats.closed.Add(1)
		return false
	}
	now := time.Now().Unix() / 60
	b, ok := m.budgets[e.Tenant]
	if !ok && len(m.budgets) >= m.cfg.MaxTenants {
		for tenant, budget := range m.budgets {
			if budget.minute != now {
				delete(m.budgets, tenant)
			}
		}
		if len(m.budgets) >= m.cfg.MaxTenants {
			m.stats.tenant.Add(1)
			return false
		}
	}
	if b.minute != now {
		b = budget{minute: now}
	}
	if b.count >= m.cfg.PerTenantPerMinute {
		m.stats.budget.Add(1)
		return false
	}
	select {
	case m.queue <- e:
		b.count++
		m.budgets[e.Tenant] = b
		m.stats.accepted.Add(1)
		return true
	default:
		m.stats.queue.Add(1)
		return false
	}
}

func (m *Manager) worker() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case e, ok := <-m.queue:
			if !ok {
				return
			}
			m.process(e)
		}
	}
}

func (m *Manager) process(e Event) {
	var findings []Finding
	var err error
	for attempt := 0; attempt <= m.cfg.MaxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
		findings, err = analyze(ctx, m.analyzer, e)
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
		if err == nil {
			break
		}
		if m.ctx.Err() != nil || attempt == m.cfg.MaxRetries {
			m.stats.errors.Add(1)
			return
		}
		m.stats.retries.Add(1)
		timer := time.NewTimer(time.Duration(1<<attempt) * 10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-m.ctx.Done():
			timer.Stop()
			m.stats.errors.Add(1)
			return
		}
	}
	if len(findings) > 32 {
		m.stats.errors.Add(1)
		return
	}
	for i, f := range findings {
		if math.IsNaN(f.Confidence) || math.IsInf(f.Confidence, 0) || f.Confidence < 0 || f.Confidence > 1 || f.Category == "" {
			m.stats.errors.Add(1)
			continue
		}
		f.Category, f.Reason, f.ModelVersion = bounded(f.Category, 128), preview(f.Reason, 1024), bounded(f.ModelVersion, 128)
		id := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", e.Tenant, e.ID, f.Category, f.ModelVersion, i)))
		f.ID, f.EventID, f.Tenant, f.Subject, f.URL, f.PolicyVersion = hex.EncodeToString(id[:]), e.ID, e.Tenant, e.Subject, e.URL, e.PolicyVersion
		now := time.Now().UTC()
		f.CreatedAt = now
		maxExpiry := now.Add(time.Duration(m.cfg.FindingTTLSeconds) * time.Second)
		if f.ExpiresAt.IsZero() || f.ExpiresAt.After(maxExpiry) {
			f.ExpiresAt = maxExpiry
		}
		if !f.ExpiresAt.After(now) {
			continue
		}
		evidence := make(map[string]string)
		for key, value := range f.Evidence {
			if len(evidence) >= 16 {
				break
			}
			if sensitiveKey(key) {
				value = "[REDACTED]"
			}
			evidence[bounded(key, 128)] = preview(value, 256)
		}
		f.Evidence = evidence
		m.findingsMu.Lock()
		if _, duplicate := m.ids[f.ID]; !duplicate {
			if m.journal != nil {
				if err := m.journal.append(f); err != nil {
					m.stats.journalErrors.Add(1)
				}
			}
			m.retain(f)
		}
		m.findingsMu.Unlock()
	}
	m.stats.completed.Add(1)
}

func analyze(ctx context.Context, analyzer Analyzer, e Event) (findings []Finding, err error) {
	defer func() {
		if recover() != nil {
			findings = nil
			err = fmt.Errorf("analysis worker panicked")
		}
	}()
	return analyzer.Analyze(ctx, e)
}

// retain is called under findingsMu or before workers start.
func (m *Manager) retain(f Finding) {
	if _, exists := m.ids[f.ID]; exists {
		return
	}
	if len(m.findings) == m.cfg.FindingsCapacity {
		delete(m.ids, m.findings[0].ID)
		copy(m.findings, m.findings[1:])
		m.findings = m.findings[:len(m.findings)-1]
	}
	m.findings = append(m.findings, f)
	m.ids[f.ID] = struct{}{}
}

// Snapshot returns newest findings first. Expired findings are omitted unless
// explicitly requested for investigations. Returned maps do not alias storage.
func (m *Manager) Snapshot(filter Filter) []Finding {
	result := make([]Finding, 0)
	if m == nil {
		return result
	}
	m.findingsMu.RLock()
	defer m.findingsMu.RUnlock()
	for i := len(m.findings) - 1; i >= 0; i-- {
		f := m.findings[i]
		if filter.Tenant != "" && f.Tenant != filter.Tenant || filter.Category != "" && f.Category != filter.Category || !filter.IncludeExpired && !f.ExpiresAt.After(time.Now()) {
			continue
		}
		f.Evidence = cloneEvidence(f.Evidence)
		result = append(result, f)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result
}

func cloneEvidence(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (m *Manager) Stats() Stats {
	if m == nil {
		return Stats{}
	}
	m.findingsMu.RLock()
	retained := len(m.findings)
	m.findingsMu.RUnlock()
	return Stats{Received: m.stats.received.Load(), SampledOut: m.stats.sampledOut.Load(), Accepted: m.stats.accepted.Load(), DroppedBudget: m.stats.budget.Load(), DroppedQueue: m.stats.queue.Load(), DroppedTenant: m.stats.tenant.Load(), DroppedClosed: m.stats.closed.Load(), Errors: m.stats.errors.Load(), Retries: m.stats.retries.Load(), Completed: m.stats.completed.Load(), JournalErrors: m.stats.journalErrors.Load(), QueueDepth: len(m.queue), RetainedFindings: retained}
}

// Close stops submissions and drains accepted events. Deadline expiry cancels
// in-progress analyzers; custom analyzers must honor their context.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.queue)
	}
	m.mu.Unlock()
	select {
	case <-m.done:
		return m.closeErr
	case <-ctx.Done():
		m.cancel()
		return ctx.Err()
	}
}
