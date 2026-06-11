// Package db provides data storage abstractions for ScopePilot.
//
// It defines a Store interface that can be backed by:
//   - In-memory (default, no dependencies)
//   - PostgreSQL (optional, requires -tags postgres and pgx driver)
//
// The in-memory store wraps the existing audit.Logger for backward
// compatibility. When PostgreSQL is enabled, it provides persistent
// storage for audit entries, scan results, and job state.
package db

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/dhiren/pentest-automation/internal/audit"
)

// Asset represents a discovered host or subdomain.
type Asset struct {
	Host      string    `json:"host"`
	Source    string    `json:"source"`    // e.g. "bbot", "manual", "nuclei"
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	InScope   bool      `json:"in_scope"`
	Tech      []string  `json:"tech,omitempty"` // detected technologies
}

// Finding represents a security finding.
type Finding struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"` // critical, high, medium, low, info
	Host      string    `json:"host"`
	Status    string    `json:"status"` // open, confirmed, false_positive, fixed
	PoCRef    string    `json:"poc_ref,omitempty"`
	Created   time.Time `json:"created"`
}

// TestedEndpoint records that a specific check was performed.
type TestedEndpoint struct {
	Host     string    `json:"host"`
	Endpoint string    `json:"endpoint"` // URL path
	Check    string    `json:"check"`    // e.g. "idor", "sqli", "actuator"
	Result   string    `json:"result"`   // "not_vulnerable", "vulnerable", "error"
	TestedAt time.Time `json:"tested_at"`
}

// Store is the data storage interface. Implementations can be in-memory
// or PostgreSQL-backed.
type Store interface {
	// LogEntry stores an audit entry.
	LogEntry(component, eventType string, data map[string]interface{}) *audit.Entry

	// RecentEntries returns the n most recent entries (newest first).
	RecentEntries(n int) []*audit.Entry

	// SearchEntries returns entries matching the given filters.
	// Empty strings match anything.
	SearchEntries(eventType, component string) []*audit.Entry

	// RedactEntry redacts specified fields from an entry by ID.
	RedactEntry(entryID string, fields []string) *audit.Entry

	// Close cleans up resources.
	Close() error

	// --- Engagement Memory (keyed by program_id) ---

	// RecordAssets upserts assets for a program. If an asset with the same
	// (program, host) already exists, its LastSeen is updated and source/tech
	// are merged.
	RecordAssets(program string, assets []Asset) error

	// GetAssets returns all assets recorded for a program.
	GetAssets(program string) ([]Asset, error)

	// RecordFinding stores a finding for a program.
	RecordFinding(program string, finding Finding) error

	// GetFindings returns all findings for a program.
	GetFindings(program string) ([]Finding, error)

	// MarkTested records that a specific endpoint/check was tested for a host.
	MarkTested(program string, te TestedEndpoint) error

	// GetTested returns all tested endpoints for a program.
	GetTested(program string) ([]TestedEndpoint, error)
}

// StoreConfig selects the storage backend.
type StoreConfig struct {
	PostgreSQLEnabled bool
	ConnString        string
	MaxConns          int32
}

// MemoryStore is an in-memory Store implementation.
// It wraps audit.Logger internally but exposes a Store interface.
type MemoryStore struct {
	logger *audit.Logger
	mu     sync.RWMutex

	// Engagement memory
	assets   map[string][]Asset      // program -> assets
	findings map[string][]Finding    // program -> findings
	tested   map[string][]TestedEndpoint // program -> tested
}

// NewMemoryStore creates an in-memory store with the given capacity.
func NewMemoryStore(maxEntries int) *MemoryStore {
	if maxEntries < 1 {
		maxEntries = 1000
	}
	return &MemoryStore{
		logger:   audit.NewLogger(maxEntries),
		assets:   make(map[string][]Asset),
		findings: make(map[string][]Finding),
		tested:   make(map[string][]TestedEndpoint),
	}
}

// LogEntry stores an audit entry in memory.
func (s *MemoryStore) LogEntry(component, eventType string, data map[string]interface{}) *audit.Entry {
	return s.logger.Log(component, eventType, data)
}

// RecentEntries returns the n most recent entries (newest first).
func (s *MemoryStore) RecentEntries(n int) []*audit.Entry {
	return s.logger.Recent(n)
}

// SearchEntries returns entries matching the given filters.
func (s *MemoryStore) SearchEntries(eventType, component string) []*audit.Entry {
	return s.logger.Search(eventType, component)
}

// RedactEntry redacts specified fields from an entry by ID.
func (s *MemoryStore) RedactEntry(entryID string, fields []string) *audit.Entry {
	return s.logger.Redact(entryID, fields)
}

// Close is a no-op for the in-memory store.
func (s *MemoryStore) Close() error { return nil }

// RecordAssets upserts assets for a program.
func (s *MemoryStore) RecordAssets(program string, assets []Asset) error {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.assets[program]
	for _, a := range assets {
		a.LastSeen = now
		if a.FirstSeen.IsZero() {
			a.FirstSeen = now
		}
		found := false
		for i, e := range existing {
			if e.Host == a.Host {
				existing[i].LastSeen = now
				existing[i].Source = mergeSource(existing[i].Source, a.Source)
				if a.FirstSeen.Before(existing[i].FirstSeen) {
					existing[i].FirstSeen = a.FirstSeen
				}
				if a.InScope {
					existing[i].InScope = true
				}
				existing[i].Tech = mergeTech(existing[i].Tech, a.Tech)
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, a)
		}
	}
	s.assets[program] = existing
	return nil
}

// GetAssets returns all assets recorded for a program.
func (s *MemoryStore) GetAssets(program string) ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.assets[program], nil
}

// RecordFinding stores a finding for a program.
func (s *MemoryStore) RecordFinding(program string, finding Finding) error {
	if finding.ID == "" {
		finding.ID = newID()
	}
	if finding.Created.IsZero() {
		finding.Created = time.Now().UTC()
	}
	if finding.Status == "" {
		finding.Status = "open"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings[program] = append(s.findings[program], finding)
	return nil
}

// GetFindings returns all findings for a program.
func (s *MemoryStore) GetFindings(program string) ([]Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[program], nil
}

// MarkTested records that a specific endpoint/check was tested.
func (s *MemoryStore) MarkTested(program string, te TestedEndpoint) error {
	if te.TestedAt.IsZero() {
		te.TestedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tested[program] = append(s.tested[program], te)
	return nil
}

// GetTested returns all tested endpoints for a program.
func (s *MemoryStore) GetTested(program string) ([]TestedEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tested[program], nil
}

// newID generates a short hex identifier.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// mergeSource merges two source strings (comma-separated, deduped).
func mergeSource(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if a == b {
		return a
	}
	return a + "," + b
}

// mergeTech merges two technology slices (deduped).
func mergeTech(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, t := range a {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, t := range b {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
