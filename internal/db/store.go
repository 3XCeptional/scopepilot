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

	"github.com/dhiren/pentest-automation/internal/audit"
)

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
}

// NewMemoryStore creates an in-memory store with the given capacity.
func NewMemoryStore(maxEntries int) *MemoryStore {
	if maxEntries < 1 {
		maxEntries = 1000
	}
	return &MemoryStore{
		logger: audit.NewLogger(maxEntries),
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

// newID generates a short hex identifier.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
