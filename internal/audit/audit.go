// Package audit implements append-oriented audit logging with redaction support.
// Entries are stored in-memory with a configurable maximum. Redaction replaces
// specified Data fields with "[REDACTED]" and returns a copy, leaving the
// original untouched.
package audit

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	Component string                 `json:"component"`
	EventType string                 `json:"event_type"`
	Data      map[string]interface{} `json:"data"`
	Redacted  bool                   `json:"redacted"`
}

// Logger is an append-oriented, in-memory audit log with a capacity cap.
type Logger struct {
	entries    []*Entry
	maxEntries int
	mu         sync.Mutex
}

// NewLogger creates a Logger that retains at most maxEntries entries at a time.
// When the log is full, the oldest entry is evicted before appending the new one.
func NewLogger(maxEntries int) *Logger {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &Logger{
		entries:    make([]*Entry, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// newID generates a short hex identifier for an entry.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Log appends a new entry and returns it. If the log is at capacity, the oldest
// entry is evicted first.
func (l *Logger) Log(component, eventType string, data map[string]interface{}) *Entry {
	entry := &Entry{
		ID:        newID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Component: component,
		EventType: eventType,
		Data:      data,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) >= l.maxEntries {
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, entry)
	return entry
}

// Recent returns the n most recent entries, in reverse chronological order
// (newest first). If n exceeds the number of entries, all entries are returned.
func (l *Logger) Recent(n int) []*Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n <= 0 {
		return nil
	}
	if n > len(l.entries) {
		n = len(l.entries)
	}

	result := make([]*Entry, n)
	for i := 0; i < n; i++ {
		result[i] = l.entries[len(l.entries)-1-i]
	}
	return result
}

// Search returns entries matching the given eventType and/or component. Empty
// strings are treated as wildcards (match anything). Results are in insertion
// order (oldest first).
func (l *Logger) Search(eventType, component string) []*Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []*Entry
	for _, e := range l.entries {
		if eventType != "" && e.EventType != eventType {
			continue
		}
		if component != "" && e.Component != component {
			continue
		}
		result = append(result, e)
	}
	return result
}

// Redact looks up an entry by ID and redacts the specified Data fields in a
// copy. The original entry is marked as redacted but otherwise untouched.
// It returns the redacted copy on success, or nil if no entry matches the ID.
func (l *Logger) Redact(entryID string, fields []string) *Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, e := range l.entries {
		if e.ID == entryID {
			return RedactEntry(e, fields)
		}
	}
	return nil
}

// RedactEntry returns a copy of entry with the specified Data fields replaced
// by "[REDACTED]". The original entry is not modified. The copy has Redacted
// set to true.
func RedactEntry(entry *Entry, fields []string) *Entry {
	if entry == nil {
		return nil
	}

	cp := &Entry{
		ID:        entry.ID,
		Timestamp: entry.Timestamp,
		Component: entry.Component,
		EventType: entry.EventType,
		Redacted:  true,
	}

	if entry.Data != nil {
		cp.Data = make(map[string]interface{}, len(entry.Data))
		for k, v := range entry.Data {
			cp.Data[k] = v
		}
	}

	redactSet := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		redactSet[f] = struct{}{}
	}

	for f := range redactSet {
		if _, ok := cp.Data[f]; ok {
			cp.Data[f] = "[REDACTED]"
		}
	}

	return cp
}
