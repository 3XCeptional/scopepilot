package db

import (
	"testing"
)

func TestMemoryStoreLogAndRecent(t *testing.T) {
	s := NewMemoryStore(100)

	e1 := s.LogEntry("test", "info", map[string]interface{}{"msg": "hello"})
	e2 := s.LogEntry("test", "warn", map[string]interface{}{"msg": "warning"})

	if e1.ID == "" || e2.ID == "" {
		t.Error("expected non-empty IDs")
	}

	recent := s.RecentEntries(10)
	if len(recent) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(recent))
	}
	// Most recent first.
	if recent[0].ID != e2.ID {
		t.Errorf("expected newest first: got %s, want %s", recent[0].ID, e2.ID)
	}
}

func TestMemoryStoreSearch(t *testing.T) {
	s := NewMemoryStore(100)

	s.LogEntry("proxy", "allow", map[string]interface{}{"url": "https://example.com"})
	s.LogEntry("mcp", "tool_invocation", map[string]interface{}{"tool": "check_url"})
	s.LogEntry("proxy", "deny", map[string]interface{}{"url": "https://evil.com"})

	// Search by event type.
	results := s.SearchEntries("allow", "")
	if len(results) != 1 {
		t.Fatalf("expected 1 allow entry, got %d", len(results))
	}

	// Search by component.
	results = s.SearchEntries("", "mcp")
	if len(results) != 1 {
		t.Fatalf("expected 1 mcp entry, got %d", len(results))
	}

	// Empty filters match all.
	results = s.SearchEntries("", "")
	if len(results) != 3 {
		t.Fatalf("expected 3 entries with empty filters, got %d", len(results))
	}
}

func TestMemoryStoreRedact(t *testing.T) {
	s := NewMemoryStore(100)

	e := s.LogEntry("test", "secret", map[string]interface{}{
		"api_key": "sk-123456",
		"url":     "https://example.com",
	})

	redacted := s.RedactEntry(e.ID, []string{"api_key"})
	if redacted == nil {
		t.Fatal("expected redacted entry, got nil")
	}
	if redacted.Data["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be redacted, got %v", redacted.Data["api_key"])
	}
	if redacted.Data["url"] != "https://example.com" {
		t.Errorf("expected url to remain unchanged, got %v", redacted.Data["url"])
	}
}

func TestMemoryStoreCapacity(t *testing.T) {
	s := NewMemoryStore(3)

	s.LogEntry("t", "e", nil)
	s.LogEntry("t", "e", nil)
	s.LogEntry("t", "e", nil)
	s.LogEntry("t", "e", nil) // This should evict the first.

	entries := s.RecentEntries(10)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (capacity), got %d", len(entries))
	}
}

func TestMemoryStoreClose(t *testing.T) {
	s := NewMemoryStore(10)
	if err := s.Close(); err != nil {
		t.Errorf("Close should not error for memory store: %v", err)
	}
}

func TestNewMemoryStoreDefaults(t *testing.T) {
	s := NewMemoryStore(0)
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	// Should use default capacity.
	entries := s.RecentEntries(10000)
	if len(entries) != 0 {
		t.Errorf("expected empty store, got %d entries", len(entries))
	}
}

func TestStoreInterface(t *testing.T) {
	// Verify that MemoryStore satisfies Store interface.
	var s Store = NewMemoryStore(100)
	if s == nil {
		t.Fatal("MemoryStore should satisfy Store interface")
	}
}
