package audit

import (
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

func TestLog(t *testing.T) {
	logger := NewLogger(10)
	e := logger.Log("scope", "check", map[string]interface{}{"host": "example.com"})

	if e.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if e.Timestamp == "" {
		t.Fatal("expected non-empty timestamp")
	}
	if e.Component != "scope" {
		t.Fatalf("Component = %q, want %q", e.Component, "scope")
	}
	if e.EventType != "check" {
		t.Fatalf("EventType = %q, want %q", e.EventType, "check")
	}
	if v := e.Data["host"]; v != "example.com" {
		t.Fatalf("Data[host] = %v, want %v", v, "example.com")
	}
	if e.Redacted {
		t.Fatal("new entry should not be redacted")
	}
}

func TestLogUniqueIDs(t *testing.T) {
	logger := NewLogger(100)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		e := logger.Log("c", "e", nil)
		if seen[e.ID] {
			t.Fatalf("duplicate ID: %s", e.ID)
		}
		seen[e.ID] = true
	}
}

func TestLogNilData(t *testing.T) {
	logger := NewLogger(5)
	e := logger.Log("c", "e", nil)
	if e.Data != nil {
		t.Fatal("expected nil Data when passed nil")
	}
}

// ---------------------------------------------------------------------------
// Recent
// ---------------------------------------------------------------------------

func TestRecent(t *testing.T) {
	logger := NewLogger(10)
	for i := 0; i < 5; i++ {
		logger.Log("c", "e", map[string]interface{}{"i": i})
	}

	recent := logger.Recent(3)
	if len(recent) != 3 {
		t.Fatalf("Recent(3) returned %d entries, want 3", len(recent))
	}
	// Newest first.
	for idx, e := range recent {
		expectedI := 4 - idx
		if v := e.Data["i"]; v != expectedI {
			t.Errorf("Recent[%d].Data[i] = %v, want %d", idx, v, expectedI)
		}
	}
}

func TestRecentMoreThanAvailable(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("c", "e", nil)

	recent := logger.Recent(100)
	if len(recent) != 1 {
		t.Fatalf("Recent(100) = %d entries, want 1", len(recent))
	}
}

func TestRecentZeroOrNegative(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("c", "e", nil)

	if r := logger.Recent(0); r != nil {
		t.Fatal("Recent(0) should be nil")
	}
	if r := logger.Recent(-1); r != nil {
		t.Fatal("Recent(-1) should be nil")
	}
}

func TestRecentEmpty(t *testing.T) {
	logger := NewLogger(10)
	r := logger.Recent(5)
	if len(r) != 0 {
		t.Fatalf("Recent on empty logger should be empty, got %d entries", len(r))
	}
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func TestSearchByEventType(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("scope", "check", nil)
	logger.Log("scope", "block", nil)
	logger.Log("http", "check", nil)

	results := logger.Search("check", "")
	if len(results) != 2 {
		t.Fatalf("Search(\"check\", \"\") = %d entries, want 2", len(results))
	}
}

func TestSearchByComponent(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("scope", "check", nil)
	logger.Log("scope", "block", nil)
	logger.Log("http", "check", nil)

	results := logger.Search("", "scope")
	if len(results) != 2 {
		t.Fatalf("Search(\"\", \"scope\") = %d entries, want 2", len(results))
	}
}

func TestSearchByBoth(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("scope", "check", nil)
	logger.Log("scope", "block", nil)
	logger.Log("http", "check", nil)

	results := logger.Search("check", "http")
	if len(results) != 1 {
		t.Fatalf("Search(\"check\", \"http\") = %d entries, want 1", len(results))
	}
}

func TestSearchNoMatch(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("scope", "check", nil)

	results := logger.Search("nonexistent", "")
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestSearchEmptyLogger(t *testing.T) {
	logger := NewLogger(10)
	results := logger.Search("check", "")
	if len(results) != 0 {
		t.Fatalf("expected 0 results on empty logger, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

func TestRedactEntry(t *testing.T) {
	entry := &Entry{
		ID:        "abc123",
		Timestamp: "now",
		Component: "scope",
		EventType: "check",
		Data:      map[string]interface{}{"host": "example.com", "port": 443, "user": "admin"},
	}

	cp := RedactEntry(entry, []string{"host", "user"})
	if cp == nil {
		t.Fatal("RedactEntry returned nil")
	}
	if !cp.Redacted {
		t.Fatal("expected redacted copy to have Redacted=true")
	}
	if cp.ID != entry.ID {
		t.Fatal("redacted copy should preserve ID")
	}
	if cp.Data["host"] != "[REDACTED]" {
		t.Errorf("host = %v, want [REDACTED]", cp.Data["host"])
	}
	if cp.Data["user"] != "[REDACTED]" {
		t.Errorf("user = %v, want [REDACTED]", cp.Data["user"])
	}
	if cp.Data["port"] != 443 {
		t.Errorf("port = %v, want 443 (should not be redacted)", cp.Data["port"])
	}
	// Original unchanged.
	if entry.Data["host"] != "example.com" {
		t.Error("original entry was modified")
	}
	if entry.Redacted {
		t.Error("original entry Redacted flag was modified")
	}
}

func TestRedactEntryNonExistentField(t *testing.T) {
	entry := &Entry{
		ID:   "abc",
		Data: map[string]interface{}{"host": "example.com"},
	}
	cp := RedactEntry(entry, []string{"nonexistent"})
	if cp == nil {
		t.Fatal("RedactEntry returned nil")
	}
	if cp.Data["host"] != "example.com" {
		t.Errorf("host = %v, want example.com (should be untouched)", cp.Data["host"])
	}
}

func TestRedactEntryNilData(t *testing.T) {
	entry := &Entry{ID: "abc", Data: nil}
	cp := RedactEntry(entry, []string{"host"})
	if cp == nil {
		t.Fatal("RedactEntry returned nil")
	}
	if cp.Data != nil {
		t.Fatal("expected nil Data when original Data is nil")
	}
}

func TestRedactEntryNilPointer(t *testing.T) {
	if r := RedactEntry(nil, []string{"host"}); r != nil {
		t.Fatal("RedactEntry(nil) should return nil")
	}
}

func TestRedactEmptyFields(t *testing.T) {
	entry := &Entry{
		ID:   "abc",
		Data: map[string]interface{}{"host": "example.com"},
	}
	cp := RedactEntry(entry, nil)
	if cp == nil {
		t.Fatal("RedactEntry with nil fields returned nil")
	}
	if cp.Data["host"] != "example.com" {
		t.Error("data should be unchanged with empty/nil fields")
	}
}

func TestRedactViaLogger(t *testing.T) {
	logger := NewLogger(10)
	e := logger.Log("scope", "check", map[string]interface{}{"host": "example.com", "api_key": "secret123"})

	cp := logger.Redact(e.ID, []string{"api_key"})
	if cp == nil {
		t.Fatal("Redact returned nil for existing entry")
	}
	if !cp.Redacted {
		t.Fatal("expected redacted copy")
	}
	if cp.Data["api_key"] != "[REDACTED]" {
		t.Errorf("api_key = %v, want [REDACTED]", cp.Data["api_key"])
	}
	if cp.Data["host"] != "example.com" {
		t.Errorf("host = %v, want example.com", cp.Data["host"])
	}
}

func TestRedactNonExistentID(t *testing.T) {
	logger := NewLogger(10)
	logger.Log("scope", "check", nil)
	if r := logger.Redact("nonexistent", []string{"host"}); r != nil {
		t.Fatal("Redact with bogus ID should return nil")
	}
}

// ---------------------------------------------------------------------------
// Max entries limiting
// ---------------------------------------------------------------------------

func TestMaxEntriesEviction(t *testing.T) {
	logger := NewLogger(3)

	logger.Log("c", "e", map[string]interface{}{"seq": 1})
	logger.Log("c", "e", map[string]interface{}{"seq": 2})
	logger.Log("c", "e", map[string]interface{}{"seq": 3})
	// At capacity (3 entries). Next insert evicts seq=1.
	logger.Log("c", "e", map[string]interface{}{"seq": 4})

	entries := logger.Search("", "")
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// The oldest remaining should be seq=2.
	if v := entries[0].Data["seq"]; v != 2 {
		t.Errorf("oldest entry seq = %v, want 2", v)
	}
	if v := entries[2].Data["seq"]; v != 4 {
		t.Errorf("newest entry seq = %v, want 4", v)
	}
}

func TestMaxEntriesSingle(t *testing.T) {
	logger := NewLogger(1)
	e1 := logger.Log("c", "e", map[string]interface{}{"seq": 1})
	e2 := logger.Log("c", "e", map[string]interface{}{"seq": 2})

	if len(logger.Search("", "")) != 1 {
		t.Fatal("expected only 1 entry with max=1")
	}
	if e1 == e2 {
		t.Fatal("Log should return a new pointer each time")
	}
}

func TestNewLoggerClampsToMinimum(t *testing.T) {
	logger := NewLogger(0)
	if logger.maxEntries != 1 {
		t.Fatalf("NewLogger(0).maxEntries = %d, want 1", logger.maxEntries)
	}
	logger.Log("c", "e", nil)
	logger.Log("c", "e", nil)
	if len(logger.Search("", "")) != 1 {
		t.Fatal("expected 1 entry when maxEntries clamped to 1")
	}
}

// ---------------------------------------------------------------------------
// Concurrent safety
// ---------------------------------------------------------------------------

func TestConcurrentSafety(t *testing.T) {
	logger := NewLogger(1000)
	const goroutines = 20
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				e := logger.Log("component", "event", map[string]interface{}{
					"goroutine": id,
					"seq":       j,
				})
				// Read back while writes happen.
				_ = logger.Recent(5)
				_ = logger.Search("event", "")
				if j%10 == 0 {
					_ = logger.Redact(e.ID, []string{"goroutine"})
				}
			}
		}(i)
	}

	wg.Wait()

	total := len(logger.Search("", ""))
	if total == 0 {
		t.Fatal("expected at least some entries after concurrent logging")
	}
	if total > logger.maxEntries {
		t.Fatalf("entries (%d) exceed maxEntries (%d)", total, logger.maxEntries)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkLog(b *testing.B) {
	logger := NewLogger(1000)
	data := map[string]interface{}{"host": "example.com", "port": 443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Log("scope", "check", data)
	}
}

func BenchmarkSearch(b *testing.B) {
	logger := NewLogger(10000)
	for i := 0; i < 5000; i++ {
		logger.Log("scope", "check", nil)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Search("check", "scope")
	}
}

func BenchmarkRedactEntry(b *testing.B) {
	entry := &Entry{
		ID:   "abc",
		Data: map[string]interface{}{"host": "example.com", "api_key": "secret", "port": 443},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RedactEntry(entry, []string{"api_key"})
	}
}
