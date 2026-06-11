package audit

import (
	"testing"
)

func TestPersistentLoggerIDConsistency(t *testing.T) {
	pl, err := NewPersistentLogger(100)
	if err != nil {
		t.Skipf("PersistentLogger not available in this environment: %v", err)
	}
	defer pl.Close()

	// Add an entry
	entry := &Entry{
		Component: "test",
		EventType: "allow",
		Data:      map[string]interface{}{"host": "example.com"},
	}
	pl.Add(entry)

	// Read back from DB
	rows, err := pl.db.Query("SELECT id, event_type FROM audit_entries WHERE event_type = 'allow' ORDER BY rowid DESC LIMIT 1")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("no rows found in DB")
	}

	var dbID, dbEventType string
	if err := rows.Scan(&dbID, &dbEventType); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// The ID assigned by Log() is in the in-memory entries
	recent := pl.Recent(1)
	if len(recent) == 0 {
		t.Fatal("no entries in memory")
	}
	memID := recent[0].ID

	if memID == "" {
		t.Error("in-memory entry has empty ID")
	}
	if dbID == "" {
		t.Error("DB entry has empty ID")
	}
	if memID != dbID {
		t.Errorf("ID mismatch: in-memory id=%q, db id=%q", memID, dbID)
	}
}
