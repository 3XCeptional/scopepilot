package audit

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// PersistentLogger is a SQLite-backed ring buffer for audit decisions.
// Wraps the in-memory Logger for hot reads but persists every entry to SQLite.
// On restart, the last N entries are replayed into the in-memory buffer.
type PersistentLogger struct {
	*Logger              // embed in-memory logger for fast reads
	db       *sql.DB
	ringSize int
	path     string
	mu       sync.Mutex
}

// NewPersistentLogger creates a SQLite-backed audit log at ~/.scopepilot/audit.db.
// ringSize controls how many entries are kept in memory and in SQLite (oldest trimmed).
func NewPersistentLogger(ringSize int) (*PersistentLogger, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(homeDir, ".scopepilot")
	os.MkdirAll(dir, 0755)
	dbPath := filepath.Join(dir, "audit.db")

	db, err := sql.Open("sqlite", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	pl := &PersistentLogger{
		Logger:   NewLogger(ringSize),
		db:       db,
		ringSize: ringSize,
		path:     dbPath,
	}

	// Replay last N entries from SQLite into in-memory buffer
	pl.replayFromDB(ringSize)

	return pl, nil
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_entries (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			component TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL,
			data_json TEXT NOT NULL DEFAULT '{}',
			redacted INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_entries(event_type);
	`)
	return err
}

func (pl *PersistentLogger) replayFromDB(n int) {
	rows, err := pl.db.Query(
		"SELECT id, timestamp, component, event_type, data_json, redacted FROM audit_entries ORDER BY rowid DESC LIMIT ?",
		n,
	)
	if err != nil {
		return // silent on error, in-memory starts empty
	}
	defer rows.Close()

	var entries []*Entry
	for rows.Next() {
		var e Entry
		var dataStr string
		var redactedInt int
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Component, &e.EventType, &dataStr, &redactedInt); err != nil {
			continue
		}
		e.Redacted = redactedInt != 0
		json.Unmarshal([]byte(dataStr), &e.Data)
		if e.Data == nil {
			e.Data = map[string]interface{}{}
		}
		entries = append(entries, &e)
	}

	// Reverse to chronological order
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for i := len(entries) - 1; i >= 0; i-- {
		pl.Logger.entries = append(pl.Logger.entries, entries[i])
	}
	// Trim to ring size
	if len(pl.Logger.entries) > pl.ringSize {
		pl.Logger.entries = pl.Logger.entries[len(pl.Logger.entries)-pl.ringSize:]
	}
}

// Add logs an entry to both the in-memory buffer and SQLite.
func (pl *PersistentLogger) Add(entry *Entry) {
	pl.Log(entry.Component, entry.EventType, entry.Data)
	pl.persist(entry)
}

func (pl *PersistentLogger) persist(entry *Entry) {
	dataJSON, _ := json.Marshal(entry.Data)
	redactedInt := 0
	if entry.Redacted {
		redactedInt = 1
	}

	_, err := pl.db.Exec(
		"INSERT INTO audit_entries (id, timestamp, component, event_type, data_json, redacted) VALUES (?, ?, ?, ?, ?, ?)",
		entry.ID, entry.Timestamp, entry.Component, entry.EventType, string(dataJSON), redactedInt,
	)
	if err != nil {
		// Silently fail on write errors; in-memory buffer still works
		return
	}

	// Trim oldest entries when over ring size (keep ~2x ring size in DB for safety)
	var count int
	pl.db.QueryRow("SELECT COUNT(*) FROM audit_entries").Scan(&count)
	if count > pl.ringSize*2 {
		pl.db.Exec(
			"DELETE FROM audit_entries WHERE rowid NOT IN (SELECT rowid FROM audit_entries ORDER BY rowid DESC LIMIT ?)",
			pl.ringSize,
		)
	}
}

// Close cleans up the SQLite connection.
func (pl *PersistentLogger) Close() error {
	return pl.db.Close()
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
