//go:build postgres

// Package db provides PostgreSQL-backed storage for ScopePilot.
// This file is only compiled when the "postgres" build tag is set:
//
//	go build -tags postgres ./...
//
// Requires: github.com/jackc/pgx/v5/pgxpool
//
//	# go get github.com/jackc/pgx/v5
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGConfig holds PostgreSQL connection configuration.
type PGConfig struct {
	ConnString string // PostgreSQL connection URI
	MaxConns   int32  // Max pool connections (default: 10)
	MinConns   int32  // Min pool connections (default: 2)
}

// PGStore is a PostgreSQL-backed Store implementation.
type PGStore struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
}

// NewPGStore creates a PostgreSQL store, connecting to the database and
// running schema migrations.
func NewPGStore(ctx context.Context, cfg PGConfig) (*PGStore, error) {
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}
	if cfg.MinConns == 0 {
		cfg.MinConns = 2
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	// Verify connectivity.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping failed: %w", err)
	}

	s := &PGStore{pool: pool}

	// Run schema migration.
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}

	return s, nil
}

// migrate creates tables if they don't exist.
func (s *PGStore) migrate(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_entries (
		id          TEXT PRIMARY KEY,
		timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		component   TEXT NOT NULL,
		event_type  TEXT NOT NULL,
		data        JSONB,
		redacted    BOOLEAN NOT NULL DEFAULT FALSE
	);

	CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_entries(event_type);
	CREATE INDEX IF NOT EXISTS idx_audit_component ON audit_entries(component);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp DESC);

	CREATE TABLE IF NOT EXISTS scan_jobs (
		id          TEXT PRIMARY KEY,
		program_id  TEXT NOT NULL,
		job_type    TEXT NOT NULL,
		status      TEXT NOT NULL DEFAULT 'pending',
		targets     JSONB,
		results     JSONB,
		errors      TEXT[],
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		started_at  TIMESTAMPTZ,
		completed_at TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_jobs_program ON scan_jobs(program_id);
	CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// LogEntry stores an audit entry in PostgreSQL.
func (s *PGStore) LogEntry(component, eventType string, data map[string]interface{}) *audit.Entry {
	entry := &audit.Entry{
		ID:        newID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Component: component,
		EventType: eventType,
		Data:      data,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		dataJSON = []byte("{}")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_entries (id, timestamp, component, event_type, data) VALUES ($1, $2, $3, $4, $5)`,
		entry.ID, entry.Timestamp, component, eventType, dataJSON,
	)
	if err != nil {
		// Fallback: return entry anyway (caller gets ID + timestamp).
		return entry
	}

	return entry
}

// RecentEntries returns the n most recent entries (newest first).
func (s *PGStore) RecentEntries(n int) []*audit.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT id, timestamp, component, event_type, data, redacted FROM audit_entries ORDER BY timestamp DESC LIMIT $1`,
		n,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	return scanEntries(rows)
}

// SearchEntries returns entries matching the given filters.
func (s *PGStore) SearchEntries(eventType, component string) []*audit.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, timestamp, component, event_type, data, redacted FROM audit_entries WHERE 1=1`
	args := []interface{}{}
	argN := 0

	if eventType != "" {
		argN++
		query += fmt.Sprintf(" AND event_type = $%d", argN)
		args = append(args, eventType)
	}
	if component != "" {
		argN++
		query += fmt.Sprintf(" AND component = $%d", argN)
		args = append(args, component)
	}
	query += ` ORDER BY timestamp DESC LIMIT 1000`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	return scanEntries(rows)
}

// RedactEntry redacts specified fields from an entry by ID.
func (s *PGStore) RedactEntry(entryID string, fields []string) *audit.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fetch current data.
	var dataJSON []byte
	var entry audit.Entry
	err := s.pool.QueryRow(ctx,
		`SELECT id, timestamp, component, event_type, data FROM audit_entries WHERE id = $1`,
		entryID,
	).Scan(&entry.ID, &entry.Timestamp, &entry.Component, &entry.EventType, &dataJSON)
	if err != nil {
		return nil
	}

	if dataJSON != nil {
		json.Unmarshal(dataJSON, &entry.Data)
	}

	// Create redacted copy.
	redacted := audit.RedactEntry(&entry, fields)

	// Update in DB.
	redactedJSON, _ := json.Marshal(redacted.Data)
	_, _ = s.pool.Exec(ctx,
		`UPDATE audit_entries SET data = $1, redacted = TRUE WHERE id = $2`,
		redactedJSON, entryID,
	)

	return redacted
}

// Close shuts down the connection pool.
func (s *PGStore) Close() error {
	s.pool.Close()
	return nil
}

// NewConfiguredStore creates an in-memory store unless PostgreSQL is selected
// by configuration or DATABASE_URL. PostgreSQL failures are returned so the
// caller can fail closed rather than losing durable audit data.
func NewConfiguredStore(cfg StoreConfig) (Store, error) {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = cfg.ConnString
	}
	envEnabled := os.Getenv("SCOPEPILOT_POSTGRES_ENABLED") == "true"
	if !cfg.PostgreSQLEnabled && !envEnabled && connStr == "" {
		return NewMemoryStore(5000), nil
	}
	if cfg.PostgreSQLEnabled && !envEnabled && connStr == "" {
		return nil, fmt.Errorf("db: PostgreSQL is enabled but no connection string is configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := NewPGStore(ctx, PGConfig{
		ConnString: connStr,
		MaxConns:   cfg.MaxConns,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}

// scanEntries scans audit entries from a pgx row iterator.
func scanEntries(rows pgx.Rows) []*audit.Entry {
	var result []*audit.Entry
	for rows.Next() {
		var e audit.Entry
		var dataJSON []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Component, &e.EventType, &dataJSON, &e.Redacted); err != nil {
			continue
		}
		if dataJSON != nil {
			json.Unmarshal(dataJSON, &e.Data)
		}
		result = append(result, &e)
	}
	return result
}

func (s *PGStore) RecordAssets(program string, assets []Asset) error {
	return fmt.Errorf("PGStore: RecordAssets not implemented")
}

func (s *PGStore) GetAssets(program string) ([]Asset, error) {
	return nil, fmt.Errorf("PGStore: GetAssets not implemented")
}

func (s *PGStore) RecordFinding(program string, finding *Finding) error {
	return fmt.Errorf("PGStore: RecordFinding not implemented")
}

func (s *PGStore) GetFindings(program string) ([]Finding, error) {
	return nil, fmt.Errorf("PGStore: GetFindings not implemented")
}

func (s *PGStore) MarkTested(program string, te TestedEndpoint) error {
	return fmt.Errorf("PGStore: MarkTested not implemented")
}

func (s *PGStore) GetTested(program string) ([]TestedEndpoint, error) {
	return nil, fmt.Errorf("PGStore: GetTested not implemented")
}
