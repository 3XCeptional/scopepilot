//go:build postgres

package db

import (
	"strings"
	"testing"
)

func TestNewConfiguredStore_PostgresBuildMemoryDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SCOPEPILOT_POSTGRES_ENABLED", "")
	store, err := NewConfiguredStore(StoreConfig{})
	if err != nil {
		t.Fatalf("memory store selection failed: %v", err)
	}
	if _, ok := store.(*MemoryStore); !ok {
		t.Fatalf("expected MemoryStore, got %T", store)
	}
}

func TestNewConfiguredStore_PostgresRequiresConnectionString(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SCOPEPILOT_POSTGRES_ENABLED", "")
	_, err := NewConfiguredStore(StoreConfig{PostgreSQLEnabled: true})
	if err == nil || !strings.Contains(err.Error(), "connection string") {
		t.Fatalf("expected connection string error, got %v", err)
	}
}
