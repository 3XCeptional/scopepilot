//go:build !postgres

package db

import (
	"strings"
	"testing"
)

func TestNewConfiguredStore_DefaultBuild(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SCOPEPILOT_POSTGRES_ENABLED", "")

	store, err := NewConfiguredStore(StoreConfig{})
	if err != nil {
		t.Fatalf("memory store selection failed: %v", err)
	}
	if _, ok := store.(*MemoryStore); !ok {
		t.Fatalf("expected MemoryStore, got %T", store)
	}

	_, err = NewConfiguredStore(StoreConfig{PostgreSQLEnabled: true})
	if err == nil || !strings.Contains(err.Error(), "postgres build tag") {
		t.Fatalf("expected build-tag error, got %v", err)
	}
}
