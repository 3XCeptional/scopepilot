//go:build !postgres

package db

import (
	"fmt"
	"os"
)

// NewConfiguredStore creates the selected store. A binary built without the
// postgres tag rejects PostgreSQL configuration rather than silently falling
// back to volatile storage.
func NewConfiguredStore(cfg StoreConfig) (Store, error) {
	if cfg.PostgreSQLEnabled || cfg.ConnString != "" || os.Getenv("DATABASE_URL") != "" || os.Getenv("SCOPEPILOT_POSTGRES_ENABLED") == "true" {
		return nil, fmt.Errorf("db: PostgreSQL requested but this binary was built without the postgres build tag")
	}
	return NewMemoryStore(5000), nil
}
