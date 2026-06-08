// Package killswitch implements global and per-program kill switches.
// A kill switch can be activated to immediately halt all testing activity
// for a program or across the entire platform. The implementation is
// thread-safe and tracks who activated the switch and when.
package killswitch

import (
	"fmt"
	"sync"
	"time"
)

// KillSwitchStatus represents the current state of a kill switch.
type KillSwitchStatus struct {
	Active      bool   `json:"active"`
	ActivatedAt string `json:"activated_at,omitempty"`
	ActivatedBy string `json:"activated_by,omitempty"`
}

// Switch provides a thread-safe kill switch that can be activated or
// deactivated. Once activated, it records who triggered it and when.
// Deactivation resets the switch to its inactive state.
type Switch struct {
	activated   bool
	activatedAt time.Time
	activatedBy string
	mu          sync.RWMutex
}

// Activate triggers the kill switch, recording the activator and timestamp.
// If the switch is already active, this is a no-op (idempotent).
func (s *Switch) Activate(by string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activated {
		return
	}

	s.activated = true
	s.activatedAt = time.Now()
	s.activatedBy = by
}

// Deactivate resets the kill switch to its inactive state, clearing
// the activation metadata.
func (s *Switch) Deactivate() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.activated = false
	s.activatedAt = time.Time{}
	s.activatedBy = ""
}

// IsActive returns whether the kill switch is currently activated.
func (s *Switch) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.activated
}

// Status returns the current kill switch state including activation
// metadata. If the switch is inactive, ActivatedAt and ActivatedBy
// are empty strings.
func (s *Switch) Status() KillSwitchStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := KillSwitchStatus{
		Active: s.activated,
	}

	if s.activated {
		status.ActivatedAt = s.activatedAt.Format(time.RFC3339)
		status.ActivatedBy = s.activatedBy
	}

	return status
}

// String returns a human-readable representation of the kill switch state.
func (s *Switch) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.activated {
		return "kill-switch: inactive"
	}

	return fmt.Sprintf(
		"kill-switch: active (activated by %q at %s)",
		s.activatedBy,
		s.activatedAt.Format(time.RFC3339),
	)
}
