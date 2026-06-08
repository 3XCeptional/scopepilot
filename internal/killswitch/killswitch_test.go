package killswitch

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Activation / deactivation
// ---------------------------------------------------------------------------

func TestActivate(t *testing.T) {
	var s Switch

	if s.IsActive() {
		t.Fatal("expected switch to be inactive initially")
	}

	s.Activate("alice")

	if !s.IsActive() {
		t.Fatal("expected switch to be active after Activate")
	}

	status := s.Status()
	if !status.Active {
		t.Fatal("expected Status().Active to be true")
	}
	if status.ActivatedBy != "alice" {
		t.Fatalf("expected ActivatedBy 'alice', got %q", status.ActivatedBy)
	}
	if status.ActivatedAt == "" {
		t.Fatal("expected ActivatedAt to be set")
	}
}

func TestDeactivate(t *testing.T) {
	var s Switch

	s.Activate("bob")
	if !s.IsActive() {
		t.Fatal("expected switch to be active after Activate")
	}

	s.Deactivate()

	if s.IsActive() {
		t.Fatal("expected switch to be inactive after Deactivate")
	}

	status := s.Status()
	if status.Active {
		t.Fatal("expected Status().Active to be false after Deactivate")
	}
	if status.ActivatedBy != "" {
		t.Fatalf("expected empty ActivatedBy, got %q", status.ActivatedBy)
	}
	if status.ActivatedAt != "" {
		t.Fatalf("expected empty ActivatedAt, got %q", status.ActivatedAt)
	}
}

func TestActivateDeactivateCycle(t *testing.T) {
	var s Switch

	for i := 0; i < 5; i++ {
		s.Activate("cycle-test")
		if !s.IsActive() {
			t.Fatalf("iteration %d: expected active after Activate", i)
		}

		s.Deactivate()
		if s.IsActive() {
			t.Fatalf("iteration %d: expected inactive after Deactivate", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Idempotent activation
// ---------------------------------------------------------------------------

func TestActivateIdempotentPreservesFirstActivator(t *testing.T) {
	var s Switch

	s.Activate("alice")
	time.Sleep(5 * time.Millisecond) // ensure a different timestamp
	s.Activate("bob")

	status := s.Status()
	if status.ActivatedBy != "alice" {
		t.Fatalf("expected original activator 'alice', got %q", status.ActivatedBy)
	}

	// Ensure the timestamp was not overwritten — it should be close to the
	// first call, not the second.
	parsed, err := time.Parse(time.RFC3339, status.ActivatedAt)
	if err != nil {
		t.Fatalf("failed to parse ActivatedAt: %v", err)
	}

	// The parsed time should be before the second activation attempt.
	secondCall := time.Now()
	if parsed.After(secondCall) || parsed.Equal(secondCall) {
		t.Fatal("expected ActivatedAt to reflect the first activation, not the second")
	}
}

func TestActivateIdempotentMultipleCalls(t *testing.T) {
	var s Switch

	s.Activate("first")
	for i := 0; i < 100; i++ {
		s.Activate("subsequent")
	}

	if !s.IsActive() {
		t.Fatal("expected switch to remain active after multiple idempotent calls")
	}

	status := s.Status()
	if status.ActivatedBy != "first" {
		t.Fatalf("expected activator 'first', got %q", status.ActivatedBy)
	}
}

// ---------------------------------------------------------------------------
// Status reporting
// ---------------------------------------------------------------------------

func TestStatusInactive(t *testing.T) {
	var s Switch

	status := s.Status()
	if status.Active {
		t.Fatal("expected inactive Status().Active to be false")
	}
	if status.ActivatedBy != "" {
		t.Fatalf("expected empty ActivatedBy on inactive switch, got %q", status.ActivatedBy)
	}
	if status.ActivatedAt != "" {
		t.Fatalf("expected empty ActivatedAt on inactive switch, got %q", status.ActivatedAt)
	}
}

func TestStatusActive(t *testing.T) {
	var s Switch

	s.Activate("charlie")
	status := s.Status()

	if !status.Active {
		t.Fatal("expected active Status().Active to be true")
	}
	if status.ActivatedBy != "charlie" {
		t.Fatalf("expected ActivatedBy 'charlie', got %q", status.ActivatedBy)
	}
	if status.ActivatedAt == "" {
		t.Fatal("expected ActivatedAt to be non-empty on active switch")
	}

	// Validate the timestamp format.
	_, err := time.Parse(time.RFC3339, status.ActivatedAt)
	if err != nil {
		t.Fatalf("ActivatedAt is not valid RFC3339: %v", err)
	}
}

func TestStatusAfterDeactivate(t *testing.T) {
	var s Switch

	s.Activate("dave")
	s.Deactivate()

	status := s.Status()
	if status.Active {
		t.Fatal("expected Status().Active to be false after Deactivate")
	}
	if status.ActivatedBy != "" {
		t.Fatalf("expected empty ActivatedBy after Deactivate, got %q", status.ActivatedBy)
	}
	if status.ActivatedAt != "" {
		t.Fatalf("expected empty ActivatedAt after Deactivate, got %q", status.ActivatedAt)
	}
}

// ---------------------------------------------------------------------------
// Zero-value switch
// ---------------------------------------------------------------------------

func TestZeroValueSwitchIsInactive(t *testing.T) {
	var s Switch

	if s.IsActive() {
		t.Fatal("expected zero-value Switch to be inactive")
	}

	status := s.Status()
	if status.Active {
		t.Fatal("expected zero-value Switch Status().Active to be false")
	}
}

// ---------------------------------------------------------------------------
// Concurrent safety
// ---------------------------------------------------------------------------

func TestConcurrentActivateAndRead(t *testing.T) {
	var s Switch
	var wg sync.WaitGroup
	const goroutines = 50

	// Spawn many goroutines that activate and read concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s.Activate("worker")
			_ = s.IsActive()
			_ = s.Status()
		}(i)
	}
	wg.Wait()

	// At least one activation should have taken effect.
	if !s.IsActive() {
		t.Fatal("expected switch to be active after concurrent activation")
	}
}

func TestConcurrentActivateAndDeactivate(t *testing.T) {
	var s Switch
	var wg sync.WaitGroup
	const goroutines = 50

	// Half activate, half deactivate in parallel.
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Activate("racer")
		}()
	}
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Deactivate()
		}()
	}
	wg.Wait()

	// Either state is valid — we just test that no data race occurs and
	// that reading the status works without panicking.
	_ = s.Status()
	_ = s.IsActive()
}

func TestConcurrentReadsNoRace(t *testing.T) {
	var s Switch
	var wg sync.WaitGroup

	s.Activate("safe")

	// Spawn many concurrent readers.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.IsActive()
			_ = s.Status()
			_ = s.String()
		}()
	}
	wg.Wait()
}

func TestConcurrentMixedAccess(t *testing.T) {
	var s Switch
	var wg sync.WaitGroup
	const goroutines = 200

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			switch id % 4 {
			case 0:
				s.Activate("mixed")
			case 1:
				s.Deactivate()
			case 2:
				_ = s.IsActive()
			case 3:
				_ = s.Status()
			}
		}(i)
	}
	wg.Wait()

	// No panic, no data race — final state can be anything.
}

func TestConcurrentStatusConsistency(t *testing.T) {
	var s Switch
	s.Activate("consistent")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status := s.Status()
			// If the switch is reported as active, the metadata must be set.
			if status.Active {
				if status.ActivatedBy == "" {
					t.Error("Status() returned Active=true but empty ActivatedBy")
				}
				if status.ActivatedAt == "" {
					t.Error("Status() returned Active=true but empty ActivatedAt")
				}
			}
		}()
	}
	wg.Wait()
}
