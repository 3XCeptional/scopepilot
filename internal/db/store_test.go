package db

import (
	"testing"
	"time"
)

func TestMemoryStore_RecordAssets(t *testing.T) {
	s := NewMemoryStore(100)

	// Record initial assets
	assets := []Asset{
		{Host: "api.example.com", Source: "bbot", InScope: true, Tech: []string{"nginx"}},
		{Host: "admin.example.com", Source: "bbot", InScope: true},
	}
	if err := s.RecordAssets("crystal", assets); err != nil {
		t.Fatalf("RecordAssets failed: %v", err)
	}

	got, err := s.GetAssets("crystal")
	if err != nil {
		t.Fatalf("GetAssets failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(got))
	}

	// Upsert same host with new source + tech
	upsert := []Asset{
		{Host: "api.example.com", Source: "manual", Tech: []string{"python"}},
	}
	if err := s.RecordAssets("crystal", upsert); err != nil {
		t.Fatalf("RecordAssets upsert failed: %v", err)
	}

	got2, _ := s.GetAssets("crystal")
	if len(got2) != 2 {
		t.Fatalf("expected 2 assets after upsert, got %d", len(got2))
	}
	// Verify merge
	for _, a := range got2 {
		if a.Host == "api.example.com" {
			if a.Source != "bbot,manual" {
				t.Errorf("expected merged source 'bbot,manual', got %q", a.Source)
			}
			if len(a.Tech) != 2 {
				t.Errorf("expected 2 techs (nginx+python), got %d: %v", len(a.Tech), a.Tech)
			}
		}
	}
}

func TestMemoryStore_GetAssets_EmptyProgram(t *testing.T) {
	s := NewMemoryStore(100)
	got, err := s.GetAssets("nonexistent")
	if err != nil {
		t.Fatalf("GetAssets failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 assets for empty program, got %d", len(got))
	}
}

func TestMemoryStore_RecordFinding(t *testing.T) {
	s := NewMemoryStore(100)

	f := Finding{
		Title:    "IDOR in user profile",
		Severity: "high",
		Host:     "api.example.com",
		Status:   "open",
	}
	if err := s.RecordFinding("crystal", f); err != nil {
		t.Fatalf("RecordFinding failed: %v", err)
	}

	got, err := s.GetFindings("crystal")
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Title != f.Title {
		t.Errorf("expected title %q, got %q", f.Title, got[0].Title)
	}
	if got[0].ID == "" {
		t.Error("expected auto-generated ID")
	}
	if got[0].Created.IsZero() {
		t.Error("expected non-zero Created time")
	}
}

func TestMemoryStore_GetFindings_EmptyProgram(t *testing.T) {
	s := NewMemoryStore(100)
	got, err := s.GetFindings("nonexistent")
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestMemoryStore_MarkTested(t *testing.T) {
	s := NewMemoryStore(100)

	te := TestedEndpoint{
		Host:     "admin.example.com",
		Endpoint: "/actuator/health",
		Check:    "actuator",
		Result:   "not_vulnerable",
	}
	if err := s.MarkTested("crystal", te); err != nil {
		t.Fatalf("MarkTested failed: %v", err)
	}

	got, err := s.GetTested("crystal")
	if err != nil {
		t.Fatalf("GetTested failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 tested endpoint, got %d", len(got))
	}
	if got[0].Check != "actuator" {
		t.Errorf("expected check 'actuator', got %q", got[0].Check)
	}
	if got[0].TestedAt.IsZero() {
		t.Error("expected non-zero TestedAt time")
	}
}

func TestMemoryStore_RecordAssets_UpsertLastSeen(t *testing.T) {
	s := NewMemoryStore(100)

	// Record asset once
	s.RecordAssets("crystal", []Asset{{Host: "x.example.com", Source: "bbot"}})
	initial, _ := s.GetAssets("crystal")
	firstSeen := initial[0].LastSeen

	// Wait a moment, then upsert
	time.Sleep(time.Millisecond)
	s.RecordAssets("crystal", []Asset{{Host: "x.example.com", Source: "manual"}})

	updated, _ := s.GetAssets("crystal")
	if !updated[0].LastSeen.After(firstSeen) {
		t.Error("expected LastSeen to be updated on upsert")
	}
}

func TestMemoryStore_SeparatePrograms(t *testing.T) {
	s := NewMemoryStore(100)

	s.RecordAssets("program-a", []Asset{{Host: "a.com", Source: "bbot"}})
	s.RecordAssets("program-b", []Asset{{Host: "b.com", Source: "bbot"}})
	s.RecordFinding("program-a", Finding{Title: "XSS in a.com", Severity: "medium"})

	aAssets, _ := s.GetAssets("program-a")
	bAssets, _ := s.GetAssets("program-b")
	aFindings, _ := s.GetFindings("program-a")
	bFindings, _ := s.GetFindings("program-b")

	if len(aAssets) != 1 || aAssets[0].Host != "a.com" {
		t.Error("program-a should have a.com asset")
	}
	if len(bAssets) != 1 || bAssets[0].Host != "b.com" {
		t.Error("program-b should have b.com asset")
	}
	if len(aFindings) != 1 {
		t.Error("program-a should have 1 finding")
	}
	if len(bFindings) != 0 {
		t.Error("program-b should have 0 findings")
	}
}

func TestMergeTech(t *testing.T) {
	a := []string{"nginx", "python"}
	b := []string{"python", "postgres"}
	got := mergeTech(a, b)
	if len(got) != 3 {
		t.Errorf("expected 3 unique techs, got %d: %v", len(got), got)
	}
}

func TestNewID(t *testing.T) {
	id1 := newID()
	id2 := newID()
	if id1 == "" || id2 == "" {
		t.Error("expected non-empty IDs")
	}
	if id1 == id2 {
		t.Error("expected unique IDs")
	}
}
