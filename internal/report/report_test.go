package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleFindings() []string {
	return []string{
		"[critical] api.example.com - SQL Injection (cve-2025-001)",
		"[high] api.example.com - IDOR in User Profile (idor-profile)",
		"[medium] app.example.com - XSS in Login (xss-login)",
		"[info] app.example.com - Tech Detection (tech-detect)",
		"[low] app.example.com - Missing CORS Headers (cors-misconfig)",
		"[high] admin.example.com - Open S3 Bucket (s3-open)",
	}
}

func TestRenderFindings_ContainsHostSections(t *testing.T) {
	meta := ReportMeta{
		ProgramID:   "test-prog",
		Tool:        "nuclei 3.2.1",
		TemplateDir: "/templates",
		Targets:     []string{"api.example.com", "app.example.com", "admin.example.com"},
		Duration:    "1m30s",
	}
	md := RenderFindings(sampleFindings(), meta)

	// Must contain the title
	if !strings.Contains(md, "Vulnerability Report") {
		t.Error("missing title")
	}
	if !strings.Contains(md, "test-prog") {
		t.Error("missing program ID")
	}

	// Must contain host headings
	for _, host := range []string{"api.example.com", "app.example.com", "admin.example.com"} {
		if !strings.Contains(md, "### "+host) {
			t.Errorf("missing host section for %q", host)
		}
	}

	// Must contain all finding lines
	for _, f := range sampleFindings() {
		if !strings.Contains(md, f) {
			t.Errorf("missing finding: %q", f)
		}
	}
}

func TestRenderFindings_SeverityDistribution(t *testing.T) {
	md := RenderFindings(sampleFindings(), ReportMeta{})

	// Must have severity table
	if !strings.Contains(md, "| Severity | Count |") {
		t.Error("missing severity table header")
	}
	// Check counts: 1 critical, 2 high, 1 medium, 1 low, 1 info, 0 unknown
	checks := map[string]string{
		"critical": "| Critical | 1 |",
		"high":     "| High | 2 |",
		"medium":   "| Medium | 1 |",
		"low":      "| Low | 1 |",
		"info":     "| Info | 1 |",
		"unknown":  "| Unknown | 0 |",
	}
	for sev, row := range checks {
		if !strings.Contains(md, row) {
			t.Errorf("missing or incorrect severity count for %q: expected row %q", sev, row)
		}
	}
}

func TestRenderFindings_Empty(t *testing.T) {
	md := RenderFindings(nil, ReportMeta{ProgramID: "empty-prog"})
	if !strings.Contains(md, "No findings") {
		t.Error("expected 'No findings' for empty slice")
	}
	if !strings.Contains(md, "empty-prog") {
		t.Error("missing program ID")
	}
}

func TestRenderFindings_DryRunBanner(t *testing.T) {
	md := RenderFindings(nil, ReportMeta{DryRun: true})
	if !strings.Contains(md, "Dry run") {
		t.Error("expected dry run banner")
	}
}

func TestWriteReport_CreatesFile(t *testing.T) {
	outDir := t.TempDir()
	meta := ReportMeta{
		ProgramID: "write-test",
		Targets:   []string{"x.com"},
	}
	path, err := WriteReport(sampleFindings(), meta, outDir)
	if err != nil {
		t.Fatalf("WriteReport failed: %v", err)
	}

	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %q", path)
	}
	if !strings.HasPrefix(filepath.Base(path), "findings_") {
		t.Errorf("expected findings_ prefix, got %q", filepath.Base(path))
	}
	if !strings.HasSuffix(path, ".md") {
		t.Errorf("expected .md suffix, got %q", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read written report: %v", err)
	}
	if !strings.Contains(string(data), "write-test") {
		t.Error("report file missing program ID")
	}
	if !strings.Contains(string(data), "api.example.com") {
		t.Error("report file missing findings")
	}
}

func TestWriteReport_DefaultOutputDir(t *testing.T) {
	// When outputDir is empty, WriteReport uses os.UserCacheDir().
	// Just verify it doesn't panic and returns a sensible path.
	meta := ReportMeta{ProgramID: "default-dir-test"}
	path, err := WriteReport([]string{"[info] test.com - Test (test)"}, meta, "")
	if err != nil {
		t.Fatalf("WriteReport with default dir failed: %v", err)
	}
	defer os.Remove(path)

	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if !strings.Contains(path, "scopepilot") {
		t.Errorf("expected scopepilot in default path, got %q", path)
	}
}

func TestGroupByHost(t *testing.T) {
	findings := []string{
		"[info] a.com - X (t1)",
		"[high] b.com - Y (t2)",
		"[low] a.com - Z (t3)",
	}
	grouped := groupByHost(findings)
	if len(grouped["a.com"]) != 2 {
		t.Errorf("expected 2 findings for a.com, got %d", len(grouped["a.com"]))
	}
	if len(grouped["b.com"]) != 1 {
		t.Errorf("expected 1 finding for b.com, got %d", len(grouped["b.com"]))
	}
}

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[critical] h - n (t)", "critical"},
		{"[high] h - n (t)", "high"},
		{"[medium] h - n (t)", "medium"},
		{"[low] h - n (t)", "low"},
		{"[info] h - n (t)", "info"},
		{"naked line", "unknown"},
		{"", "unknown"},
		{"[bogus] h - n (t)", "unknown"},
	}
	for _, tc := range tests {
		got := extractSeverity(tc.input)
		if got != tc.want {
			t.Errorf("extractSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[high] api.example.com - SQLi (cve-001)", "api.example.com"},
		{"[info] app.example.com - Tech (tech)", "app.example.com"},
		{"naked line", "unknown"},
		{"", "unknown"},
		{"[] ", "unknown"},
	}
	for _, tc := range tests {
		got := extractHost(tc.input)
		if got != tc.want {
			t.Errorf("extractHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRenderFindings_TitleCasedSeverity(t *testing.T) {
	// Verify the severity table uses proper title casing (not raw lowercase).
	md := RenderFindings([]string{"[critical] h - n (t)", "[high] h - n (t)"}, ReportMeta{})
	// Each severity should be Title-cased: Critical, High, etc.
	for _, expected := range []string{"| Critical |", "| High |"} {
		if !strings.Contains(md, expected) {
			t.Errorf("expected title-cased %q in severity table", expected)
		}
	}
	// Raw lowercase in the table header is wrong.
	if strings.Contains(md, "| critical |") {
		t.Error("found lowercase severity in table, expected title-cased")
	}
}

func TestRenderFindings_StartTimeInReport(t *testing.T) {
	fixedTime := time.Date(2026, 6, 12, 10, 30, 0, 0, time.UTC)
	meta := ReportMeta{
		ProgramID: "starttime-test",
		StartTime: fixedTime,
	}
	md := RenderFindings(nil, meta)
	if !strings.Contains(md, "2026-06-12T10:30:00Z") {
		t.Errorf("expected StartTime in report, got: %s", md)
	}
	if !strings.Contains(md, "starttime-test") {
		t.Error("missing program ID")
	}
}

func TestRenderFindings_StartTimeZeroUsesNow(t *testing.T) {
	// When StartTime is zero, the report should contain a timestamp
	// close to the current time (within a few seconds).
	before := time.Now().UTC().Format(time.RFC3339)
	md := RenderFindings(nil, ReportMeta{ProgramID: "now-test"})
	// The report should contain a timestamp that sorts after 'before'
	// and has the same date prefix.
	if !strings.Contains(md, "now-test") {
		t.Error("missing program ID")
	}
	// Just verify a timestamp line exists.
	if !strings.Contains(md, "**Generated:** ") {
		t.Error("missing Generated line")
	}
	// The timestamp should be non-empty and contain a T (RFC3339).
	// We can't test exact equality since time passes, but we can check format.
	generated := md[strings.Index(md, "**Generated:** ")+len("**Generated:** "):]
	end := strings.Index(generated, "\n")
	if end > 0 {
		ts := strings.TrimSpace(generated[:end])
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("Generated timestamp %q is not valid RFC3339: %v", ts, err)
		}
		if ts < before {
			t.Errorf("Generated timestamp %q should not be before test start %q", ts, before)
		}
	}
}
