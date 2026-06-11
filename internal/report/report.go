// Package report generates Markdown vulnerability reports from
// Nuclei findings. Reports include severity distribution, findings
// grouped by host, and scan metadata.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportMeta describes the scan that produced the findings.
type ReportMeta struct {
	ProgramID   string
	Tool        string // e.g. "nuclei 3.2.1"
	TemplateDir string
	Targets     []string
	Duration    string // human-readable
	DryRun      bool
}

// RenderFindings produces a Markdown string from raw findings and metadata.
// Each finding string has the format "[severity] host - name (template-id)".
func RenderFindings(findings []string, meta ReportMeta) string {
	var b strings.Builder

	b.WriteString("# Vulnerability Report")
	if meta.ProgramID != "" {
		b.WriteString(" — ")
		b.WriteString(meta.ProgramID)
	}
	b.WriteString("\n\n")

	b.WriteString("**Generated:** ")
	b.WriteString(time.Now().UTC().Format(time.RFC3339))
	b.WriteString("\n\n")

	if meta.Tool != "" {
		b.WriteString("**Tool:** ")
		b.WriteString(meta.Tool)
		b.WriteString("\n\n")
	}
	b.WriteString("**Targets:** ")
	b.WriteString(strings.Join(meta.Targets, ", "))
	b.WriteString("\n\n")
	b.WriteString("**Duration:** ")
	b.WriteString(meta.Duration)
	b.WriteString("\n\n")
	if meta.TemplateDir != "" {
		b.WriteString("**Templates:** ")
		b.WriteString(meta.TemplateDir)
		b.WriteString("\n\n")
	}
	if meta.DryRun {
		b.WriteString("**⚠ Dry run — no actual scan was executed.**\n\n")
	}

	// Severity distribution.
	sevCount := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}
	for _, f := range findings {
		sev := extractSeverity(f)
		sevCount[sev]++
	}

	b.WriteString("## Severity Distribution\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		fmt.Fprintf(&b, "| %s | %d |\n", strings.Title(sev), sevCount[sev])
	}
	b.WriteString("\n")

	// Group findings by host.
	byHost := groupByHost(findings)

	b.WriteString("## Findings by Host\n\n")
	for _, host := range sortedKeys(byHost) {
		fmt.Fprintf(&b, "### %s\n\n", host)
		for _, f := range byHost[host] {
			b.WriteString("- ")
			b.WriteString(f)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(findings) == 0 {
		b.WriteString("_No findings._\n")
	}

	return b.String()
}

// WriteReport renders findings to a Markdown string and writes it to
// findings_<timestamp>.md under the given outputDir. Returns the
// absolute path to the written file. If outputDir is empty, uses
// os.UserCacheDir()/scopepilot/reports.
func WriteReport(findings []string, meta ReportMeta, outputDir string) (string, error) {
	content := RenderFindings(findings, meta)

	if outputDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("report: no output dir and cannot determine user cache dir: %w", err)
		}
		outputDir = filepath.Join(cacheDir, "scopepilot", "reports")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("report: create output dir %q: %w", outputDir, err)
	}

	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	name := fmt.Sprintf("findings_%s.md", ts)
	path := filepath.Join(outputDir, name)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("report: write %q: %w", path, err)
	}

	return path, nil
}

// extractSeverity extracts the severity tag from a finding line.
// Input: "[high] host - name (id)" → "high"
func extractSeverity(finding string) string {
	if !strings.HasPrefix(finding, "[") {
		return "unknown"
	}
	end := strings.Index(finding, "]")
	if end < 0 {
		return "unknown"
	}
	s := strings.ToLower(strings.TrimSpace(finding[1:end]))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "unknown"
	}
}

// groupByHost groups findings by the host extracted from each line.
// Input: "[high] app.example.com - SQLi (cve-001)" → {"app.example.com": [...]}
func groupByHost(findings []string) map[string][]string {
	m := make(map[string][]string)
	for _, f := range findings {
		host := extractHost(f)
		m[host] = append(m[host], f)
	}
	return m
}

// extractHost extracts the hostname between "] " and " - ".
// Input: "[high] app.example.com - SQLi (cve-001)" → "app.example.com"
func extractHost(finding string) string {
	closeBracket := strings.Index(finding, "]")
	if closeBracket < 0 || closeBracket+2 >= len(finding) {
		return "unknown"
	}
	after := finding[closeBracket+2:] // skip "] "
	sep := strings.Index(after, " - ")
	if sep < 0 {
		return "unknown"
	}
	return after[:sep]
}

// sortedKeys returns the keys of m sorted lexicographically.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort for small maps.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
