package specialist

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dhiren/pentest-automation/internal/adapter"
	"github.com/dhiren/pentest-automation/internal/report"
)

// Vuln is a vulnerability assessment specialist that wraps Nuclei
// with safety constraints. It runs only passive/tech-detection templates
// — no active exploitation or intrusive scanning.
type Vuln struct {
	startTime time.Time
}

// NewVuln creates a new Vuln specialist.
func NewVuln() *Vuln {
	return &Vuln{}
}

// Name returns the specialist name.
func (v *Vuln) Name() string {
	return "vuln"
}

// Description returns a human-readable description.
func (v *Vuln) Description() string {
	return "Safe vulnerability scanning via Nuclei. Uses only passive and " +
		"technology-detection templates (severity: info, low). " +
		"No active exploitation or intrusive HTTP requests. " +
		"All traffic is routed through the scope proxy."
}

// severityBuckets groups findings by severity level.
type severityBuckets struct {
	Info     []string `json:"info,omitempty"`
	Low      []string `json:"low,omitempty"`
	Medium   []string `json:"medium,omitempty"`
	High     []string `json:"high,omitempty"`
	Critical []string `json:"critical,omitempty"`
	Unknown  []string `json:"unknown,omitempty"`
}

// Run executes safe vulnerability scanning against the given targets.
// It filters targets through the scope proxy, then runs Nuclei with
// passive templates and returns findings bucketed by severity.
func (v *Vuln) Run(ctx context.Context, targets []string, cfg Config) (*Result, error) {
	v.startTime = time.Now()

	// Step 1: Filter targets through MCP scope check.
	inScope, blocked, err := filterScope(ctx, targets, cfg)
	if err != nil {
		return nil, fmt.Errorf("scope check: %w", err)
	}

	// Step 2: Build the Nuclei adapter config from specialist config.
	nucleiCfg := adapter.NucleiConfig{
		BinaryPath:   cfg.NucleiBinary,
		MCPClient:    mcpClient(cfg),
		DryRun:       cfg.DryRun,
		Timeout:      cfg.Timeout,
		TemplateDir:  cfg.TemplateDir,
		Severities:   []string{"info", "low"},
		ProxyURL:     cfg.ProxyURL,
		VPNContainer: cfg.VPNContainer,
	}

	// Step 3: Run Nuclei via adapter.
	nucleiResult, err := adapter.RunNuclei(ctx, nucleiCfg, inScope)
	if err != nil {
		return nil, fmt.Errorf("nuclei run: %w", err)
	}

	// Step 4: Bucket findings by severity.
	buckets := bucketBySeverity(nucleiResult.Findings)

	result := &Result{
		Specialist:     v.Name(),
		TargetsIn:      len(targets),
		TargetsPassed:  len(inScope),
		TargetsBlocked: len(blocked),
		Findings:       len(nucleiResult.Findings),
		DryRun:         cfg.DryRun,
		Duration:       time.Since(v.startTime).Round(time.Millisecond).String(),
		Details: map[string]interface{}{
			"severity_buckets": buckets,
			"targets_scanned":  nucleiResult.TargetsScanned,
			"raw_output":       nucleiResult.RawOutput,
		},
	}

	if len(nucleiResult.Errors) > 0 {
		result.Error = fmt.Sprintf("nuclei reported %d errors: %v", len(nucleiResult.Errors), nucleiResult.Errors)
	}

	// Auto-generate findings report (skip in dry-run mode).
	if !cfg.DryRun && len(nucleiResult.Findings) > 0 {
		meta := report.ReportMeta{
			ProgramID:   cfg.ProgramID,
			Tool:        "nuclei",
			TemplateDir: cfg.TemplateDir,
			Targets:     targets,
			Duration:    result.Duration,
		}
		if p, err := report.WriteReport(nucleiResult.Findings, meta, cfg.OutputDir); err == nil {
			details, ok := result.Details.(map[string]interface{})
			if !ok {
				details = make(map[string]interface{})
			}
			details["report_path"] = p
			result.Details = details
		}
	}

	return result, nil
}

// bucketBySeverity groups Nuclei finding strings by their severity tag.
// Finding format: "[severity] host - name (template-id)"
func bucketBySeverity(findings []string) severityBuckets {
	var buckets severityBuckets

	for _, f := range findings {
		if !strings.HasPrefix(f, "[") {
			buckets.Unknown = append(buckets.Unknown, f)
			continue
		}

		end := strings.Index(f, "]")
		if end < 0 {
			buckets.Unknown = append(buckets.Unknown, f)
			continue
		}

		severity := strings.ToLower(strings.TrimSpace(f[1:end]))

		switch severity {
		case "info":
			buckets.Info = append(buckets.Info, f)
		case "low":
			buckets.Low = append(buckets.Low, f)
		case "medium":
			buckets.Medium = append(buckets.Medium, f)
		case "high":
			buckets.High = append(buckets.High, f)
		case "critical":
			buckets.Critical = append(buckets.Critical, f)
		default:
			buckets.Unknown = append(buckets.Unknown, f)
		}
	}

	return buckets
}
