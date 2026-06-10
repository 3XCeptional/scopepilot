package specialist

import (
	"context"
	"fmt"
	"time"

	"github.com/dhiren/pentest-automation/internal/adapter"
)

// Recon is a passive reconnaissance specialist that wraps BBOT
// with safety constraints. It runs only passive modules — no DNS
// resolution, no active scanning, no exploitation.
type Recon struct {
	startTime time.Time
}

// NewRecon creates a new Recon specialist.
func NewRecon() *Recon {
	return &Recon{}
}

// Name returns the specialist name.
func (r *Recon) Name() string {
	return "recon"
}

// Description returns a human-readable description.
func (r *Recon) Description() string {
	return "Passive reconnaissance via BBOT. Discovers subdomains, technologies, " +
		"and associated infrastructure using passive-only modules. " +
		"No active scanning or exploitation. All traffic is routed through " +
		"the scope proxy."
}

// Run executes passive reconnaissance against the given targets.
// It filters targets through the scope proxy, then runs BBOT with
// --passive-only, --no-dns, --no-www flags and returns structured results.
func (r *Recon) Run(ctx context.Context, targets []string, cfg Config) (*Result, error) {
	r.startTime = time.Now()

	// Step 1: Filter targets through MCP scope check.
	inScope, blocked, err := filterScope(ctx, targets, cfg)
	if err != nil {
		return nil, fmt.Errorf("scope check: %w", err)
	}

	// Step 2: Build the BBOT adapter config from specialist config.
	bbotCfg := adapter.BBOTConfig{
		BinaryPath:   cfg.BBOTBinary,
		MCPClient:    mcpClient(cfg),
		DryRun:       cfg.DryRun,
		Timeout:      cfg.Timeout,
		ProxyURL:     cfg.ProxyURL,
		VPNContainer: cfg.VPNContainer,
	}

	// Step 3: Run BBOT via adapter.
	bbotResult, err := adapter.RunBBOT(ctx, bbotCfg, inScope)
	if err != nil {
		return nil, fmt.Errorf("bbot run: %w", err)
	}

	// Step 4: Build structured Result.
	findingsCount := len(bbotResult.SubdomainsFound)

	result := &Result{
		Specialist:     r.Name(),
		TargetsIn:      len(targets),
		TargetsPassed:  len(inScope),
		TargetsBlocked: len(blocked),
		Findings:       findingsCount,
		DryRun:         cfg.DryRun,
		Duration:       time.Since(r.startTime).Round(time.Millisecond).String(),
		Details: map[string]interface{}{
			"subdomains_found": bbotResult.SubdomainsFound,
			"targets_scanned":  bbotResult.TargetsScanned,
			"raw_output":       bbotResult.RawOutput,
		},
	}

	if len(bbotResult.Errors) > 0 {
		result.Error = fmt.Sprintf("bbot reported %d errors: %v", len(bbotResult.Errors), bbotResult.Errors)
	}

	return result, nil
}
