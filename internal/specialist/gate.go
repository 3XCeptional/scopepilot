package specialist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dhiren/pentest-automation/internal/adapter"
)

// Gate is an exploit verification specialist that wraps Nuclei with
// verified-only templates. It requires the kill switch to be inactive
// before execution and documents the explicit approval step needed.
//
// APPROVAL REQUIREMENT:
// This specialist MUST NOT be invoked without explicit, documented
// human approval. The operator must confirm in writing that:
//  1. All targets are verified in-scope and authorized for testing.
//  2. The kill switch is inactive (checked automatically).
//  3. This is a verified-exploit-only scan (no intrusive fuzzing).
//
// The gate specialist performs an automatic kill-switch check before
// running and refuses to execute if the kill switch is active.
type Gate struct {
	startTime time.Time
}

// NewGate creates a new Gate specialist.
func NewGate() *Gate {
	return &Gate{}
}

// Name returns the specialist name.
func (g *Gate) Name() string {
	return "gate"
}

// Description returns a human-readable description.
func (g *Gate) Description() string {
	return "Verified-exploit verification via Nuclei. Uses only verified " +
		"templates (severity: medium, high, critical). " +
		"REQUIRES EXPLICIT HUMAN APPROVAL before invocation. " +
		"Automatically checks that the kill switch is inactive. " +
		"All traffic is routed through the scope proxy."
}

// killSwitchActive checks whether the MCP server reports the kill switch
// as active. Returns true if active (meaning execution should be blocked).
func killSwitchActive(ctx context.Context, cfg Config) (bool, string, error) {
	client := mcpClient(cfg)

	req := adapter.MCPRequest{
		JSONRPC: "2.0",
		Method:  "call_tool",
		Params: map[string]interface{}{
			"name":      "is_kill_switch_active",
			"arguments": map[string]interface{}{},
		},
		ID: 1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return false, "", fmt.Errorf("marshal kill-switch request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		client.BaseURL+"/mcp", strings.NewReader(string(body)))
	if err != nil {
		return false, "", fmt.Errorf("create kill-switch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.MCPAPIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.MCPAPIKey)
	}

	resp, err := client.HTTPClient.Do(httpReq)
	if err != nil {
		return false, "", fmt.Errorf("kill-switch MCP request: %w", err)
	}
	defer resp.Body.Close()

	var mcpResp adapter.MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return false, "", fmt.Errorf("decode kill-switch response: %w", err)
	}

	if mcpResp.Error != nil {
		return false, "", fmt.Errorf("kill-switch MCP error %d: %s",
			mcpResp.Error.Code, mcpResp.Error.Message)
	}

	var status struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(mcpResp.Result, &status); err != nil {
		return false, "", fmt.Errorf("unmarshal kill-switch status: %w", err)
	}

	return status.Active, "", nil
}

// Run executes verified-only exploit verification against the given targets.
// It first checks that the kill switch is inactive, filters targets through
// the scope proxy, then runs Nuclei with verified templates.
//
// This specialist MUST only be invoked after explicit human approval
// (see the type-level doc comment for the approval checklist).
func (g *Gate) Run(ctx context.Context, targets []string, cfg Config) (*Result, error) {
	g.startTime = time.Now()

	// Step 0: Require explicit human approval. This specialist performs
	// verified-exploit verification and MUST NOT run without documented
	// operator consent.
	if !cfg.AllowExploitation {
		return nil, fmt.Errorf("gate specialist requires explicit human approval — set AllowExploitation=true in Config to confirm all targets are authorised for exploitation testing")
	}

	// Step 1: Check kill switch. If active, refuse to run.
	active, _, err := killSwitchActive(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("kill-switch check failed: %w", err)
	}
	if active {
		return &Result{
			Specialist:     g.Name(),
			TargetsIn:      len(targets),
			TargetsPassed:  0,
			TargetsBlocked: len(targets),
			Findings:       0,
			DryRun:         cfg.DryRun,
			Error:          "kill switch is active — exploitation gate blocked. Deactivate the kill switch before retrying.",
			Duration:       time.Since(g.startTime).Round(time.Millisecond).String(),
			Details: map[string]interface{}{
				"kill_switch_blocked": true,
				"reason":              "kill switch is active, execution refused",
			},
		}, nil
	}

	// Step 2: Filter targets through MCP scope check.
	inScope, blocked, err := filterScope(ctx, targets, cfg)
	if err != nil {
		return nil, fmt.Errorf("scope check: %w", err)
	}

	// Step 3: Build the Nuclei adapter config from specialist config.
	nucleiCfg := adapter.NucleiConfig{
		BinaryPath:   cfg.NucleiBinary,
		MCPClient:    mcpClient(cfg),
		DryRun:       cfg.DryRun,
		Timeout:      cfg.Timeout,
		TemplateDir:  cfg.TemplateDir,
		Severities:   []string{"medium", "high", "critical"},
		ProxyURL:     cfg.ProxyURL,
		VPNContainer: cfg.VPNContainer,
	}

	// Step 4: Run Nuclei via adapter.
	nucleiResult, err := adapter.RunNuclei(ctx, nucleiCfg, inScope)
	if err != nil {
		return nil, fmt.Errorf("nuclei run: %w", err)
	}

	// Step 5: Build structured Result with verified-only context.
	result := &Result{
		Specialist:     g.Name(),
		TargetsIn:      len(targets),
		TargetsPassed:  len(inScope),
		TargetsBlocked: len(blocked),
		Findings:       len(nucleiResult.Findings),
		DryRun:         cfg.DryRun,
		Duration:       time.Since(g.startTime).Round(time.Millisecond).String(),
		Details: map[string]interface{}{
			"kill_switch_checked": true,
			"kill_switch_active":  false,
			"verified_findings":   nucleiResult.Findings,
			"targets_scanned":     nucleiResult.TargetsScanned,
			"raw_output":          nucleiResult.RawOutput,
		},
	}

	if len(nucleiResult.Errors) > 0 {
		result.Error = fmt.Sprintf("nuclei reported %d errors: %v",
			len(nucleiResult.Errors), nucleiResult.Errors)
	}

	return result, nil
}
