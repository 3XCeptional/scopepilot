// Package specialist provides bounded MCP agents for specific security
// testing tasks. Each specialist wraps a tool (BBOT, Nuclei) with safety
// constraints: scope validation via proxy, rate limiting, and kill-switch
// enforcement.
//
// Specialists are MCP-callable tools that run through the safety chain:
//
//	Agent → MCP → Specialist → Scope Check → Execute → Structured Result
//
// Three specialists:
//   - Recon:   Passive recon via BBOT (subdomains, tech detection)
//   - Vuln:    Safe vulnerability checks via Nuclei (passive templates)
//   - Gate:    Verified-only exploit verification (requires kill-switch OK)
package specialist

import (
	"context"
	"time"

	"github.com/dhiren/pentest-automation/internal/adapter"
)

// Config holds shared specialist configuration.
type Config struct {
	BBOTBinary        string        // Path to bbot binary
	NucleiBinary      string        // Path to nuclei binary
	TemplateDir       string        // Path to nuclei templates
	MCPURL            string        // URL of the MCP server (for scope checking)
	MCPAPIKey         string        // Bearer token for MCP authentication
	ProgramID         string        // Program ID for scope checking
	ProxyURL          string        // HTTP proxy URL (scope proxy)
	VPNContainer      string        // VPN namespace requested by policy; host adapters fail closed when set
	DryRun            bool          // Validate only, no execution
	Timeout           time.Duration // Max execution time
	AllowExploitation bool          // Explicit human approval for Gate specialist. Must be true for Gate to execute.
	OutputDir         string        // Directory for auto-generated findings reports (empty = os.UserCacheDir())
}

// Result is the common specialist result structure.
type Result struct {
	Specialist     string      `json:"specialist"`
	TargetsIn      int         `json:"targets_in"`
	TargetsPassed  int         `json:"targets_passed"`
	TargetsBlocked int         `json:"targets_blocked"`
	Findings       int         `json:"findings"`
	DryRun         bool        `json:"dry_run"`
	Error          string      `json:"error,omitempty"`
	Details        interface{} `json:"details,omitempty"`
	Duration       string      `json:"duration"`
}

// Specialist is the interface for a bounded task agent.
type Specialist interface {
	// Name returns the specialist name (recon, vuln, gate).
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Run executes the specialist task against the given targets.
	Run(ctx context.Context, targets []string, cfg Config) (*Result, error)
}

// mcpClient creates a safe-check MCP client from config.
func mcpClient(cfg Config) *adapter.MCPClient {
	return adapter.NewMCPClientWithAPIKey(cfg.MCPURL, cfg.ProgramID, cfg.MCPAPIKey)
}

// filterScope checks targets against the scope proxy and returns
// only those that pass all safety checks.
func filterScope(ctx context.Context, targets []string, cfg Config) ([]string, []string, error) {
	client := mcpClient(cfg)
	inScope, blocked := client.FilterInScope(ctx, targets)
	return inScope, blocked, nil
}
