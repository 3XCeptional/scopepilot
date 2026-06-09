// Package adapter provides safe wrappers for external recon tools
// (BBOT, Nuclei) that route all traffic through ScopePilot's scope proxy
// and MCP interface. Tools never receive out-of-scope targets.
package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"os/exec"
)

// MCPClient communicates with the ScopePilot MCP server.
type MCPClient struct {
	BaseURL    string
	HTTPClient *http.Client
	ProgramID  string
}

// MCPRequest is a JSON-RPC 2.0 request.
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int         `json:"id"`
}

// MCPResponse is a JSON-RPC 2.0 response.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC error.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SafeCheckResult is the result of checking a URL against scope.
type SafeCheckResult struct {
	URL        string `json:"url"`
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	BlockedIP  bool   `json:"blocked_ip,omitempty"`
	DeniedHost bool   `json:"denied_host,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
}

// RunSafeCheckResponse is the result of a batch safe-check call.
type RunSafeCheckResponse struct {
	Results []SafeCheckResult `json:"results"`
}

// NewMCPClient creates a new MCP client.
func NewMCPClient(baseURL, programID string) *MCPClient {
	return &MCPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		ProgramID:  programID,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// CheckURL validates a single URL through the MCP server.
func (c *MCPClient) CheckURL(ctx context.Context, url string) (*SafeCheckResult, error) {
	req := MCPRequest{
		JSONRPC: "2.0",
		Method:  "call_tool",
		Params: map[string]interface{}{
			"name": "check_url",
			"arguments": map[string]interface{}{
				"url": url,
			},
		},
		ID: 1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/mcp", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("mcp error %d: %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	var result SafeCheckResult
	if err := json.Unmarshal(mcpResp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}

	return &result, nil
}

// RunSafeCheck validates a batch of URLs through the MCP server.
func (c *MCPClient) RunSafeCheck(ctx context.Context, urls []string) (*RunSafeCheckResponse, error) {
	req := MCPRequest{
		JSONRPC: "2.0",
		Method:  "call_tool",
		Params: map[string]interface{}{
			"name": "run_safe_check",
			"arguments": map[string]interface{}{
				"urls": urls,
			},
		},
		ID: 1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/mcp", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("mcp error %d: %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	var result RunSafeCheckResponse
	if err := json.Unmarshal(mcpResp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}

	return &result, nil
}

// BBOTConfig holds configuration for the BBOT adapter.
type BBOTConfig struct {
	BinaryPath string // Path to bbot binary
	MCPClient  *MCPClient
	DryRun     bool // If true, only check scope, don't execute BBOT
	Timeout    time.Duration
	ProxyURL   string // HTTP proxy URL (e.g. http://127.0.0.1:8443); empty = no proxy
}

// NucleiConfig holds configuration for the Nuclei adapter.
type NucleiConfig struct {
	BinaryPath  string // Path to nuclei binary
	MCPClient   *MCPClient
	DryRun      bool
	Timeout     time.Duration
	TemplateDir string // Path to nuclei templates
	ProxyURL    string // HTTP proxy URL (e.g. http://127.0.0.1:8443); empty = no proxy
}

// BBOTResult holds structured results from a BBOT scan.
type BBOTResult struct {
	TargetsScanned  int      `json:"targets_scanned"`
	TargetsBlocked  int      `json:"targets_blocked"`
	SubdomainsFound []string `json:"subdomains_found,omitempty"`
	RawOutput       string   `json:"raw_output,omitempty"`
	DryRun          bool     `json:"dry_run"`
	Errors          []string `json:"errors,omitempty"`
}

// NucleiResult holds structured results from a Nuclei scan.
type NucleiResult struct {
	TargetsScanned int      `json:"targets_scanned"`
	TargetsBlocked int      `json:"targets_blocked"`
	Findings       []string `json:"findings,omitempty"`
	RawOutput      string   `json:"raw_output,omitempty"`
	DryRun         bool     `json:"dry_run"`
	Errors         []string `json:"errors,omitempty"`
}

// FilterInScope checks a list of hostnames against ScopePilot's MCP
// and returns only those that pass scope validation.
func (c *MCPClient) FilterInScope(ctx context.Context, hosts []string) ([]string, []string) {
	var inScope []string
	var blocked []string

	for _, host := range hosts {
		url := "https://" + host
		result, err := c.CheckURL(ctx, url)
		if err != nil {
			blocked = append(blocked, host)
			continue
		}
		if result != nil && result.Allowed {
			inScope = append(inScope, host)
		} else {
			blocked = append(blocked, host)
		}
	}

	return inScope, blocked
}

// RunBBOT runs BBOT against in-scope targets through the scope proxy.
func RunBBOT(ctx context.Context, cfg BBOTConfig, targets []string) (*BBOTResult, error) {
	result := &BBOTResult{DryRun: cfg.DryRun}

	// Step 1: Filter targets through MCP scope check.
	inScope, blocked := cfg.MCPClient.FilterInScope(ctx, targets)
	result.TargetsBlocked = len(blocked)

	if cfg.DryRun {
		result.TargetsScanned = len(inScope)
		return result, nil
	}

	if len(inScope) == 0 {
		return result, nil
	}

	// Step 2: Build BBOT command with safe args.
	// Use: bbot -t <targets> --no-dns --no-www --force -o json -n <output-dir>
	// Only passive modules: --passive-only
	// No exploitation flags.
	args := []string{
		"-t", strings.Join(inScope, ","),
		"--passive-only",
		"--no-dns",
		"--no-www",
		"--force",
		"-o", "json",
	}

	if cfg.ProxyURL != "" {
		args = append(args, "--proxy", cfg.ProxyURL)
	}

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// BBOT may return non-zero for some failures — still parse output.
		result.Errors = append(result.Errors, fmt.Sprintf("bbot exited: %v", err))
	}

	result.TargetsScanned = len(inScope)
	result.RawOutput = string(output)
	result.SubdomainsFound = parseBBOTOutput(string(output))

	return result, nil
}

// parseBBOTOutput extracts subdomains and hosts from BBOT JSON output.
func parseBBOTOutput(output string) []string {
	var hosts []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// BBOT JSON output has a "host" field in each event.
		var event struct {
			Host string `json:"host"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Host != "" {
			hosts = append(hosts, event.Host)
		}
	}
	return hosts
}

// RunNuclei runs Nuclei against in-scope targets through the scope proxy.
func RunNuclei(ctx context.Context, cfg NucleiConfig, targets []string) (*NucleiResult, error) {
	result := &NucleiResult{DryRun: cfg.DryRun}

	// Step 1: Filter targets through MCP scope check.
	inScope, blocked := cfg.MCPClient.FilterInScope(ctx, targets)
	result.TargetsBlocked = len(blocked)

	if cfg.DryRun {
		result.TargetsScanned = len(inScope)
		return result, nil
	}

	if len(inScope) == 0 {
		return result, nil
	}

	// Step 2: Build Nuclei command with safe args.
	// Use: nuclei -u <target> -t <templates> -json -o - — only passive/tech detection
	// --no-httpx, --no-format, --bulk-size, --concurrency low.
	// Explicitly no exploit/severity flags that would cause exploitation.
	args := []string{
		"-u", strings.Join(inScope, ","),
		"-t", cfg.TemplateDir,
		"-json",
		"-o", "-",
		"--no-httpx",
		"--bulk-size", "5",
		"--concurrency", "2",
	}

	if cfg.ProxyURL != "" {
		args = append(args, "-proxy", cfg.ProxyURL)
	}

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("nuclei exited: %v", err))
	}

	result.TargetsScanned = len(inScope)
	result.RawOutput = string(output)
	result.Findings = parseNucleiOutput(string(output))

	return result, nil
}

// parseNucleiOutput extracts findings from Nuclei JSON output.
func parseNucleiOutput(output string) []string {
	var findings []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Each line of Nuclei JSON output is a finding.
		var finding struct {
			TemplateID string `json:"template-id"`
			Name       string `json:"name"`
			Severity   string `json:"severity"`
			Host       string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &finding); err == nil && finding.TemplateID != "" {
			findings = append(findings, fmt.Sprintf("[%s] %s - %s (%s)",
				finding.Severity, finding.Host, finding.Name, finding.TemplateID))
		}
	}
	return findings
}
