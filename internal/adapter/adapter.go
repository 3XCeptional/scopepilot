// Package adapter provides safe wrappers for external recon tools
// (BBOT, Nuclei) that route all traffic through ScopePilot's scope proxy
// and MCP interface. Tools never receive out-of-scope targets.
package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dhiren/pentest-automation/internal/db"
)

// MCPClient communicates with the ScopePilot MCP server.
type MCPClient struct {
	BaseURL    string
	HTTPClient *http.Client
	ProgramID  string
	APIKey     string
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
	return NewMCPClientWithAPIKey(baseURL, programID, os.Getenv("SCOPEPILOT_MCP_API_KEY"))
}

// NewMCPClientWithAPIKey creates a new MCP client with an explicit bearer token.
func NewMCPClientWithAPIKey(baseURL, programID, apiKey string) *MCPClient {
	return &MCPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		ProgramID:  programID,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		APIKey:     strings.TrimSpace(apiKey),
	}
}

func (c *MCPClient) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
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
	c.applyHeaders(httpReq)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp request returned HTTP %d", resp.StatusCode)
	}

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
	c.applyHeaders(httpReq)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp request returned HTTP %d", resp.StatusCode)
	}

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

// AssetRecorder is the interface for persisting discovered assets.
// Implemented by db.Store to avoid direct import dependency.
type AssetRecorder interface {
	RecordAssets(program string, hosts []db.Asset) error
}

// BBOTConfig holds configuration for the BBOT adapter.
type BBOTConfig struct {
	BinaryPath   string // Path to bbot binary
	MCPClient    *MCPClient
	DryRun       bool // If true, only check scope, don't execute BBOT
	Timeout      time.Duration
	ProxyURL     string // HTTP proxy URL (e.g. http://127.0.0.1:8443); empty = no proxy
	NoProxy      bool // Run without proxy env, post-hoc filter results
	VPNContainer string // Container name for VPN namespace sharing (--network container:)
	ProgramID    string // Program ID for engagement memory
	Store        AssetRecorder // Engagement-memory store (optional)
}

// NucleiConfig holds configuration for the Nuclei adapter.
type NucleiConfig struct {
	BinaryPath   string // Path to nuclei binary
	MCPClient    *MCPClient
	DryRun       bool
	Timeout      time.Duration
	TemplateDir  string // Path to nuclei templates
	Severities   []string
	ProxyURL     string // HTTP proxy URL (e.g. http://127.0.0.1:8443); empty = no proxy
	NoProxy      bool // Run without proxy env, post-hoc filter results
	VPNContainer string // Container name for VPN namespace sharing (--network container:)
	ProgramID    string // Program ID for engagement memory
	Store        AssetRecorder // Engagement-memory store (optional)
}

// BBOTResult holds structured results from a BBOT scan.
type BBOTResult struct {
	TargetsScanned  int      `json:"targets_scanned"`
	TargetsBlocked  int      `json:"targets_blocked"`
	SubdomainsFound []string `json:"subdomains_found,omitempty"`
	RawOutput       string   `json:"raw_output,omitempty"`
	DryRun          bool     `json:"dry_run"`
	NoProxy         bool     `json:"no_proxy,omitempty"` // ran without proxy env
	Errors          []string `json:"errors,omitempty"`
}

// NucleiResult holds structured results from a Nuclei scan.
type NucleiResult struct {
	TargetsScanned int      `json:"targets_scanned"`
	TargetsBlocked int      `json:"targets_blocked"`
	Findings       []string `json:"findings,omitempty"`
	RawOutput      string   `json:"raw_output,omitempty"`
	DryRun         bool     `json:"dry_run"`
	NoProxy        bool     `json:"no_proxy,omitempty"` // ran without proxy env
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
	if cfg.MCPClient == nil {
		return nil, fmt.Errorf("bbot: MCP client is required")
	}

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
	if cfg.NoProxy {
		// Recon-no-proxy mode: run without proxy env, post-hoc filter results.
		result.NoProxy = true
	} else {
		if cfg.ProxyURL == "" {
			return nil, fmt.Errorf("bbot: proxy URL is required for execution")
		}
		if err := validateProxyURL(cfg.ProxyURL); err != nil {
			return nil, fmt.Errorf("bbot: %w", err)
		}
	}
	if cfg.VPNContainer != "" {
		return nil, fmt.Errorf("bbot: VPN namespace %q cannot be enforced for a host process; use a containerized worker", cfg.VPNContainer)
	}

	// Step 2: Build BBOT command with safe args.
	bbotVersion := detectBBOTVersion(cfg.BinaryPath)
	cmd := exec.CommandContext(ctx, cfg.BinaryPath, bbotArgs(inScope, cfg.ProxyURL, cfg.NoProxy, bbotVersion)...)
	if cfg.NoProxy {
		cmd.Env = os.Environ() // direct internet, no proxy
	} else {
		cmd.Env = proxyEnvironment(cfg.ProxyURL)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// BBOT may return non-zero for some failures — still parse output.
		result.Errors = append(result.Errors, fmt.Sprintf("bbot exited: %v", err))
	}

	result.TargetsScanned = len(inScope)
	result.RawOutput = string(output)

	// Parse raw output to discover hosts.
	discovered := parseBBOTOutput(string(output))

	// Post-hoc scope filter for no-proxy mode.
	if cfg.NoProxy {
		var allowed []string
		for _, h := range discovered {
			if ok, _ := cfg.MCPClient.FilterInScope(ctx, []string{h}); len(ok) > 0 {
				allowed = append(allowed, h)
			}
		}
		result.SubdomainsFound = allowed
	} else {
		result.SubdomainsFound = discovered
	}

	// Record discovered hosts into engagement memory.
	if cfg.Store != nil && cfg.ProgramID != "" && len(result.SubdomainsFound) > 0 {
		assets := make([]db.Asset, len(result.SubdomainsFound))
		for i, h := range result.SubdomainsFound {
			assets[i] = db.Asset{Host: h, Source: "bbot", InScope: true}
		}
		if err := cfg.Store.RecordAssets(cfg.ProgramID, assets); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("store: %v", err))
		}
	}

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
	if cfg.MCPClient == nil {
		return nil, fmt.Errorf("nuclei: MCP client is required")
	}

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
	if strings.TrimSpace(cfg.TemplateDir) == "" {
		return nil, fmt.Errorf("nuclei: template directory is required for execution")
	}
	if cfg.ProxyURL == "" {
		return nil, fmt.Errorf("nuclei: proxy URL is required for execution")
	}
	if err := validateProxyURL(cfg.ProxyURL); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	if cfg.VPNContainer != "" {
		return nil, fmt.Errorf("nuclei: VPN namespace %q cannot be enforced for a host process; use a containerized worker", cfg.VPNContainer)
	}

	// Step 2: Build Nuclei command with safe args.
	// Create a temp file for nuclei JSONL output so parseNucleiOutput
	// reads clean JSONL instead of stdout banner noise.
	tmpOut, err := os.CreateTemp("", "scopepilot_nuclei_*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("nuclei: create temp output: %w", err)
	}
	tmpPath := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpPath)

	args := nucleiArgs(cfg.TemplateDir, inScope, tmpPath, detectNucleiVersion(cfg.BinaryPath))

	severities := cfg.Severities
	if len(severities) == 0 {
		severities = []string{"info", "low"}
	}
	for _, severity := range severities {
		switch severity {
		case "info", "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("nuclei: unsupported severity %q", severity)
		}
	}
	args = append(args, "-severity", strings.Join(severities, ","))

	args = append(args, "-proxy", cfg.ProxyURL)

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, args...)
	cmd.Env = proxyEnvironment(cfg.ProxyURL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("nuclei exited: %v", err))
	}

	result.TargetsScanned = len(inScope)
	result.RawOutput = string(output)

	// Read findings from the temp output file (nuclei writes JSONL there,
	// stdout only contains banner/log noise).
	if data, readErr := os.ReadFile(tmpPath); readErr == nil {
		result.Findings = parseNucleiOutput(string(data))
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("nuclei: read output: %v", readErr))
	}

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

func validateProxyURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("proxy URL must use http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("proxy URL must include a host")
	}
	if u.User != nil {
		return fmt.Errorf("proxy URL must not contain credentials")
	}
	return nil
}

// DiscoverNucleiTemplates probes common locations for nuclei templates
// in platform-appropriate order. Returns the first that exists, or "".
func DiscoverNucleiTemplates() string {
	paths := []string{
		os.Getenv("NUCLEI_TEMPLATES"),
		filepath.Join(os.Getenv("HOME"), "nuclei-templates"),
		filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "nuclei-templates"),
		"/home/nuclei-templates",
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	return ""
}

func proxyEnvironment(proxyURL string) []string {
	env := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		default:
			env = append(env, entry)
		}
	}
	return append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"NO_PROXY=",
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"all_proxy="+proxyURL,
		"no_proxy=",
	)
}

// bbotArgs returns the CLI args for a BBOT discovery run, selecting
// flags appropriate for the given version. version 0 means unknown
// (assume current/v2).
func bbotArgs(targets []string, proxyURL string, noProxy bool, version int) []string {
	args := []string{
		"-t", strings.Join(targets, ","),
		"-y",
		"-o", "-",
	}
	if version < 2 && version > 0 {
		// BBOT v1.x: use old flag names
		args = append(args, "--passive-only", "--no-dns", "--no-www", "--force", "-o", "json")
	} else {
		// BBOT v2.x+ (or unknown — assume v2): use current flags
		args = append(args, "-rf", "passive", "-om", "json")
	}
	if !noProxy && proxyURL != "" {
		args = append(args, "--proxy", proxyURL)
	}
	return args
}

// nucleiArgs returns the CLI args for a Nuclei scan run, selecting
// flags appropriate for the given version. version 0 means unknown
// (assume current/v3). outputPath is the file path where nuclei
// should write JSONL results.
func nucleiArgs(templateDir string, targets []string, outputPath string, version int) []string {
	jsonFlag := "-jsonl"
	if version < 3 && version > 0 {
		jsonFlag = "-json" // Nuclei v2.x
	}
	args := []string{
		"-t", templateDir,
		jsonFlag,
		"-o", outputPath,
		"--no-httpx",
		"--bulk-size", "5",
		"--concurrency", "2",
		"-exclude-tags", "fuzz,dos,headless,code",
	}
	for _, target := range targets {
		args = append(args, "-u", target)
	}
	return args
}

// detectBBOTVersion detects the installed bbot version.
// Returns major version number (0 if detection fails).
func detectBBOTVersion(binaryPath string) int {
	data, err := exec.Command(binaryPath, "--version").Output()
	if err != nil {
		return 0
	}
	return parseMajorVersion(string(data))
}

// detectNucleiVersion detects the installed nuclei version.
// Returns major version number (0 if detection fails).
func detectNucleiVersion(binaryPath string) int {
	data, err := exec.Command(binaryPath, "--version").Output()
	if err != nil {
		return 0
	}
	return parseMajorVersion(string(data))
}

// parseMajorVersion extracts the major version number from a tool's
// --version output (e.g. "2.14.0" → 2).
func parseMajorVersion(versionOutput string) int {
	re := regexp.MustCompile(`(\d+)\.\d+\.\d+`)
	matches := re.FindStringSubmatch(versionOutput)
	if len(matches) < 2 {
		return 0
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}
	return major
}
