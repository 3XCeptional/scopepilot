package specialist

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhiren/pentest-automation/internal/adapter"
)

// ---------------------------------------------------------------------------
// Compile-time interface checks
// ---------------------------------------------------------------------------

func TestSpecialistInterface(t *testing.T) {
	// Compile-time checks that all three specialists implement the Specialist interface.
	var _ Specialist = (*Recon)(nil)
	var _ Specialist = (*Vuln)(nil)
	var _ Specialist = (*Gate)(nil)
}

// ---------------------------------------------------------------------------
// Config defaults and construction
// ---------------------------------------------------------------------------

func TestConfigDefaults(t *testing.T) {
	var cfg Config

	if cfg.BBOTBinary != "" {
		t.Errorf("expected empty BBOTBinary, got %q", cfg.BBOTBinary)
	}
	if cfg.NucleiBinary != "" {
		t.Errorf("expected empty NucleiBinary, got %q", cfg.NucleiBinary)
	}
	if cfg.TemplateDir != "" {
		t.Errorf("expected empty TemplateDir, got %q", cfg.TemplateDir)
	}
	if cfg.MCPURL != "" {
		t.Errorf("expected empty MCPURL, got %q", cfg.MCPURL)
	}
	if cfg.ProgramID != "" {
		t.Errorf("expected empty ProgramID, got %q", cfg.ProgramID)
	}
	if cfg.ProxyURL != "" {
		t.Errorf("expected empty ProxyURL, got %q", cfg.ProxyURL)
	}
	if cfg.DryRun {
		t.Error("expected DryRun false by default")
	}
	if cfg.Timeout != 0 {
		t.Errorf("expected zero Timeout, got %v", cfg.Timeout)
	}
	if cfg.AllowExploitation {
		t.Error("expected AllowExploitation false by default")
	}
}

func TestConfigFullConstruction(t *testing.T) {
	cfg := Config{
		BBOTBinary:        "/usr/local/bin/bbot",
		NucleiBinary:      "/usr/local/bin/nuclei",
		TemplateDir:       "/opt/nuclei-templates",
		MCPURL:            "http://127.0.0.1:8080",
		ProgramID:         "test-prog",
		ProxyURL:          "http://127.0.0.1:8443",
		DryRun:            true,
		Timeout:           90 * time.Second,
		AllowExploitation: true,
	}

	if cfg.BBOTBinary != "/usr/local/bin/bbot" {
		t.Errorf("unexpected BBOTBinary: %q", cfg.BBOTBinary)
	}
	if cfg.Timeout != 90*time.Second {
		t.Errorf("unexpected Timeout: %v", cfg.Timeout)
	}
	if !cfg.DryRun {
		t.Error("expected DryRun true")
	}
	if !cfg.AllowExploitation {
		t.Error("expected AllowExploitation true")
	}
}

// ---------------------------------------------------------------------------
// Result construction and JSON serialization
// ---------------------------------------------------------------------------

func TestResultConstruction(t *testing.T) {
	now := time.Now()
	result := &Result{
		Specialist:     "recon",
		TargetsIn:      10,
		TargetsPassed:  8,
		TargetsBlocked: 2,
		Findings:       15,
		DryRun:         false,
		Duration:       time.Since(now).Round(time.Millisecond).String(),
		Details: map[string]interface{}{
			"subdomains_found": []string{"a.example.com", "b.example.com"},
		},
	}

	if result.Specialist != "recon" {
		t.Errorf("unexpected Specialist: %q", result.Specialist)
	}
	if result.TargetsIn != 10 {
		t.Errorf("unexpected TargetsIn: %d", result.TargetsIn)
	}
	if result.TargetsPassed != 8 {
		t.Errorf("unexpected TargetsPassed: %d", result.TargetsPassed)
	}
	if result.TargetsBlocked != 2 {
		t.Errorf("unexpected TargetsBlocked: %d", result.TargetsBlocked)
	}
	if result.Findings != 15 {
		t.Errorf("unexpected Findings: %d", result.Findings)
	}
}

func TestResultJSONSerialization(t *testing.T) {
	result := &Result{
		Specialist:     "vuln",
		TargetsIn:      5,
		TargetsPassed:  3,
		TargetsBlocked: 2,
		Findings:       7,
		DryRun:         true,
		Duration:       "1.5s",
		Error:          "some error",
		Details: map[string]interface{}{
			"targets_scanned": 3,
			"raw_output":      "output",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Specialist != result.Specialist {
		t.Errorf("Specialist roundtrip: got %q, want %q", decoded.Specialist, result.Specialist)
	}
	if decoded.TargetsIn != result.TargetsIn {
		t.Errorf("TargetsIn roundtrip: got %d, want %d", decoded.TargetsIn, result.TargetsIn)
	}
	if decoded.DryRun != result.DryRun {
		t.Errorf("DryRun roundtrip: got %v, want %v", decoded.DryRun, result.DryRun)
	}
	if decoded.Error != result.Error {
		t.Errorf("Error roundtrip: got %q, want %q", decoded.Error, result.Error)
	}
}

func TestResultEmptyFields(t *testing.T) {
	result := &Result{
		Specialist: "gate",
		TargetsIn:  0,
		Duration:   "0s",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if !strings.Contains(string(data), `"duration":"0s"`) {
		t.Errorf("expected duration in JSON output")
	}
	// Error should be omitted when empty (omitempty tag).
	if strings.Contains(string(data), `"error"`) {
		t.Errorf("expected empty Error to be omitted from JSON, got: %s", string(data))
	}
}

// ---------------------------------------------------------------------------
// BucketBySeverity — pure function tests
// ---------------------------------------------------------------------------

func TestBucketBySeverity(t *testing.T) {
	tests := []struct {
		name     string
		findings []string
		want     severityBuckets
	}{
		{
			name:     "empty findings",
			findings: nil,
			want:     severityBuckets{},
		},
		{
			name:     "empty slice",
			findings: []string{},
			want:     severityBuckets{},
		},
		{
			name: "info",
			findings: []string{
				"[info] app.example.com - Tech Stack (tech-detect)",
			},
			want: severityBuckets{
				Info: []string{"[info] app.example.com - Tech Stack (tech-detect)"},
			},
		},
		{
			name: "low",
			findings: []string{
				"[low] app.example.com - Missing Header (missing-header)",
			},
			want: severityBuckets{
				Low: []string{"[low] app.example.com - Missing Header (missing-header)"},
			},
		},
		{
			name: "medium",
			findings: []string{
				"[medium] app.example.com - Weak Cipher (weak-cipher)",
			},
			want: severityBuckets{
				Medium: []string{"[medium] app.example.com - Weak Cipher (weak-cipher)"},
			},
		},
		{
			name: "high",
			findings: []string{
				"[high] app.example.com - RCE (rce-detection)",
			},
			want: severityBuckets{
				High: []string{"[high] app.example.com - RCE (rce-detection)"},
			},
		},
		{
			name: "critical",
			findings: []string{
				"[critical] app.example.com - Critical Vuln (critical-vuln)",
			},
			want: severityBuckets{
				Critical: []string{"[critical] app.example.com - Critical Vuln (critical-vuln)"},
			},
		},
		{
			name: "mixed severities in order",
			findings: []string{
				"[info] a.example.com - Info (i1)",
				"[low] b.example.com - Low (l1)",
				"[medium] c.example.com - Medium (m1)",
				"[high] d.example.com - High (h1)",
				"[critical] e.example.com - Critical (c1)",
			},
			want: severityBuckets{
				Info:     []string{"[info] a.example.com - Info (i1)"},
				Low:      []string{"[low] b.example.com - Low (l1)"},
				Medium:   []string{"[medium] c.example.com - Medium (m1)"},
				High:     []string{"[high] d.example.com - High (h1)"},
				Critical: []string{"[critical] e.example.com - Critical (c1)"},
			},
		},
		{
			name: "unknown severity",
			findings: []string{
				"[unknown] app.example.com - Unknown (unk)",
			},
			want: severityBuckets{
				Unknown: []string{"[unknown] app.example.com - Unknown (unk)"},
			},
		},
		{
			name: "malformed — no brackets",
			findings: []string{
				"plain text finding",
			},
			want: severityBuckets{
				Unknown: []string{"plain text finding"},
			},
		},
		{
			name: "malformed — no closing bracket",
			findings: []string{
				"[info no-close",
			},
			want: severityBuckets{
				Unknown: []string{"[info no-close"},
			},
		},
		{
			name: "case insensitivity",
			findings: []string{
				"[INFO] c.example.com - Case Test (case1)",
				"[Info] d.example.com - Case Test (case2)",
			},
			want: severityBuckets{
				Info: []string{
					"[INFO] c.example.com - Case Test (case1)",
					"[Info] d.example.com - Case Test (case2)",
				},
			},
		},
		{
			name: "multiple findings per severity",
			findings: []string{
				"[info] a.example.com - A (a1)",
				"[info] b.example.com - B (b1)",
				"[low] c.example.com - C (c1)",
				"[info] d.example.com - D (d1)",
			},
			want: severityBuckets{
				Info: []string{
					"[info] a.example.com - A (a1)",
					"[info] b.example.com - B (b1)",
					"[info] d.example.com - D (d1)",
				},
				Low: []string{"[low] c.example.com - C (c1)"},
			},
		},
		{
			name: "whitespace around severity",
			findings: []string{
				"[ info ] app.example.com - Spaced (spaced)",
			},
			want: severityBuckets{
				Info: []string{"[ info ] app.example.com - Spaced (spaced)"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bucketBySeverity(tt.findings)

			if !severityBucketsEqual(got, tt.want) {
				t.Errorf("bucketBySeverity(%v) = %+v, want %+v", tt.findings, got, tt.want)
			}
		})
	}
}

// severityBucketsEqual compares two severityBuckets for test assertions.
func severityBucketsEqual(a, b severityBuckets) bool {
	return stringSlicesEqual(a.Info, b.Info) &&
		stringSlicesEqual(a.Low, b.Low) &&
		stringSlicesEqual(a.Medium, b.Medium) &&
		stringSlicesEqual(a.High, b.High) &&
		stringSlicesEqual(a.Critical, b.Critical) &&
		stringSlicesEqual(a.Unknown, b.Unknown)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// MCP mock server helpers
// ---------------------------------------------------------------------------

// mcpScopeHandler returns an http.Handler that responds to MCP JSON-RPC
// requests for check_url and is_kill_switch_active tools.
//
// allowFunc returns true if a URL should be considered in-scope.
// killSwitchActive controls the response to is_kill_switch_active queries.
// If returnErr is set, the handler returns a JSON-RPC error response.
func mcpScopeHandler(allowFunc func(url string) bool, killSwitchActive bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
			ID      int             `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if req.Method != "call_tool" {
			writeMCPError(w, req.ID, -32601, "method not found")
			return
		}

		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			writeMCPError(w, req.ID, -32700, "invalid params")
			return
		}

		switch params.Name {
		case "check_url":
			var args struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(params.Arguments, &args); err != nil {
				writeMCPError(w, req.ID, -32700, "invalid check_url arguments")
				return
			}
			allowed := allowFunc(args.URL)
			writeMCPResult(w, req.ID, adapter.SafeCheckResult{
				URL:     args.URL,
				Allowed: allowed,
			})
		case "is_kill_switch_active":
			writeMCPResult(w, req.ID, map[string]bool{
				"active": killSwitchActive,
			})
		default:
			writeMCPError(w, req.ID, -32601, "unknown tool: "+params.Name)
		}
	})
}

func writeMCPResult(w http.ResponseWriter, id int, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	raw, err := json.Marshal(result)
	if err != nil {
		http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":`+jsonID(id)+`}`, http.StatusInternalServerError)
		return
	}
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Result:  raw,
	}
	json.NewEncoder(w).Encode(resp)
}

func writeMCPError(w http.ResponseWriter, id int, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are returned with HTTP 200
	resp := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
	}
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}

func jsonID(id int) string {
	if id == 0 {
		return "0"
	}
	return strings.TrimSpace(func() string { b, _ := json.Marshal(id); return string(b) }())
}

// newMCPServer creates a test MCP server with the given allow predicate
// and kill-switch state.
func newMCPServer(t *testing.T, allowFunc func(url string) bool, killSwitchActive bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(mcpScopeHandler(allowFunc, killSwitchActive))
}

// alwaysAllow returns true for all URLs.
func alwaysAllow(_ string) bool { return true }

// neverAllow returns false for all URLs.
func neverAllow(_ string) bool { return false }

// ---------------------------------------------------------------------------
// filterScope tests
// ---------------------------------------------------------------------------

func TestFilterScope(t *testing.T) {
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Skipf("cannot bind socket: %v", err)
	} else {
		_ = ln.Close()
	}
	srv := newMCPServer(t, func(url string) bool {
		return strings.Contains(url, "in-scope")
	}, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		ProgramID: "test",
		ProxyURL:  "http://127.0.0.1:8443",
		DryRun:    false,
	}

	t.Run("in scope targets pass", func(t *testing.T) {
		targets := []string{"in-scope.example.com"}
		inScope, blocked, err := filterScope(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("filterScope error: %v", err)
		}
		if len(inScope) != 1 {
			t.Errorf("expected 1 in-scope target, got %d: %v", len(inScope), inScope)
		}
		if len(blocked) != 0 {
			t.Errorf("expected 0 blocked targets, got %d: %v", len(blocked), blocked)
		}
	})

	t.Run("out of scope targets blocked", func(t *testing.T) {
		targets := []string{"evil.com"}
		inScope, blocked, err := filterScope(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("filterScope error: %v", err)
		}
		if len(inScope) != 0 {
			t.Errorf("expected 0 in-scope targets, got %d: %v", len(inScope), inScope)
		}
		if len(blocked) != 1 {
			t.Errorf("expected 1 blocked target, got %d: %v", len(blocked), blocked)
		}
	})

	t.Run("mixed targets", func(t *testing.T) {
		targets := []string{"in-scope.example.com", "evil.com", "also-in-scope.example.net"}
		inScope, blocked, err := filterScope(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("filterScope error: %v", err)
		}
		if len(inScope) != 2 {
			t.Errorf("expected 2 in-scope targets, got %d: %v", len(inScope), inScope)
		}
		if len(blocked) != 1 {
			t.Errorf("expected 1 blocked target, got %d: %v", len(blocked), blocked)
		}
	})
}

func TestFilterScopeEmptyTargets(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		ProgramID: "test",
	}

	inScope, blocked, err := filterScope(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("filterScope error: %v", err)
	}
	if len(inScope) != 0 {
		t.Errorf("expected 0 in-scope targets for empty input, got %d", len(inScope))
	}
	if len(blocked) != 0 {
		t.Errorf("expected 0 blocked targets for empty input, got %d", len(blocked))
	}
}

func TestFilterScopeAllTargetsBlocked(t *testing.T) {
	srv := newMCPServer(t, neverAllow, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		ProgramID: "test",
	}

	targets := []string{"a.com", "b.com", "c.com"}
	inScope, blocked, err := filterScope(context.Background(), targets, cfg)
	if err != nil {
		t.Fatalf("filterScope error: %v", err)
	}
	if len(inScope) != 0 {
		t.Errorf("expected 0 in-scope targets, got %d", len(inScope))
	}
	if len(blocked) != 3 {
		t.Errorf("expected 3 blocked targets, got %d", len(blocked))
	}
}

// ---------------------------------------------------------------------------
// mcpClient construction
// ---------------------------------------------------------------------------

func TestMCPClientConstruction(t *testing.T) {
	cfg := Config{
		MCPURL:    "http://127.0.0.1:9999",
		ProgramID: "test-prog",
	}
	client := mcpClient(cfg)
	if client == nil {
		t.Fatal("mcpClient returned nil")
	}
	if client.BaseURL != "http://127.0.0.1:9999" {
		t.Errorf("expected BaseURL 'http://127.0.0.1:9999', got %q", client.BaseURL)
	}
	if client.ProgramID != "test-prog" {
		t.Errorf("expected ProgramID 'test-prog', got %q", client.ProgramID)
	}
	if client.HTTPClient == nil {
		t.Error("expected non-nil HTTPClient")
	}
}

// ---------------------------------------------------------------------------
// killSwitchActive tests
// ---------------------------------------------------------------------------

func TestKillSwitchActive(t *testing.T) {
	t.Run("kill switch inactive", func(t *testing.T) {
		srv := newMCPServer(t, alwaysAllow, false)
		defer srv.Close()

		cfg := Config{MCPURL: srv.URL, ProgramID: "test"}
		active, reason, err := killSwitchActive(context.Background(), cfg)
		if err != nil {
			t.Fatalf("killSwitchActive error: %v", err)
		}
		if active {
			t.Error("expected kill switch inactive (false)")
		}
		if reason != "" {
			t.Errorf("expected empty reason, got %q", reason)
		}
	})

	t.Run("kill switch active", func(t *testing.T) {
		srv := newMCPServer(t, alwaysAllow, true)
		defer srv.Close()

		cfg := Config{MCPURL: srv.URL, ProgramID: "test"}
		active, reason, err := killSwitchActive(context.Background(), cfg)
		if err != nil {
			t.Fatalf("killSwitchActive error: %v", err)
		}
		if !active {
			t.Error("expected kill switch active (true)")
		}
		if reason != "" {
			t.Errorf("expected empty reason, got %q", reason)
		}
	})
}

func TestKillSwitchActivePropagatesBearerToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer specialist-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeMCPResult(w, 1, map[string]bool{"active": false})
	}))
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		MCPAPIKey: "specialist-api-key",
		ProgramID: "test",
	}
	active, _, err := killSwitchActive(context.Background(), cfg)
	if err != nil {
		t.Fatalf("killSwitchActive error: %v", err)
	}
	if active {
		t.Fatal("expected inactive kill switch")
	}
}

func TestKillSwitchActiveServerError(t *testing.T) {
	// Start a server that returns an MCP error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32000,
				"message": "server error",
			},
		})
	}))
	defer srv.Close()

	cfg := Config{MCPURL: srv.URL, ProgramID: "test"}
	_, _, err := killSwitchActive(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from MCP error response")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("expected error to mention 'server error', got: %v", err)
	}
	if !strings.Contains(err.Error(), "-32000") {
		t.Errorf("expected error to contain error code, got: %v", err)
	}
}

func TestKillSwitchActiveConnectionRefused(t *testing.T) {
	cfg := Config{
		MCPURL:    "http://127.0.0.1:1", // very unlikely to be listening
		ProgramID: "test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err := killSwitchActive(ctx, cfg)
	if err == nil {
		t.Fatal("expected error from connection refused")
	}
	if !strings.Contains(err.Error(), "MCP request") && !strings.Contains(err.Error(), "connection") {
		t.Logf("got error (expected some network error): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Specialist Name() and Description() tests
// ---------------------------------------------------------------------------

func TestReconNameAndDescription(t *testing.T) {
	r := NewRecon()
	if r.Name() != "recon" {
		t.Errorf("expected Name 'recon', got %q", r.Name())
	}
	if r.Description() == "" {
		t.Error("expected non-empty Description")
	}
	if !strings.Contains(r.Description(), "BBOT") {
		t.Error("expected Description to mention BBOT")
	}
}

func TestVulnNameAndDescription(t *testing.T) {
	v := NewVuln()
	if v.Name() != "vuln" {
		t.Errorf("expected Name 'vuln', got %q", v.Name())
	}
	if v.Description() == "" {
		t.Error("expected non-empty Description")
	}
	if !strings.Contains(v.Description(), "Nuclei") {
		t.Error("expected Description to mention Nuclei")
	}
}

func TestGateNameAndDescription(t *testing.T) {
	g := NewGate()
	if g.Name() != "gate" {
		t.Errorf("expected Name 'gate', got %q", g.Name())
	}
	if g.Description() == "" {
		t.Error("expected non-empty Description")
	}
	if !strings.Contains(g.Description(), "kill switch") {
		t.Error("expected Description to mention kill switch")
	}
}

// ---------------------------------------------------------------------------
// Recon.Run dry-run integration tests
// ---------------------------------------------------------------------------

func TestReconRunDryRun(t *testing.T) {
	srv := newMCPServer(t, func(url string) bool {
		return strings.Contains(url, "in-scope")
	}, false)
	defer srv.Close()

	cfg := Config{
		BBOTBinary: "/usr/bin/bbot",
		MCPURL:     srv.URL,
		ProgramID:  "test",
		ProxyURL:   "http://127.0.0.1:8443",
		DryRun:     true,
		Timeout:    30 * time.Second,
	}

	r := NewRecon()

	t.Run("mixed targets", func(t *testing.T) {
		targets := []string{"in-scope.example.com", "evil.com"}
		result, err := r.Run(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("Recon.Run error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Specialist != "recon" {
			t.Errorf("expected Specialist 'recon', got %q", result.Specialist)
		}
		if result.TargetsIn != 2 {
			t.Errorf("expected TargetsIn=2, got %d", result.TargetsIn)
		}
		if result.TargetsPassed != 1 {
			t.Errorf("expected TargetsPassed=1, got %d", result.TargetsPassed)
		}
		if result.TargetsBlocked != 1 {
			t.Errorf("expected TargetsBlocked=1, got %d", result.TargetsBlocked)
		}
		if !result.DryRun {
			t.Error("expected DryRun=true in result")
		}
		if result.Duration == "" {
			t.Error("expected non-empty Duration")
		}
		if result.Details == nil {
			t.Error("expected non-nil Details")
		}
	})

	t.Run("empty targets", func(t *testing.T) {
		result, err := r.Run(context.Background(), nil, cfg)
		if err != nil {
			t.Fatalf("Recon.Run with empty targets error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.TargetsIn != 0 {
			t.Errorf("expected TargetsIn=0, got %d", result.TargetsIn)
		}
		if result.TargetsPassed != 0 {
			t.Errorf("expected TargetsPassed=0, got %d", result.TargetsPassed)
		}
	})

	t.Run("all blocked", func(t *testing.T) {
		targets := []string{"evil1.com", "evil2.com"}
		result, err := r.Run(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("Recon.Run all-blocked error: %v", err)
		}
		if result.TargetsBlocked != 2 {
			t.Errorf("expected TargetsBlocked=2, got %d", result.TargetsBlocked)
		}
		if result.TargetsPassed != 0 {
			t.Errorf("expected TargetsPassed=0, got %d", result.TargetsPassed)
		}
	})
}

// ---------------------------------------------------------------------------
// Vuln.Run dry-run integration tests
// ---------------------------------------------------------------------------

func TestVulnRunDryRun(t *testing.T) {
	srv := newMCPServer(t, func(url string) bool {
		return strings.Contains(url, "in-scope")
	}, false)
	defer srv.Close()

	cfg := Config{
		NucleiBinary: "/usr/bin/nuclei",
		TemplateDir:  "/opt/nuclei-templates",
		MCPURL:       srv.URL,
		ProgramID:    "test",
		ProxyURL:     "http://127.0.0.1:8443",
		DryRun:       true,
		Timeout:      30 * time.Second,
	}

	v := NewVuln()

	t.Run("mixed targets", func(t *testing.T) {
		targets := []string{"in-scope.example.com", "evil.com"}
		result, err := v.Run(context.Background(), targets, cfg)
		if err != nil {
			t.Fatalf("Vuln.Run error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Specialist != "vuln" {
			t.Errorf("expected Specialist 'vuln', got %q", result.Specialist)
		}
		if result.TargetsIn != 2 {
			t.Errorf("expected TargetsIn=2, got %d", result.TargetsIn)
		}
		if result.TargetsPassed != 1 {
			t.Errorf("expected TargetsPassed=1, got %d", result.TargetsPassed)
		}
		if result.TargetsBlocked != 1 {
			t.Errorf("expected TargetsBlocked=1, got %d", result.TargetsBlocked)
		}
		if !result.DryRun {
			t.Error("expected DryRun=true in result")
		}
		if result.Duration == "" {
			t.Error("expected non-empty Duration")
		}
	})

	t.Run("empty targets", func(t *testing.T) {
		result, err := v.Run(context.Background(), nil, cfg)
		if err != nil {
			t.Fatalf("Vuln.Run with empty targets error: %v", err)
		}
		if result.TargetsIn != 0 {
			t.Errorf("expected TargetsIn=0, got %d", result.TargetsIn)
		}
	})
}

// ---------------------------------------------------------------------------
// Gate.Run dry-run integration tests
// ---------------------------------------------------------------------------

func TestGateRunDryRunKillSwitchOff(t *testing.T) {
	srv := newMCPServer(t, func(url string) bool {
		return strings.Contains(url, "in-scope")
	}, false) // kill switch off
	defer srv.Close()

	cfg := Config{
		NucleiBinary:      "/usr/bin/nuclei",
		TemplateDir:       "/opt/nuclei-templates",
		MCPURL:            srv.URL,
		ProgramID:         "test",
		ProxyURL:          "http://127.0.0.1:8443",
		DryRun:            true,
		Timeout:           30 * time.Second,
		AllowExploitation: true,
	}

	g := NewGate()
	targets := []string{"in-scope.example.com", "evil.com"}
	result, err := g.Run(context.Background(), targets, cfg)
	if err != nil {
		t.Fatalf("Gate.Run error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Specialist != "gate" {
		t.Errorf("expected Specialist 'gate', got %q", result.Specialist)
	}
	if result.TargetsIn != 2 {
		t.Errorf("expected TargetsIn=2, got %d", result.TargetsIn)
	}
	if result.TargetsPassed != 1 {
		t.Errorf("expected TargetsPassed=1, got %d", result.TargetsPassed)
	}
	if result.TargetsBlocked != 1 {
		t.Errorf("expected TargetsBlocked=1, got %d", result.TargetsBlocked)
	}
	if !result.DryRun {
		t.Error("expected DryRun=true in result")
	}
	// Verify kill switch was checked (details should contain kill_switch_checked).
	details, ok := result.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Details to be map[string]interface{}, got %T", result.Details)
	}
	if checked, ok := details["kill_switch_checked"]; !ok || checked != true {
		t.Errorf("expected kill_switch_checked=true in details, got %v", details)
	}
}

func TestGateRunKillSwitchBlocks(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, true) // kill switch active
	defer srv.Close()

	cfg := Config{
		NucleiBinary:      "/usr/bin/nuclei",
		TemplateDir:       "/opt/nuclei-templates",
		MCPURL:            srv.URL,
		ProgramID:         "test",
		DryRun:            true,
		AllowExploitation: true,
	}

	g := NewGate()
	targets := []string{"app.example.com"}
	result, err := g.Run(context.Background(), targets, cfg)
	if err != nil {
		t.Fatalf("Gate.Run with active kill switch error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Error == "" {
		t.Error("expected non-empty Error when kill switch is active")
	}
	if !strings.Contains(result.Error, "kill switch") {
		t.Errorf("expected Error to mention 'kill switch', got %q", result.Error)
	}
	if result.TargetsBlocked != 1 {
		t.Errorf("expected TargetsBlocked=1 when kill switch active, got %d", result.TargetsBlocked)
	}
	if result.TargetsPassed != 0 {
		t.Errorf("expected TargetsPassed=0 when kill switch active, got %d", result.TargetsPassed)
	}
	if result.Findings != 0 {
		t.Errorf("expected Findings=0 when kill switch active, got %d", result.Findings)
	}
	// Verify kill switch is noted in details.
	details, ok := result.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Details to be map[string]interface{}, got %T", result.Details)
	}
	if blocked, ok := details["kill_switch_blocked"]; !ok || blocked != true {
		t.Errorf("expected kill_switch_blocked=true in details, got %v", details)
	}
}

func TestGateRunKillSwitchError(t *testing.T) {
	// Start a server that returns an MCP error for is_kill_switch_active.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32000,
				"message": "kill-switch check failed",
			},
		})
	}))
	defer srv.Close()

	cfg := Config{
		MCPURL:            srv.URL,
		ProgramID:         "test",
		DryRun:            true,
		AllowExploitation: true,
	}

	g := NewGate()
	_, err := g.Run(context.Background(), []string{"app.example.com"}, cfg)
	if err == nil {
		t.Fatal("expected error when MCP returns error for kill-switch check")
	}
	if !strings.Contains(err.Error(), "kill-switch") {
		t.Errorf("expected error to mention 'kill-switch', got: %v", err)
	}
}

func TestGateRunEmptyTargets(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	cfg := Config{
		NucleiBinary:      "/usr/bin/nuclei",
		TemplateDir:       "/opt/nuclei-templates",
		MCPURL:            srv.URL,
		ProgramID:         "test",
		DryRun:            true,
		AllowExploitation: true,
	}

	g := NewGate()
	result, err := g.Run(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("Gate.Run with empty targets error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.TargetsIn != 0 {
		t.Errorf("expected TargetsIn=0, got %d", result.TargetsIn)
	}
}

// ---------------------------------------------------------------------------
// Recon.Run with empty targets edge cases
// ---------------------------------------------------------------------------

func TestReconRunConnectionRefused(t *testing.T) {
	cfg := Config{
		BBOTBinary: "/usr/bin/bbot",
		MCPURL:     "http://127.0.0.1:1", // connection refused
		ProgramID:  "test",
		DryRun:     true,
	}

	r := NewRecon()
	// filterScope is tolerant: it calls FilterInScope which blocks on error.
	// So this should not return an error from filterScope itself, but targets
	// will all be blocked.
	result, err := r.Run(context.Background(), []string{"app.example.com"}, cfg)
	if err != nil {
		t.Fatalf("Recon.Run with connection refused should not error: %v", err)
	}
	// The MCP conn error causes CheckURL to fail, so target gets blocked.
	if result.TargetsBlocked != 1 {
		t.Errorf("expected 1 blocked target (connection refused), got %d", result.TargetsBlocked)
	}
	if result.TargetsPassed != 0 {
		t.Errorf("expected 0 passed targets, got %d", result.TargetsPassed)
	}
}

func TestVulnRunConnectionRefused(t *testing.T) {
	cfg := Config{
		NucleiBinary: "/usr/bin/nuclei",
		TemplateDir:  "/opt/nuclei-templates",
		MCPURL:       "http://127.0.0.1:1",
		ProgramID:    "test",
		DryRun:       true,
	}

	v := NewVuln()
	result, err := v.Run(context.Background(), []string{"app.example.com"}, cfg)
	if err != nil {
		t.Fatalf("Vuln.Run with connection refused should not error: %v", err)
	}
	if result.TargetsBlocked != 1 {
		t.Errorf("expected 1 blocked target, got %d", result.TargetsBlocked)
	}
}

// ---------------------------------------------------------------------------
// Gate.killSwitchActive error paths
// ---------------------------------------------------------------------------

func TestKillSwitchActiveBadURL(t *testing.T) {
	// An invalid URL scheme should cause an error at the HTTP request level.
	cfg := Config{
		MCPURL:    "://bad",
		ProgramID: "test",
	}

	// mcpClient(cfg) will create a client with BaseURL "://bad" (trimmed).
	// The HTTP request will fail with a scheme error.
	_, _, err := killSwitchActive(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from bad URL")
	}
}

func TestKillSwitchActiveNonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	cfg := Config{MCPURL: srv.URL, ProgramID: "test"}
	_, _, err := killSwitchActive(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from non-JSON response")
	}
	if !strings.Contains(err.Error(), "decode") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected decode/invalid error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// filterScope with MCP server returning error responses
// ---------------------------------------------------------------------------

func TestFilterScopeServerError(t *testing.T) {
	// Server that returns MCP errors for all requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32601,
				"message": "method not found",
			},
		})
	}))
	defer srv.Close()

	cfg := Config{MCPURL: srv.URL, ProgramID: "test"}

	// filterScope calls FilterInScope → CheckURL → gets MCP error
	// FilterInScope treats errors as blocked.
	inScope, blocked, err := filterScope(context.Background(), []string{"test.com"}, cfg)
	if err != nil {
		t.Fatalf("filterScope should not return error on MCP errors: %v", err)
	}
	if len(inScope) != 0 {
		t.Errorf("expected 0 in-scope targets on MCP error, got %d", len(inScope))
	}
	if len(blocked) != 1 {
		t.Errorf("expected 1 blocked target on MCP error, got %d", len(blocked))
	}
}

// ---------------------------------------------------------------------------
// Multiple specialist instances and concurrent safety
// ---------------------------------------------------------------------------

func TestReconRunRecordsStartTime(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		ProgramID: "test",
		DryRun:    true,
	}

	r := NewRecon()
	if !r.startTime.IsZero() {
		t.Error("expected zero startTime before Run")
	}

	result, err := r.Run(context.Background(), []string{"test.com"}, cfg)
	if err != nil {
		t.Fatalf("Recon.Run error: %v", err)
	}
	if result.Duration == "" {
		t.Error("expected non-empty Duration after Run")
	}
	if r.startTime.IsZero() {
		t.Error("expected non-zero startTime after Run")
	}
}

func TestVulnRunRecordsStartTime(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:    srv.URL,
		ProgramID: "test",
		DryRun:    true,
	}

	v := NewVuln()
	if !v.startTime.IsZero() {
		t.Error("expected zero startTime before Run")
	}

	result, err := v.Run(context.Background(), []string{"test.com"}, cfg)
	if err != nil {
		t.Fatalf("Vuln.Run error: %v", err)
	}
	if result.Duration == "" {
		t.Error("expected non-empty Duration after Run")
	}
	if v.startTime.IsZero() {
		t.Error("expected non-zero startTime after Run")
	}
}

func TestGateRunRecordsStartTime(t *testing.T) {
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	cfg := Config{
		MCPURL:            srv.URL,
		ProgramID:         "test",
		DryRun:            true,
		AllowExploitation: true,
	}

	g := NewGate()
	if !g.startTime.IsZero() {
		t.Error("expected zero startTime before Run")
	}

	result, err := g.Run(context.Background(), []string{"test.com"}, cfg)
	if err != nil {
		t.Fatalf("Gate.Run error: %v", err)
	}
	if result.Duration == "" {
		t.Error("expected non-empty Duration after Run")
	}
	if g.startTime.IsZero() {
		t.Error("expected non-zero startTime after Run")
	}
}

func TestVulnRunGeneratesReportPath(t *testing.T) {
	// Verify that Vuln.Run produces a report_path in Details when findings
	// are present and OutputDir is set. Uses a fake nuclei that writes a
	// minimal JSONL finding to the -o file.
	srv := newMCPServer(t, alwaysAllow, false)
	defer srv.Close()

	outputDir := t.TempDir()
	fakeBin := filepath.Join(t.TempDir(), "nuclei-fake")
	fakeScript := `#!/bin/sh
# Find the -o flag in args and write a sample finding to that file.
for i in "$@"; do
  case "$i" in
    -o) shift; echo '{"template-id":"test","name":"Test Find","severity":"high","host":"https://app.example.com","type":"http"}' > "$1"; exit 0;;
  esac
  shift
done
exit 1
`
	if err := os.WriteFile(fakeBin, []byte(fakeScript), 0700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}

	cfg := Config{
		NucleiBinary: fakeBin,
		TemplateDir:  "/templates",
		MCPURL:       srv.URL,
		ProgramID:    "test-prog",
		ProxyURL:     "http://127.0.0.1:8443",
		OutputDir:    outputDir,
		DryRun:       false,
		Timeout:      5 * time.Second,
	}

	v := NewVuln()
	result, err := v.Run(context.Background(), []string{"app.example.com"}, cfg)
	if err != nil {
		t.Fatalf("Vuln.Run error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	details, ok := result.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected Details map, got %T", result.Details)
	}
	rp, ok := details["report_path"]
	if !ok || rp == "" {
		t.Errorf("expected non-empty report_path in Details, got %v", rp)
	}
	if result.Findings == 0 {
		t.Error("expected Findings > 0")
	}
}
