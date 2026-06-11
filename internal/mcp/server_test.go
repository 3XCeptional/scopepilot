package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/config"
	"github.com/dhiren/pentest-automation/internal/db"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/proxy"
	"github.com/dhiren/pentest-automation/internal/ratelimit"
	"github.com/dhiren/pentest-automation/internal/scope"
	"github.com/dhiren/pentest-automation/internal/specialist"
)

// testScopeConfig returns a minimal scope config for testing.
func testScopeConfig() config.ScopeConfig {
	return config.ScopeConfig{
		Include: []config.ScopeRule{
			{Type: "exact_host", Value: "example.com"},
			{Type: "exact_host", Value: "scannable-target.com"},
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		Exclude: []config.ScopeRule{
			{Type: "exact_host", Value: "excluded.example.com"},
			{Type: "path_prefix", Value: "/admin", Host: "example.com"},
		},
	}
}

// testProxy creates a proxy configured for testing.
func testProxy() *proxy.Proxy {
	pcfg := proxy.Config{
		ProgramID:            "test-program-1",
		ActiveTestingEnabled: true,
		ScopeCfg:             testScopeConfig(),
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		Limits: config.LimitsConfig{
			RequestsPerSecondPerHost: 100,
		},
	}
	return proxy.NewProxy(pcfg)
}

// testServer creates a fully wired MCP server for testing.
func testServer() *Server {
	store := db.NewMemoryStore(100)
	ks := &killswitch.Switch{}
	prx := testProxy()
	srv := NewServer(prx, store, ks)
	srv.SetDeactivationToken("test-token-123")
	return srv
}

// ---------------------------------------------------------------------------
// ListTools
// ---------------------------------------------------------------------------

func TestListTools_ReturnsExpectedTools(t *testing.T) {
	srv := testServer()
	tools := srv.ListTools()

	expected := map[string]bool{
		"get_scope_status":       false,
		"check_url":              false,
		"get_audit_log":          false,
		"get_recent_decisions":   false,
		"get_ratelimit_status":   false,
		"activate_kill_switch":   false,
		"deactivate_kill_switch": false,
		"is_kill_switch_active":  false,
		"run_safe_check":         false,
	}

	for _, tool := range tools {
		if _, ok := expected[tool.Name]; !ok {
			t.Errorf("unexpected tool name: %q", tool.Name)
			continue
		}
		if expected[tool.Name] {
			t.Errorf("duplicate tool name: %q", tool.Name)
		}
		expected[tool.Name] = true

		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil InputSchema", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("tool %q has nil OutputSchema", tool.Name)
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("missing expected tool: %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// CallTool — valid calls
// ---------------------------------------------------------------------------

func TestCallTool_GetScopeStatus(t *testing.T) {
	srv := testServer()
	result, err := srv.CallToolContext(context.Background(), "get_scope_status", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	// Check program_id.
	if id, ok := status["program_id"]; !ok || fmt.Sprintf("%v", id) != "test-program-1" {
		t.Errorf("expected program_id 'test-program-1', got %v", id)
	}
	// Check include_count.
	if ic, ok := status["include_count"]; !ok {
		t.Errorf("missing include_count")
	} else if fmt.Sprintf("%v", ic) != "3" {
		t.Errorf("expected include_count 3, got %v", ic)
	}
	// Check exclude_count.
	if ec, ok := status["exclude_count"]; !ok {
		t.Errorf("missing exclude_count")
	} else if fmt.Sprintf("%v", ec) != "2" {
		t.Errorf("expected exclude_count 2, got %v", ec)
	}
}

func TestCallTool_CheckURL_Allowed(t *testing.T) {
	if _, err := net.LookupHost("example.com"); err != nil {
		t.Skipf("DNS resolution failed: %v", err)
	}
	srv := testServer()
	result, err := srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{
		"url": "https://example.com/page",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cr, ok := result.(*proxy.CheckResult)
	if !ok {
		t.Fatalf("expected *proxy.CheckResult, got %T", result)
	}

	if !cr.Allowed {
		t.Errorf("expected allowed=true for example.com, got reason: %s", cr.Reason)
	}
	if cr.URL != "https://example.com/page" {
		t.Errorf("unexpected URL: %s", cr.URL)
	}
}

func TestCallTool_CheckURL_BlockedIP(t *testing.T) {
	srv := testServer()

	// 127.0.0.1 is a blocked IP.
	result, err := srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{
		"url": "https://127.0.0.1/admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cr, ok := result.(*proxy.CheckResult)
	if !ok {
		t.Fatalf("expected *proxy.CheckResult, got %T", result)
	}

	if cr.Allowed {
		t.Errorf("expected allowed=false for loopback IP")
	}
	if !cr.BlockedIP {
		t.Errorf("expected BlockedIP=true for loopback IP, got reason: %s", cr.Reason)
	}
}

func TestCallTool_CheckURL_DeniedScheme(t *testing.T) {
	srv := testServer()

	// HTTP is not in the allowed schemes.
	result, err := srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{
		"url": "http://example.com/page",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cr, ok := result.(*proxy.CheckResult)
	if !ok {
		t.Fatalf("expected *proxy.CheckResult, got %T", result)
	}

	if cr.Allowed {
		t.Errorf("expected allowed=false for http scheme")
	}
	if !cr.DeniedScheme {
		t.Errorf("expected DeniedScheme=true for http scheme")
	}
}

func TestCallTool_CheckURL_OutOfScope(t *testing.T) {
	srv := testServer()

	// Not in scope. Use an IP-based URL that's not blocked and not in scope.
	// 93.184.216.34 is example.com's IP but it's not in our scope CIDR rules.
	// The result should be allowed=false since the IP doesn't match any CIDR rule.
	result, err := srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{
		"url": "https://93.184.216.34/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cr, ok := result.(*proxy.CheckResult)
	if !ok {
		t.Fatalf("expected *proxy.CheckResult, got %T", result)
	}

	if cr.Allowed {
		t.Errorf("expected allowed=false for out-of-scope URL")
	}
	// The IP 93.184.216.34 is not blocked (it's a public IP) but also not in scope
	// because the scope only has hostname rules, not CIDR rules for this IP.
	if cr.ScopeResult != nil && cr.ScopeResult.InScope {
		t.Errorf("expected scope_result to be out-of-scope")
	}
}

func TestCallTool_GetAuditLog(t *testing.T) {
	srv := testServer()

	// Call tools first to generate audit entries.
	_, _ = srv.CallToolContext(context.Background(), "get_scope_status", map[string]interface{}{})
	_, _ = srv.CallToolContext(context.Background(), "is_kill_switch_active", map[string]interface{}{})

	// Now get audit log.
	result, err := srv.CallToolContext(context.Background(), "get_audit_log", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, ok := result.([]*audit.Entry)
	if !ok {
		t.Fatalf("expected []*audit.Entry, got %T", result)
	}

	if len(entries) < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", len(entries))
	}

	// Filter by event type.
	result2, err := srv.CallToolContext(context.Background(), "get_audit_log", map[string]interface{}{
		"event_type": "tool_invocation",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	filtered, ok := result2.([]*audit.Entry)
	if !ok {
		t.Fatalf("expected []*audit.Entry, got %T", result2)
	}
	if len(filtered) < 2 {
		t.Errorf("expected at least 2 filtered entries, got %d", len(filtered))
	}
	for _, e := range filtered {
		if e.EventType != "tool_invocation" {
			t.Errorf("expected event_type 'tool_invocation', got %q", e.EventType)
		}
	}
}

func TestCallTool_GetRateLimitStatus(t *testing.T) {
	srv := testServer()
	result, err := srv.CallToolContext(context.Background(), "get_ratelimit_status", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, ok := result.(*proxy.RateLimitState)
	if !ok {
		t.Fatalf("expected *proxy.RateLimitState, got %T", result)
	}
	if state.Hosts == nil {
		t.Errorf("expected non-nil Hosts slice")
	}
}

func TestCallTool_RunSafeCheck(t *testing.T) {
	if _, err := net.LookupHost("example.com"); err != nil {
		t.Skipf("DNS resolution failed: %v", err)
	}
	srv := testServer()
	result, err := srv.CallToolContext(context.Background(), "run_safe_check", map[string]interface{}{
		"urls": []interface{}{
			"https://example.com/",
			"https://127.0.0.1/",
			"http://example.com/",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	resultsRaw, ok := resp["results"]
	if !ok {
		t.Fatal("missing 'results' key")
	}
	results, ok := resultsRaw.([]*proxy.CheckResult)
	if !ok {
		t.Fatalf("expected []*proxy.CheckResult, got %T", resultsRaw)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// First: allowed
	if !results[0].Allowed {
		t.Errorf("expected first result allowed=true, got reason: %s", results[0].Reason)
	}
	// Second: blocked IP
	if results[1].Allowed {
		t.Errorf("expected second result allowed=false (blocked IP)")
	}
	// Third: denied scheme
	if results[2].Allowed {
		t.Errorf("expected third result allowed=false (denied scheme)")
	}
}

func TestCallTool_RunSafeCheckRejectsInvalidElements(t *testing.T) {
	srv := testServer()
	_, err := srv.CallToolContext(context.Background(), "run_safe_check", map[string]interface{}{
		"urls": []interface{}{"https://example.com/", 123},
	})
	if err == nil || !strings.Contains(err.Error(), "strings") {
		t.Fatalf("expected invalid URL element error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CallTool — kill switch flow
// ---------------------------------------------------------------------------

func TestCallTool_KillSwitchActivateDeactivate(t *testing.T) {
	srv := testServer()

	// Initially inactive.
	result, err := srv.CallToolContext(context.Background(), "is_kill_switch_active", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if active, ok := status["active"].(bool); !ok || active {
		t.Errorf("expected kill switch to be inactive initially")
	}

	// Activate.
	result, err = srv.CallToolContext(context.Background(), "activate_kill_switch", map[string]interface{}{
		"reason": "testing kill switch",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ks, ok := result.(killswitch.KillSwitchStatus)
	if !ok {
		t.Fatalf("expected killswitch.KillSwitchStatus, got %T", result)
	}
	if !ks.Active {
		t.Errorf("expected kill switch to be active")
	}
	if ks.ActivatedBy != "mcp:testing kill switch" {
		t.Errorf("expected activated_by 'mcp:testing kill switch', got %q", ks.ActivatedBy)
	}
	if ks.ActivatedAt == "" {
		t.Errorf("expected non-empty activated_at")
	}

	// Verify via is_kill_switch_active.
	result, err = srv.CallToolContext(context.Background(), "is_kill_switch_active", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status, _ = result.(map[string]interface{})
	if active, _ := status["active"].(bool); !active {
		t.Errorf("expected kill switch to be active after activation")
	}

	// Deactivate.
	result, err = srv.CallToolContext(context.Background(), "deactivate_kill_switch", map[string]interface{}{
		"token": "test-token-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ks, _ = result.(killswitch.KillSwitchStatus)
	if ks.Active {
		t.Errorf("expected kill switch to be inactive after deactivation")
	}

	// Verify via is_kill_switch_active.
	result, err = srv.CallToolContext(context.Background(), "is_kill_switch_active", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status, _ = result.(map[string]interface{})
	if active, _ := status["active"].(bool); active {
		t.Errorf("expected kill switch to be inactive after deactivation")
	}
}

// ---------------------------------------------------------------------------
// CallTool — error cases
// ---------------------------------------------------------------------------

func TestCallTool_UnknownToolName(t *testing.T) {
	srv := testServer()
	_, err := srv.CallToolContext(context.Background(), "non_existent_tool", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for unknown tool, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("expected error about unknown tool, got: %v", err)
	}
}

func TestCallTool_MissingRequiredParams(t *testing.T) {
	srv := testServer()

	// check_url requires 'url'.
	_, err := srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "missing required parameter") {
		t.Errorf("expected error about missing required parameter, got: %v", err)
	}

	// activate_kill_switch requires 'reason'.
	_, err = srv.CallToolContext(context.Background(), "activate_kill_switch", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "missing required parameter") {
		t.Errorf("expected error about missing required parameter, got: %v", err)
	}

	// run_safe_check requires 'urls'.
	_, err = srv.CallToolContext(context.Background(), "run_safe_check", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "missing required parameter") {
		t.Errorf("expected error about missing required parameter, got: %v", err)
	}
}

func TestCallTool_UnknownFields_Rejected(t *testing.T) {
	srv := testServer()

	// get_scope_status schema has additionalProperties=false.
	_, err := srv.CallToolContext(context.Background(), "get_scope_status", map[string]interface{}{
		"unknown_field": "should be rejected",
	})
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown parameter") {
		t.Errorf("expected error about unknown parameter, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Audit logging of MCP invocations
// ---------------------------------------------------------------------------

func TestCallTool_AuditLogging(t *testing.T) {
	store := db.NewMemoryStore(100)
	ks := &killswitch.Switch{}
	prx := testProxy()
	srv := NewServer(prx, store, ks)

	// Perform a series of tool calls.
	_, _ = srv.CallToolContext(context.Background(), "get_scope_status", map[string]interface{}{})
	_, _ = srv.CallToolContext(context.Background(), "is_kill_switch_active", map[string]interface{}{})
	_, _ = srv.CallToolContext(context.Background(), "check_url", map[string]interface{}{
		"url": "https://example.com/",
	})
	_, _ = srv.CallToolContext(context.Background(), "activate_kill_switch", map[string]interface{}{
		"reason": "emergency test",
	})

	// Check that audit log has entries.
	entries := store.SearchEntries("tool_invocation", "mcp")
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 tool_invocation audit entries, got %d", len(entries))
	}

	// Check kill_switch entry.
	ksEntries := store.SearchEntries("kill_switch", "mcp")
	if len(ksEntries) < 1 {
		t.Fatalf("expected at least 1 kill_switch audit entry, got %d", len(ksEntries))
	}

	lastKS := ksEntries[len(ksEntries)-1]
	if lastKS.Data == nil {
		t.Fatal("expected non-nil Data in kill_switch audit entry")
	}
	action, _ := lastKS.Data["action"].(string)
	if action != "activate" {
		t.Errorf("expected action 'activate', got %q", action)
	}
	reason, _ := lastKS.Data["reason"].(string)
	if reason != "emergency test" {
		t.Errorf("expected reason 'emergency test', got %q", reason)
	}
}

func TestCallTool_AuditRedactsSecrets(t *testing.T) {
	store := db.NewMemoryStore(100)
	srv := NewServer(testProxy(), store, &killswitch.Switch{})
	srv.SetDeactivationToken("expected-token")

	_, _ = srv.CallToolContext(context.Background(), "deactivate_kill_switch", map[string]interface{}{
		"token": "wrong-secret-token",
	})

	entries := store.SearchEntries("tool_invocation", "mcp")
	if len(entries) != 1 {
		t.Fatalf("expected one tool invocation, got %d", len(entries))
	}
	params, ok := entries[0].Data["params"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected params map, got %T", entries[0].Data["params"])
	}
	if params["token"] != "[REDACTED]" {
		t.Fatalf("expected token redaction, got %v", params["token"])
	}
}

func TestDashboardDoesNotExposeAPIKey(t *testing.T) {
	srv := testServer()
	srv.SetAPIKey("server-secret-api-key")

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	srv.Dashboard().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "server-secret-api-key") {
		t.Fatal("dashboard exposed the MCP API key")
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff header, got %q", got)
	}
}

func TestSpecialistToolsRequireRegistration(t *testing.T) {
	srv := testServer()
	if _, err := srv.CallToolContext(context.Background(), "run_recon_specialist", map[string]interface{}{
		"targets": []interface{}{"app.example.com"},
	}); err == nil {
		t.Fatal("expected unregistered specialist tool to be unavailable")
	}

	srv.ConfigureSpecialists(specialist.Config{
		MCPURL:    "http://127.0.0.1:9090",
		ProxyURL:  "http://127.0.0.1:8443",
		DryRun:    true,
		ProgramID: "test-program-1",
	})

	got := map[string]bool{}
	for _, tool := range srv.ListTools() {
		got[tool.Name] = true
	}
	for _, name := range []string{"run_recon_specialist", "run_vuln_specialist", "run_gate_specialist"} {
		if !got[name] {
			t.Fatalf("registered tool %q missing from list_tools", name)
		}
	}
}

func TestSpecialistExecutionBlockedByKillSwitch(t *testing.T) {
	srv := testServer()
	srv.ConfigureSpecialists(specialist.Config{DryRun: true})
	srv.ks.Activate("test")

	_, err := srv.CallToolContext(context.Background(), "run_recon_specialist", map[string]interface{}{
		"targets": []interface{}{"app.example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "kill switch") {
		t.Fatalf("expected kill-switch denial, got %v", err)
	}
}

func TestGateSpecialistRequiresApprovalToken(t *testing.T) {
	srv := testServer()
	srv.ConfigureSpecialists(specialist.Config{DryRun: true})
	srv.SetGateApprovalToken("operator-approved-token")

	_, err := srv.CallToolContext(context.Background(), "run_gate_specialist", map[string]interface{}{
		"targets":        []interface{}{"app.example.com"},
		"approval_token": "wrong-token",
	})
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("expected approval denial, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// HTTP handler (JSON-RPC 2.0)
// ---------------------------------------------------------------------------

func TestHTTPServeHTTP_ListTools(t *testing.T) {
	srv := testServer()
	handler := http.HandlerFunc(srv.ServeHTTP)

	body := toJSON(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "list_tools",
		"id":      1,
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		JSONRPC string    `json:"jsonrpc"`
		Result  []ToolDef `json:"result"`
		ID      int       `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc '2.0', got %q", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("expected id 1, got %v", resp.ID)
	}
	if len(resp.Result) != 9 {
		t.Errorf("expected 9 tools, got %d", len(resp.Result))
	}
}

func TestHTTPServeHTTP_CallTool(t *testing.T) {
	srv := testServer()
	handler := http.HandlerFunc(srv.ServeHTTP)

	body := toJSON(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "call_tool",
		"params": map[string]interface{}{
			"name":      "is_kill_switch_active",
			"arguments": map[string]interface{}{},
		},
		"id": 2,
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		JSONRPC string                 `json:"jsonrpc"`
		Result  map[string]interface{} `json:"result"`
		ID      int                    `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc '2.0', got %q", resp.JSONRPC)
	}
	if resp.ID != 2 {
		t.Errorf("expected id 2, got %v", resp.ID)
	}
	active, ok := resp.Result["active"].(bool)
	if !ok {
		t.Fatalf("expected 'active' boolean in result")
	}
	if active {
		t.Errorf("expected kill switch to be inactive")
	}
}

func TestHTTPServeHTTP_InvalidMethod(t *testing.T) {
	srv := testServer()
	handler := http.HandlerFunc(srv.ServeHTTP)

	body := toJSON(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "non_existent_method",
		"id":      3,
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		JSONRPC string    `json:"jsonrpc"`
		Error   *rpcError `json:"error"`
		ID      int       `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601 (Method not found), got %d", resp.Error.Code)
	}
}

func TestHTTPServeHTTP_GetRejected(t *testing.T) {
	srv := testServer()
	handler := http.HandlerFunc(srv.ServeHTTP)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTPServeHTTP_InvalidJSON(t *testing.T) {
	srv := testServer()
	handler := http.HandlerFunc(srv.ServeHTTP)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	return b
}

// Compile-time check that Server implements http.Handler.
var _ http.Handler = (*Server)(nil)

// Compile-time reference checks.
var _ = fmt.Sprintf("%T", &scope.Decision{})
var _ = fmt.Sprintf("%T", &ratelimit.PerHostLimiter{})
var _ = fmt.Sprintf("%T", &proxy.CheckResult{})
var _ = fmt.Sprintf("%T", proxy.ScopeSummary{})
var _ = fmt.Sprintf("%T", &proxy.RateLimitState{})

func TestJSONRPC_DirectToolNameMethod(t *testing.T) {
	srv := testServer()
	for _, method := range []string{"get_scope_status", "tools/call", "tools/list"} {
		body := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method}
		if method == "tools/call" {
			body["params"] = map[string]interface{}{"name": "get_scope_status", "arguments": map[string]interface{}{}}
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if srv.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+srv.apiKey)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != nil {
			t.Fatalf("method %q returned error: %v", method, resp["error"])
		}
		if resp["result"] == nil {
			t.Fatalf("method %q returned no result", method)
		}
	}
}
