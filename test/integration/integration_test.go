// Package integration_test contains end-to-end tests for ScopePilot that
// start the binary, send requests through the proxy and MCP servers, and
// verify correct behavior end-to-end.
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/config"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/mcp"
	"github.com/dhiren/pentest-automation/internal/proxy"
)

// TestProxyHealthCheck verifies the /health endpoint bypasses all safety layers.
func TestProxyHealthCheck(t *testing.T) {
	cfg := proxy.Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "app.example.com"},
			},
		},
	}
	p := proxy.NewProxy(cfg)

	// Health check should work even though this host is out of scope.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
}

// TestProxyHealthCheckDuringKillSwitch verifies health check works even when kill switch is active.
func TestProxyHealthCheckDuringKillSwitch(t *testing.T) {
	p := proxy.NewProxy(proxy.Config{ProgramID: "test"})
	p.Switch.Activate("tester")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check expected 200 even with kill switch, got %d", resp.StatusCode)
	}
}

// TestProxyScopeDeny verifies out-of-scope requests are denied.
func TestProxyScopeDeny(t *testing.T) {
	cfg := proxy.Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "app.example.com"},
			},
		},
	}
	p := proxy.NewProxy(cfg)
	p.Switch = &killswitch.Switch{}

	req := httptest.NewRequest(http.MethodGet, "https://evil.com/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("out-of-scope expected 403, got %d", resp.StatusCode)
	}
}

// TestProxyKillSwitchBlocksRequest verifies kill switch blocks all forwarding.
func TestProxyKillSwitchBlocksRequest(t *testing.T) {
	cfg := proxy.Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "wildcard_host", Value: "*.example.com"},
			},
		},
	}
	p := proxy.NewProxy(cfg)
	p.Switch = &killswitch.Switch{}

	// Activate kill switch.
	p.Switch.Activate("test")

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("kill switch expected 403, got %d", resp.StatusCode)
	}
}

// TestMCPScopeStatus verifies the MCP get_scope_status tool.
func TestMCPScopeStatus(t *testing.T) {
	cfg := proxy.Config{
		ProgramID:            "integration-test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "app.example.com"},
				{Type: "wildcard_host", Value: "*.example.com"},
			},
			Exclude: []config.ScopeRule{
				{Type: "exact_host", Value: "status.example.com"},
			},
		},
	}
	p := proxy.NewProxy(cfg)
	p.Switch = &killswitch.Switch{}
	p.Logger = audit.NewLogger(1000)

	srv := mcp.NewServer(p, p.Logger, p.Switch)
	srv.SetProgramID("integration-test-program")

	// Send list_tools request.
	reqBody := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"get_scope_status","arguments":{}},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("MCP expected 200, got %d", resp.StatusCode)
	}

	var mcpResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	json.NewDecoder(resp.Body).Decode(&mcpResp)

	if mcpResp.Error != nil {
		t.Fatalf("MCP error: %d %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	var status struct {
		ProgramID      string   `json:"program_id"`
		IncludeCount   int      `json:"include_count"`
		ExcludeCount   int      `json:"exclude_count"`
		AllowedSchemes []string `json:"allowed_schemes"`
		AllowedPorts   []int    `json:"allowed_ports"`
	}
	json.Unmarshal(mcpResp.Result, &status)

	if status.ProgramID != "integration-test-program" {
		t.Errorf("expected program_id 'integration-test-program', got %q", status.ProgramID)
	}
	if status.IncludeCount != 2 {
		t.Errorf("expected 2 include rules, got %d", status.IncludeCount)
	}
	if status.ExcludeCount != 1 {
		t.Errorf("expected 1 exclude rule, got %d", status.ExcludeCount)
	}
}

// TestMCPCheckURL verifies the MCP check_url tool.
func TestMCPCheckURL(t *testing.T) {
	cfg := proxy.Config{
		ProgramID:            "test",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "wildcard_host", Value: "*.example.com"},
			},
		},
	}
	p := proxy.NewProxy(cfg)
	p.Switch = &killswitch.Switch{}
	p.Logger = audit.NewLogger(1000)
	p.SetDNSOverride(func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	})

	srv := mcp.NewServer(p, p.Logger, p.Switch)
	srv.SetProgramID("test")

	// Test in-scope URL.
	reqBody := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"check_url","arguments":{"url":"https://app.example.com/page"}},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	var mcpResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	json.NewDecoder(resp.Body).Decode(&mcpResp)

	if mcpResp.Error != nil {
		t.Fatalf("MCP error for in-scope URL: %d %s", mcpResp.Error.Code, mcpResp.Error.Message)
	}

	var result map[string]interface{}
	json.Unmarshal(mcpResp.Result, &result)
	if result["allowed"] != true {
		t.Errorf("expected allowed=true for in-scope URL, got: %v", result)
	}

	// Test out-of-scope URL.
	reqBody2 := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"check_url","arguments":{"url":"https://evil.com/page"}},"id":2}`
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	var mcpResp2 struct {
		Result json.RawMessage `json:"result"`
	}
	json.NewDecoder(resp2.Body).Decode(&mcpResp2)
	json.Unmarshal(mcpResp2.Result, &result)
	if result["allowed"] == true {
		t.Errorf("expected allowed=false for out-of-scope URL, got: %v", result)
	}
}

// TestMCPKillSwitch verifies kill switch activation/deactivation via MCP.
func TestMCPKillSwitch(t *testing.T) {
	p := proxy.NewProxy(proxy.Config{ProgramID: "test", ActiveTestingEnabled: true})
	p.Switch = &killswitch.Switch{}
	p.Logger = audit.NewLogger(1000)

	srv := mcp.NewServer(p, p.Logger, p.Switch)
	srv.SetProgramID("test")
	srv.SetDeactivationToken("test-token-123")

	// Activate via MCP.
	reqBody := fmt.Sprintf(`{"jsonrpc":"2.0","method":"call_tool","params":{"name":"activate_kill_switch","arguments":{"reason":"%s"}},"id":1}`, "integration test")
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp := w.Result()
	resp.Body.Close()

	if !p.Switch.IsActive() {
		t.Error("kill switch should be active after MCP activation")
	}

	// Verify proxy blocks requests.
	proxyReq := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	proxyW := httptest.NewRecorder()
	p.ServeHTTP(proxyW, proxyReq)
	proxyResp := proxyW.Result()
	defer proxyResp.Body.Close()
	if proxyResp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when kill switch active via MCP, got %d", proxyResp.StatusCode)
	}

	// Deactivate via MCP.
	reqBody2 := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"deactivate_kill_switch","arguments":{"token":"test-token-123"}},"id":2}`
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	resp2.Body.Close()

	if p.Switch.IsActive() {
		t.Error("kill switch should be inactive after MCP deactivation")
	}
}

// TestMCPKillSwitchDeactivationWithWrongToken verifies deactivation requires correct token.
func TestMCPKillSwitchDeactivationWithWrongToken(t *testing.T) {
	p := proxy.NewProxy(proxy.Config{ProgramID: "test", ActiveTestingEnabled: true})
	p.Switch = &killswitch.Switch{}
	p.Switch.Activate("test")
	p.Logger = audit.NewLogger(1000)

	srv := mcp.NewServer(p, p.Logger, p.Switch)
	srv.SetProgramID("test")
	srv.SetDeactivationToken("test-token-123")

	// Try to deactivate with wrong token.
	reqBody := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"deactivate_kill_switch","arguments":{"token":"wrong-token"}},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	var mcpResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	json.NewDecoder(resp.Body).Decode(&mcpResp)

	// The handler returns a JSON-RPC error for wrong token.
	if mcpResp.Error == nil {
		t.Fatal("expected error for wrong deactivation token")
	}
	if !strings.Contains(mcpResp.Error.Message, "token") {
		t.Errorf("expected error about token, got: %s", mcpResp.Error.Message)
	}

	// Kill switch should still be active after failed deactivation.
	if !p.Switch.IsActive() {
		t.Error("kill switch should still be active after failed deactivation attempt")
	}
}

// TestMCPAuth verifies API key authentication.
func TestMCPAuth(t *testing.T) {
	p := proxy.NewProxy(proxy.Config{ProgramID: "test", ActiveTestingEnabled: true})
	p.Switch = &killswitch.Switch{}
	p.Logger = audit.NewLogger(1000)

	srv := mcp.NewServer(p, p.Logger, p.Switch)
	srv.SetProgramID("test")
	srv.SetAPIKey("secret-key-123")

	// Request without auth header.
	reqBody := `{"jsonrpc":"2.0","method":"call_tool","params":{"name":"is_kill_switch_active","arguments":{}},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	// Request with correct auth header.
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer secret-key-123")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct auth, got %d", resp2.StatusCode)
	}

	// Request with wrong auth header.
	req3 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer wrong-key")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)

	resp3 := w3.Result()
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong auth, got %d", resp3.StatusCode)
	}
}
