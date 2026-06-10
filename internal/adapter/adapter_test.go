package adapter

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
)

func TestMCPClient_BearerToken(t *testing.T) {
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Skipf("cannot bind socket: %v", err)
	} else {
		_ = ln.Close()
	}
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  SafeCheckResult{URL: "https://app.example.com/", Allowed: true},
			"id":      1,
		})
	}))
	defer mcpServer.Close()

	client := NewMCPClientWithAPIKey(mcpServer.URL, "test-prog", "test-api-key")
	result, err := client.CheckURL(context.Background(), "https://app.example.com/")
	if err != nil {
		t.Fatalf("CheckURL failed: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected authenticated request to be allowed")
	}
}

func TestNewMCPClient_ReadsAPIKeyFromEnvironment(t *testing.T) {
	t.Setenv("SCOPEPILOT_MCP_API_KEY", "env-api-key")
	client := NewMCPClient("http://127.0.0.1:9090", "test-prog")
	if client.APIKey != "env-api-key" {
		t.Fatalf("expected API key from environment, got %q", client.APIKey)
	}
}

func TestMCPClient_CheckURL(t *testing.T) {
	// Create a test MCP server that simulates ScopePilot responses.
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.Method == "call_tool" {
			var call struct {
				Name      string `json:"name"`
				Arguments struct {
					URL string `json:"url"`
				} `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &call); err != nil {
				http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"invalid params"},"id":1}`, http.StatusBadRequest)
				return
			}

			var result SafeCheckResult
			if call.Arguments.URL == "https://app.example.com/" {
				result = SafeCheckResult{URL: call.Arguments.URL, Allowed: true, Reason: "in scope"}
			} else {
				result = SafeCheckResult{URL: call.Arguments.URL, Allowed: false, Reason: "out of scope"}
			}

			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"result":  result,
				"id":      1,
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer mcpServer.Close()

	client := NewMCPClient(mcpServer.URL, "test-prog")

	ctx := context.Background()

	// Test in-scope URL.
	result, err := client.CheckURL(ctx, "https://app.example.com/")
	if err != nil {
		t.Fatalf("CheckURL failed: %v", err)
	}
	if result == nil || !result.Allowed {
		t.Errorf("expected allowed=true, got %+v", result)
	}

	// Test out-of-scope URL.
	result, err = client.CheckURL(ctx, "https://evil.com/")
	if err != nil {
		t.Fatalf("CheckURL failed: %v", err)
	}
	if result == nil || result.Allowed {
		t.Errorf("expected allowed=false, got %+v", result)
	}
}

func TestMCPClient_RunSafeCheck(t *testing.T) {
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Method == "call_tool" {
			var call struct {
				Name      string `json:"name"`
				Arguments struct {
					URLs []string `json:"urls"`
				} `json:"arguments"`
			}
			json.Unmarshal(req.Params, &call)

			var results []SafeCheckResult
			for _, u := range call.Arguments.URLs {
				allowed := false
				if u == "https://good.example.com/" {
					allowed = true
				}
				results = append(results, SafeCheckResult{
					URL:     u,
					Allowed: allowed,
					Reason:  "scope check",
				})
			}

			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"result": RunSafeCheckResponse{
					Results: results,
				},
				"id": 1,
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer mcpServer.Close()

	client := NewMCPClient(mcpServer.URL, "test-prog")
	ctx := context.Background()

	result, err := client.RunSafeCheck(ctx, []string{
		"https://good.example.com/",
		"https://bad.example.com/",
	})
	if err != nil {
		t.Fatalf("RunSafeCheck failed: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result.Results))
	}
	if !result.Results[0].Allowed {
		t.Error("expected first result allowed=true")
	}
	if result.Results[1].Allowed {
		t.Error("expected second result allowed=false")
	}
}

func TestFilterInScope(t *testing.T) {
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		var call struct {
			Name      string `json:"name"`
			Arguments struct {
				URL string `json:"url"`
			} `json:"arguments"`
		}
		json.Unmarshal(req.Params, &call)

		allowed := call.Arguments.URL == "https://app.example.com" || call.Arguments.URL == "https://app.example.com/"
		result := SafeCheckResult{URL: call.Arguments.URL, Allowed: allowed}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  result,
			"id":      1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mcpServer.Close()

	client := NewMCPClient(mcpServer.URL, "test-prog")
	ctx := context.Background()

	inScope, blocked := client.FilterInScope(ctx, []string{
		"app.example.com",
		"evil.com",
	})

	if len(inScope) != 1 || inScope[0] != "app.example.com" {
		t.Errorf("expected [app.example.com] in scope, got %v", inScope)
	}
	if len(blocked) != 1 || blocked[0] != "evil.com" {
		t.Errorf("expected [evil.com] blocked, got %v", blocked)
	}
}

func TestParseBBOTOutput(t *testing.T) {
	output := `{"type":"DNS_NAME","host":"sub.example.com","event_index":0}
{"type":"URL","host":"app.example.com","event_index":1}
{"type":"URL_UNVERIFIED","host":"test.example.com","event_index":2}
invalid json line
`

	hosts := parseBBOTOutput(output)
	if len(hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "sub.example.com" {
		t.Errorf("expected sub.example.com, got %s", hosts[0])
	}
}

func TestParseNucleiOutput(t *testing.T) {
	output := `{"template-id":"tech-detect","name":"Tech Detection","severity":"info","host":"https://app.example.com","type":"http"}
{"template-id":"cve-2024-0001","name":"Test CVE","severity":"high","host":"https://app.example.com","type":"http"}
invalid
`

	findings := parseNucleiOutput(output)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}
}

func TestBBOTConfig_DryRun(t *testing.T) {
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := SafeCheckResult{URL: "https://app.example.com/", Allowed: true}
		resp := map[string]interface{}{"jsonrpc": "2.0", "result": result, "id": 1}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mcpServer.Close()

	client := NewMCPClient(mcpServer.URL, "test-prog")
	cfg := BBOTConfig{
		BinaryPath: "bbot",
		MCPClient:  client,
		DryRun:     true,
		Timeout:    10,
	}

	ctx := context.Background()
	result, err := RunBBOT(ctx, cfg, []string{"app.example.com"})
	if err != nil {
		t.Fatalf("RunBBOT dry run failed: %v", err)
	}
	if !result.DryRun {
		t.Error("expected dry_run=true")
	}
	if result.TargetsScanned != 1 {
		t.Errorf("expected 1 target scanned, got %d", result.TargetsScanned)
	}
	if result.TargetsBlocked != 0 {
		t.Errorf("expected 0 blocked, got %d", result.TargetsBlocked)
	}
}

func TestNucleiConfig_DryRun(t *testing.T) {
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := SafeCheckResult{URL: "https://app.example.com/", Allowed: true}
		resp := map[string]interface{}{"jsonrpc": "2.0", "result": result, "id": 1}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mcpServer.Close()

	client := NewMCPClient(mcpServer.URL, "test-prog")
	cfg := NucleiConfig{
		BinaryPath:  "nuclei",
		MCPClient:   client,
		DryRun:      true,
		Timeout:     10,
		TemplateDir: "/templates",
	}

	ctx := context.Background()
	result, err := RunNuclei(ctx, cfg, []string{"app.example.com"})
	if err != nil {
		t.Fatalf("RunNuclei dry run failed: %v", err)
	}
	if !result.DryRun {
		t.Error("expected dry_run=true")
	}
	if result.TargetsScanned != 1 {
		t.Errorf("expected 1 target scanned, got %d", result.TargetsScanned)
	}
}

func TestRunBBOT_RequiresProxyForExecution(t *testing.T) {
	client, closeServer := allowAllMCPClient(t)
	defer closeServer()

	_, err := RunBBOT(context.Background(), BBOTConfig{
		BinaryPath: "/bin/false",
		MCPClient:  client,
	}, []string{"app.example.com"})
	if err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("expected proxy configuration error, got %v", err)
	}
}

func TestRunNuclei_RequiresProxyForExecution(t *testing.T) {
	client, closeServer := allowAllMCPClient(t)
	defer closeServer()

	_, err := RunNuclei(context.Background(), NucleiConfig{
		BinaryPath:  "/bin/false",
		MCPClient:   client,
		TemplateDir: "/templates",
	}, []string{"app.example.com"})
	if err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("expected proxy configuration error, got %v", err)
	}
}

func TestRunBBOT_RejectsUnsupportedVPNNamespace(t *testing.T) {
	client, closeServer := allowAllMCPClient(t)
	defer closeServer()

	_, err := RunBBOT(context.Background(), BBOTConfig{
		BinaryPath:   "/bin/false",
		MCPClient:    client,
		ProxyURL:     "http://127.0.0.1:8443",
		VPNContainer: "scopepilot-vpn",
	}, []string{"app.example.com"})
	if err == nil || !strings.Contains(err.Error(), "VPN") {
		t.Fatalf("expected fail-closed VPN error, got %v", err)
	}
}

func TestRunNuclei_PropagatesProxyEnvironment(t *testing.T) {
	client, closeServer := allowAllMCPClient(t)
	defer closeServer()

	script := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s' \"$HTTP_PROXY\" \"$HTTPS_PROXY\" \"$ALL_PROXY\" \"$NO_PROXY\"\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}

	result, err := RunNuclei(context.Background(), NucleiConfig{
		BinaryPath:  script,
		MCPClient:   client,
		TemplateDir: "/templates",
		ProxyURL:    "http://127.0.0.1:8443",
	}, []string{"app.example.com"})
	if err != nil {
		t.Fatalf("RunNuclei failed: %v", err)
	}
	want := "http://127.0.0.1:8443|http://127.0.0.1:8443|http://127.0.0.1:8443|"
	if result.RawOutput != want {
		t.Fatalf("unexpected proxy environment: got %q want %q", result.RawOutput, want)
	}
}

func TestRunNuclei_UsesLowImpactDefaults(t *testing.T) {
	client, closeServer := allowAllMCPClient(t)
	defer closeServer()

	script := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$*\"\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}

	result, err := RunNuclei(context.Background(), NucleiConfig{
		BinaryPath:  script,
		MCPClient:   client,
		TemplateDir: "/templates",
		ProxyURL:    "http://127.0.0.1:8443",
	}, []string{"app.example.com"})
	if err != nil {
		t.Fatalf("RunNuclei failed: %v", err)
	}
	for _, expected := range []string{
		"-severity info,low",
		"-exclude-tags fuzz,dos,headless,code",
		"-proxy http://127.0.0.1:8443",
	} {
		if !strings.Contains(result.RawOutput, expected) {
			t.Fatalf("expected %q in args: %s", expected, result.RawOutput)
		}
	}
}

func allowAllMCPClient(t *testing.T) (*MCPClient, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  SafeCheckResult{URL: "https://app.example.com", Allowed: true},
			"id":      1,
		})
	}))
	return NewMCPClient(server.URL, "test-prog"), server.Close
}
