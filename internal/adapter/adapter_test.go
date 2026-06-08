package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
