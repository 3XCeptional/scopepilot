package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBBOTArgs(t *testing.T) {
	targets := []string{"example.com", "test.com"}
	proxyURL := "http://127.0.0.1:8443"

	args := bbotArgs(targets, proxyURL, false, 2)

	// Verify targets
	foundTargets := false
	for _, a := range args {
		if a == "example.com,test.com" {
			foundTargets = true
			break
		}
	}
	if !foundTargets {
		t.Error("bbotArgs: targets not found in args")
	}

	// Verify modern flags (not removed v1.x flags)
	for _, bad := range []string{"--passive-only", "--no-dns", "--no-www"} {
		for _, a := range args {
			if a == bad {
				t.Errorf("bbotArgs: deprecated flag %s should not be present", bad)
			}
		}
	}

	// Verify modern flags present
	hasRFPassive := false
	hasJSON := false
	hasYes := false
	for _, a := range args {
		switch a {
		case "-rf":
			hasRFPassive = true
		case "-om":
			hasJSON = true
		case "-y":
			hasYes = true
		}
	}
	if !hasRFPassive {
		t.Error("bbotArgs: missing -rf flag for module filtering")
	}
	if !hasJSON {
		t.Error("bbotArgs: missing output module flag")
	}
	if !hasYes {
		t.Error("bbotArgs: missing -y non-interactive flag")
	}
}

func TestNucleiArgs(t *testing.T) {
	templateDir := "/templates"
	targets := []string{"example.com", "test.com"}

	args := nucleiArgs(templateDir, targets, "/tmp/test_output.jsonl", 3)

	// Verify -jsonl present (not deprecated -json)
	hasJSONL := false
	hasDeprecatedJSON := false
	for _, a := range args {
		if a == "-jsonl" {
			hasJSONL = true
		}
		if a == "-json" {
			hasDeprecatedJSON = true
		}
	}
	if !hasJSONL {
		t.Error("nucleiArgs: missing -jsonl flag (v3.x+)")
	}
	if hasDeprecatedJSON {
		t.Error("nucleiArgs: deprecated -json flag should not be present")
	}

	// Verify template dir
	foundTemplate := false
	for _, a := range args {
		if a == templateDir {
			foundTemplate = true
			break
		}
	}
	if !foundTemplate {
		t.Error("nucleiArgs: template directory not found in args")
	}

	// Verify targets present
	for _, target := range targets {
		found := false
		for _, a := range args {
			if a == target {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("nucleiArgs: target %q not found", target)
		}
	}
}

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"2.14.0", 2},
		{"3.0.0", 3},
		{"1.5.2", 1},
		{"BBOT v2.14.0", 2},
		{"nuclei 3.2.1", 3},
		{"garbage", 0},
		{"", 0},
		{"0.1.0", 0},
	}
	for _, tc := range tests {
		got := parseMajorVersion(tc.input)
		if got != tc.want {
			t.Errorf("parseMajorVersion(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestBBOTArgsNoDeprecatedFlags(t *testing.T) {
	args := bbotArgs([]string{"x.com"}, "http://proxy:8080", false, 2)
	argStr := strings.Join(args, " ")
	deprecated := []string{"--passive-only", "--no-dns", "--no-www"}
	for _, d := range deprecated {
		if strings.Contains(argStr, d) {
			t.Errorf("bbot args contain deprecated flag %q: %s", d, args)
		}
	}
}

func TestNucleiArgsNoDeprecatedFlags(t *testing.T) {
	args := nucleiArgs("/templates", []string{"x.com"}, "/tmp/test.jsonl", 3)
	argStr := strings.Join(args, " ")
	if strings.Contains(argStr, "-json ") {
		t.Errorf("nuclei args contain deprecated -json flag: %s", args)
	}
}

func TestNucleiArgsNoHardcodedTmp(t *testing.T) {
	// RunNuclei now uses os.CreateTemp for a unique, per-run path.
	// Verify nucleiArgs does NOT contain a bare /tmp/ path.
	args := nucleiArgs("/t", []string{"h.com"}, "/tmp/scopepilot_nuclei_out.jsonl", 3)
	argStr := strings.Join(args, " ")
	if !strings.Contains(argStr, "/tmp/") {
		t.Error("expected /tmp/ in args (test uses /tmp path), but check that it's the param not hardcoded")
	}
	// Now verify with a non-/tmp path to confirm the param is used.
	args2 := nucleiArgs("/t", []string{"h.com"}, filepath.Join(t.TempDir(), "out.jsonl"), 3)
	argStr2 := strings.Join(args2, " ")
	if strings.Contains(argStr2, "/tmp/scopepilot") {
		t.Error("nucleiArgs still contains hardcoded /tmp/scopepilot path: " + argStr2)
	}
}

func TestBBOTArgs_Version1(t *testing.T) {
	targets := []string{"x.com"}
	args := bbotArgs(targets, "http://proxy:8080", false, 1)
	argStr := strings.Join(args, " ")
	// v1 should use deprecated flags
	for _, want := range []string{"--passive-only", "--no-dns", "--no-www", "--force", "-o", "json"} {
		if !strings.Contains(argStr, want) {
			t.Errorf("bbotArgs(v1): expected %q in args: %s", want, argStr)
		}
	}
	// v1 should NOT have v2-only flags
	for _, bad := range []string{"-rf", "-om"} {
		if strings.Contains(argStr, bad) {
			t.Errorf("bbotArgs(v1): unexpected v2 flag %q in v1 args: %s", bad, argStr)
		}
	}
}

func TestBBOTArgs_Version0(t *testing.T) {
	// unknown version (0) should default to v2 (current) flags
	args := bbotArgs([]string{"x.com"}, "http://proxy:8080", false, 0)
	argStr := strings.Join(args, " ")
	if !strings.Contains(argStr, "-rf") {
		t.Errorf("bbotArgs(v0): expected v2 flag -rf for unknown version: %s", argStr)
	}
	// hard assert no v1 deprecated flags
	for _, bad := range []string{"--passive-only", "--no-dns", "--no-www"} {
		if strings.Contains(argStr, bad) {
			t.Errorf("bbotArgs(v0): unexpected v1 flag %q: %s", bad, argStr)
		}
	}
}

func TestNucleiArgs_Version2(t *testing.T) {
	args := nucleiArgs("/t", []string{"h.com"}, "/tmp/o.jsonl", 2)
	argStr := strings.Join(args, " ")
	// v2 should use -json not -jsonl
	if !strings.Contains(argStr, "-json ") {
		t.Errorf("nucleiArgs(v2): expected -json flag for v2: %s", argStr)
	}
	if strings.Contains(argStr, "-jsonl") {
		t.Errorf("nucleiArgs(v2): unexpected -jsonl flag in v2 args: %s", argStr)
	}
}

func TestNucleiArgs_Version0(t *testing.T) {
	// unknown version (0) should default to v3 (current) flags
	args := nucleiArgs("/t", []string{"h.com"}, "/tmp/o.jsonl", 0)
	argStr := strings.Join(args, " ")
	if !strings.Contains(argStr, "-jsonl") {
		t.Errorf("nucleiArgs(v0): expected -jsonl for unknown version: %s", argStr)
	}
	if strings.Contains(argStr, "-json ") {
		t.Errorf("nucleiArgs(v0): unexpected -json flag for unknown version: %s", argStr)
	}
}

func TestParseNucleiOutput_SampleJSONL(t *testing.T) {
	sample := `{"template-id":"tech-detect","name":"Tech Detection","severity":"info","host":"https://app.example.com","type":"http"}
{"template-id":"cve-2024-0001","name":"Test CVE","severity":"high","host":"https://app.example.com","type":"http"}
`
	findings := parseNucleiOutput(sample)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}
	// First should be info severity.
	if !strings.Contains(findings[0], "[info]") {
		t.Errorf("expected first finding severity 'info', got %q", findings[0])
	}
	// Non-JSON line should be skipped silently.
	findings2 := parseNucleiOutput("banner line\n" + sample + "trailing\n")
	if len(findings2) != 2 {
		t.Errorf("expected 2 findings with banner noise, got %d", len(findings2))
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
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s' \"$HTTP_PROXY\" \"$HTTPS_PROXY\" \"$ALL_PROXY\" \"$NO_PROXY\"\n"), 0700); err != nil {
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
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$*\"\n"), 0700); err != nil {
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
