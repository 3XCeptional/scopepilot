package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dhiren/pentest-automation/internal/config"
)

// TestActiveTestingEnabled verifies ActiveTestingEnabled flag controls request forwarding.
func TestActiveTestingEnabled(t *testing.T) {
	t.Run("disabled_denies_via_ServeHTTP", func(t *testing.T) {
		cfg := Config{
			ProgramID:            "test-program",
			ActiveTestingEnabled: false,
			AllowedSchemes:       []string{"https"},
			ScopeCfg: config.ScopeConfig{
				Include: []config.ScopeRule{
					{Type: "exact_host", Value: "example.com"},
				},
			},
		}
		p := NewProxy(cfg)
		p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("enabled_passes_gate", func(t *testing.T) {
		cfg := Config{
			ProgramID:            "test-program",
			ActiveTestingEnabled: true,
			AllowedSchemes:       []string{"http"},
			AllowedPorts:         []int{80},
			ScopeCfg: config.ScopeConfig{
				Include: []config.ScopeRule{
					{Type: "exact_host", Value: "enabled-test.example.com"},
				},
			},
		}
		p := NewProxy(cfg)
		p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		}
		result, err := p.CheckURL("http://enabled-test.example.com/test")
		if err != nil {
			t.Fatalf("CheckURL error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected CheckURL allow, got reason: %s", result.Reason)
		}
	})
}

// TestActiveTestingEnabledCheckURL verifies CheckURL respects ActiveTestingEnabled.
func TestActiveTestingEnabledCheckURL(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: false,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	result, err := p.CheckURL("https://example.com/test")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected denied, got allowed=true, reason: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "active testing disabled") {
		t.Errorf("expected 'active testing disabled', got: %s", result.Reason)
	}
}

// TestCheckURL validates a known-good URL passes all safety checks.
func TestCheckURL(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "checkurl-test.example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	result, err := p.CheckURL("https://checkurl-test.example.com/test")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed, got: %s", result.Reason)
	}
}

// TestCheckURL_DeniedScheme validates that an http URL is denied when only https is allowed.
func TestCheckURL_DeniedScheme(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	result, err := p.CheckURL("http://example.com/test")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected denied for http, got allowed: %s", result.Reason)
	}
}

// TestCheckURL_OutOfScope validates a host not in scope is denied.
func TestCheckURL_OutOfScope(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	result, err := p.CheckURL("https://evil.com/test")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected denied for out-of-scope, got allowed: %s", result.Reason)
	}
}

// TestCheckURL_BlockedIP validates private IPs are blocked.
func TestCheckURL_BlockedIP(t *testing.T) {
	cfg := Config{
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
	p := NewProxy(cfg)
	// Return a private IP — must be blocked.
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	result, err := p.CheckURL("https://app.example.com/test")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected denied for 10.0.0.1, got allowed: %s", result.Reason)
	}
}

// TestCheckURL_PathExcluded validates path_prefix exclusion works.
func TestCheckURL_PathExcluded(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "wildcard_host", Value: "*.example.com"},
			},
			Exclude: []config.ScopeRule{
				{Type: "path_prefix", Value: "/admin", Host: "app.example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	result, err := p.CheckURL("https://app.example.com/admin/panel")
	if err != nil {
		t.Fatalf("CheckURL error: %v", err)
	}
	if result.Allowed {
		t.Errorf("expected denied for /admin path, got allowed: %s", result.Reason)
	}
}

// TestDryRun validates dry-run mode returns decision without forwarding.
func TestDryRun(t *testing.T) {
	cfg := Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		DryRun:               true,
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "dryrun-test.example.com"},
			},
		},
	}
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "https://dryrun-test.example.com/page", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for dry-run, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode dry-run response: %v", err)
	}
	if body["dry_run"] != true {
		t.Errorf("expected dry_run=true in response")
	}
	if body["allowed"] != true {
		t.Errorf("expected allowed=true in dry-run response, got: %v", body["allowed"])
	}
}

// TestKillSwitchBlocks validates kill switch stops all requests.
func TestKillSwitchBlocks(t *testing.T) {
	cfg := Config{
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
	p := NewProxy(cfg)
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	p.Switch.Activate("test")
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when kill switch active, got %d", resp.StatusCode)
	}
}

// TestValidateScheme tests scheme validation.
func TestValidateScheme(t *testing.T) {
	p := &Proxy{}
	p.AllowedSchemes = []string{"https"}
	if p.ValidateScheme("http") {
		t.Error("expected http to be denied")
	}
	if !p.ValidateScheme("https") {
		t.Error("expected https to be allowed")
	}
}

// TestValidatePort tests port validation.
func TestValidatePort(t *testing.T) {
	p := &Proxy{}
	p.AllowedPorts = []int{443}
	if _, ok := p.ValidatePort("80", "https"); ok {
		t.Error("expected port 80 to be denied")
	}
	if _, ok := p.ValidatePort("443", "https"); !ok {
		t.Error("expected port 443 to be allowed")
	}
}
