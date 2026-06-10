package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dhiren/pentest-automation/internal/config"
)

// connectProxyConfig returns a Config whose scope includes tunnel.example.com.
func connectProxyConfig() Config {
	return Config{
		ProgramID:            "test-program",
		ActiveTestingEnabled: true,
		AllowedSchemes:       []string{"https"},
		AllowedPorts:         []int{443},
		ScopeCfg: config.ScopeConfig{
			Include: []config.ScopeRule{
				{Type: "exact_host", Value: "tunnel.example.com"},
			},
		},
	}
}

// newConnectRequest builds a CONNECT request for host:port with a recorder.
func newConnectRequest(authority string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodConnect, "http://"+authority, nil)
	req.Host = authority
	return req, httptest.NewRecorder()
}

// TestConnect_OutOfScopeDenied verifies a CONNECT to an out-of-scope host is 403.
func TestConnect_OutOfScopeDenied(t *testing.T) {
	p := NewProxy(connectProxyConfig())
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	req, w := newConnectRequest("evil.example.org:443")
	p.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for out-of-scope CONNECT, got %d", w.Result().StatusCode)
	}
}

// TestConnect_BlockedPortDenied verifies a CONNECT to a non-allowed port is 403.
func TestConnect_BlockedPortDenied(t *testing.T) {
	p := NewProxy(connectProxyConfig())
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	req, w := newConnectRequest("tunnel.example.com:8080")
	p.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for blocked-port CONNECT, got %d", w.Result().StatusCode)
	}
}

// TestConnect_KillSwitchDenied verifies an active kill switch blocks CONNECT.
func TestConnect_KillSwitchDenied(t *testing.T) {
	p := NewProxy(connectProxyConfig())
	p.lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	p.Switch.Activate("test")
	req, w := newConnectRequest("tunnel.example.com:443")
	p.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when kill switch active, got %d", w.Result().StatusCode)
	}
}

// TestConnect_InScopeRelaysBytes verifies an in-scope CONNECT returns 200 and
// relays bytes end-to-end. Requires binding local listeners; skipped when the
// environment forbids binding (e.g. a network-restricted sandbox).
func TestConnect_InScopeRelaysBytes(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind local listener in this environment: %v", err)
	}
	probe.Close()

	const want = "hello-tunnel"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, want)
	}))
	defer target.Close()
	targetAddr := target.Listener.Addr().String()

	p := NewProxy(connectProxyConfig())
	// DNS returns a public IP so the IP blocklist passes; the dial override
	// redirects the connection to the loopback test server.
	p.SetDNSOverride(func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	})
	p.dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("tcp", targetAddr, timeout)
	}

	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "tunnel.example.com",
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://tunnel.example.com:443/")
	if err != nil {
		t.Fatalf("CONNECT tunnel request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 through tunnel, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != want {
		t.Errorf("expected relayed body %q, got %q", want, string(body))
	}
}

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
