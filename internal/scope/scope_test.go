package scope

import (
	"net"
	"testing"

	"github.com/dhiren/pentest-automation/internal/config"
)

func makeScopeConfig(includes, excludes []config.ScopeRule) config.ScopeConfig {
	return config.ScopeConfig{
		Include: includes,
		Exclude: excludes,
	}
}

func TestIsHostInScope(t *testing.T) {
	engine := NewEngine("test-prog", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "exact_host", Value: "app.example.com"},
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		[]config.ScopeRule{
			{Type: "exact_host", Value: "status.example.com"},
			{Type: "exact_host", Value: "admin.example.com"},
		},
	))

	tests := []struct {
		host    string
		inScope bool
	}{
		{"app.example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"status.example.com", false},
		{"admin.example.com", false},
		{"other.com", false},
		{"", false},
		{"APP.EXAMPLE.COM", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			dec := engine.IsHostInScope(tt.host)
			if dec.InScope != tt.inScope {
				t.Errorf("IsHostInScope(%q) = %v, want %v. Reason: %s", tt.host, dec.InScope, tt.inScope, dec.Reason)
			}
		})
	}
}

func TestIsURLInScope(t *testing.T) {
	engine := NewEngine("test-prog", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		[]config.ScopeRule{
			{Type: "path_prefix", Value: "/logout", Host: "app.example.com"},
		},
	))

	allowedSchemes := []string{"https"}
	allowedPorts := []int{443}

	tests := []struct {
		url     string
		inScope bool
	}{
		{"https://app.example.com/dashboard", true},
		{"https://app.example.com/logout", false},
		{"https://app.example.com/logout/extra", false},
		{"http://app.example.com", false},
		{"https://other.com", false},
		{"https://app.example.com:8443", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			dec := engine.IsURLInScope(tt.url, allowedSchemes, allowedPorts)
			if dec.InScope != tt.inScope {
				t.Errorf("IsURLInScope(%q) = %v, want %v. Reason: %s", tt.url, dec.InScope, tt.inScope, dec.Reason)
			}
		})
	}
}

func TestIsIPInScope(t *testing.T) {
	engine := NewEngine("test-prog", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "cidr", Value: "93.184.216.0/24"},
		},
		nil,
	))

	tests := []struct {
		ip      string
		inScope bool
	}{
		{"93.184.216.34", true},
		{"93.184.216.1", true},
		{"93.184.216.255", true},
		{"1.2.3.4", false},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			dec := engine.IsIPInScope(ip)
			if dec.InScope != tt.inScope {
				t.Errorf("IsIPInScope(%s) = %v, want %v. Reason: %s", tt.ip, dec.InScope, tt.inScope, dec.Reason)
			}
		})
	}
}

func TestBlockedIPs(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.255",
		"169.254.1.1", "169.254.169.254",
		"224.0.0.1",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"100.64.0.1", "100.127.255.255",
		"0.0.0.1", "240.0.0.1",
		"::1",
		"fe80::1",
		"fd00::1", "fc00::1",
		"::ffff:10.0.0.1",
		"::ffff:127.0.0.1",
		"::ffff:192.168.1.1",
		"::ffff:169.254.169.254",
	}

	for _, ipStr := range blocked {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			if !isBlockedIP(ip) {
				t.Errorf("expected %s to be blocked", ipStr)
			}
		})
	}
}

func TestNotBlockedIPs(t *testing.T) {
	allowed := []string{
		"8.8.8.8", "1.1.1.1",
		"93.184.216.34", "45.33.32.156",
		"2001:db8::1",
		"2606:4700::1",
	}

	for _, ipStr := range allowed {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			if isBlockedIP(ip) {
				t.Errorf("expected %s to be allowed", ipStr)
			}
		})
	}
}

func TestExclusionOverridesInclusion(t *testing.T) {
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		[]config.ScopeRule{
			{Type: "exact_host", Value: "status.example.com"},
			{Type: "path_prefix", Value: "/restricted", Host: "app.example.com"},
		},
	))

	tests := []struct {
		url     string
		inScope bool
	}{
		{"https://app.example.com/page", true},
		{"https://status.example.com", false},
		{"https://app.example.com/restricted", false},
		{"https://app.example.com/restricted/data", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			dec := engine.IsURLInScope(tt.url, []string{"https"}, []int{443})
			if dec.InScope != tt.inScope {
				t.Errorf("%s: inScope=%v, want %v. Reason: %s", tt.url, dec.InScope, tt.inScope, dec.Reason)
			}
		})
	}
}

func TestInternationalizedDomainNames(t *testing.T) {
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "exact_host", Value: "xn--mnich-kva.example.com"},
		},
		nil,
	))

	// IDN in its native form should normalize to Punycode and match.
	dec := engine.IsHostInScope("münich.example.com")
	if !dec.InScope {
		t.Errorf("IDN host should match: %s", dec.Reason)
	}

	// Punycode form should also match.
	dec2 := engine.IsHostInScope("xn--mnich-kva.example.com")
	if !dec2.InScope {
		t.Errorf("Punycode host should match: %s", dec2.Reason)
	}
}

func TestCNAMELeavingScope(t *testing.T) {
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		nil,
	))

	dec := engine.IsHostInScope("cdn.example.com")
	if !dec.InScope {
		t.Fatal("cdn.example.com should be in scope")
	}

	dec2 := engine.IsHostInScope("cdn.other-service.com")
	if dec2.InScope {
		t.Error("CNAME target should be out of scope")
	}
}

func TestWildcardApex_NotIncludedByDefault(t *testing.T) {
	// Default IncludeApex=false: *.example.com should NOT match example.com.
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com"},
		},
		nil,
	))

	// Subdomains always match.
	for _, host := range []string{"sub.example.com", "deep.sub.example.com"} {
		dec := engine.IsHostInScope(host)
		if !dec.InScope {
			t.Errorf("subdomain %q should be in scope with default IncludeApex=false, got reason: %s", host, dec.Reason)
		}
	}

	// Apex must NOT be in scope when IncludeApex is false (default).
	dec := engine.IsHostInScope("example.com")
	if dec.InScope {
		t.Error("apex example.com should NOT be in scope when IncludeApex is false (default)")
	}

	// Different domain still out of scope.
	dec2 := engine.IsHostInScope("other.com")
	if dec2.InScope {
		t.Error("other.com should be out of scope")
	}
}

func TestWildcardApex_IncludedWhenFlagSet(t *testing.T) {
	// IncludeApex=true: *.example.com should match BOTH subdomains AND the apex.
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com", IncludeApex: true},
		},
		nil,
	))

	// Subdomains still match.
	for _, host := range []string{"sub.example.com", "deep.sub.example.com"} {
		dec := engine.IsHostInScope(host)
		if !dec.InScope {
			t.Errorf("subdomain %q should be in scope with IncludeApex=true, got reason: %s", host, dec.Reason)
		}
	}

	// Apex NOW in scope.
	dec := engine.IsHostInScope("example.com")
	if !dec.InScope {
		t.Error("apex example.com should be in scope when IncludeApex=true")
	}

	// Case-insensitive apex still works.
	dec2 := engine.IsHostInScope("EXAMPLE.COM")
	if !dec2.InScope {
		t.Error("apex EXAMPLE.COM should be in scope when IncludeApex=true (case-insensitive)")
	}

	// Different domain still out of scope.
	dec3 := engine.IsHostInScope("other.com")
	if dec3.InScope {
		t.Error("other.com should still be out of scope even with IncludeApex=true")
	}
}

func TestWildcardApex_ExcludeStillWorks(t *testing.T) {
	// When both include (with IncludeApex) and exclude rules exist,
	// exclusions must still override inclusions for the apex.
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "wildcard_host", Value: "*.example.com", IncludeApex: true},
		},
		[]config.ScopeRule{
			{Type: "exact_host", Value: "internal.example.com"},
		},
	))

	// Apex should be in scope (included via IncludeApex, not excluded).
	dec := engine.IsHostInScope("example.com")
	if !dec.InScope {
		t.Error("apex example.com should be in scope")
	}

	// Explicitly excluded should still be out of scope.
	dec2 := engine.IsHostInScope("internal.example.com")
	if dec2.InScope {
		t.Error("internal.example.com should be out of scope despite IncludeApex")
	}
}

func TestIsURLInScope_InvalidPort(t *testing.T) {
	engine := NewEngine("test", makeScopeConfig(
		[]config.ScopeRule{
			{Type: "exact_host", Value: "app.example.com"},
		},
		[]config.ScopeRule{},
	))
	allowedSchemes := []string{"https"}
	allowedPorts := []int{443}

	// Malformed port strings should be rejected, not silently parsed
	t.Run("malformed port '443abc' is denied", func(t *testing.T) {
		dec := engine.IsURLInScope("https://app.example.com:443abc/test", allowedSchemes, allowedPorts)
		if dec.InScope {
			t.Errorf("expected denied for malformed port, got in-scope: %s", dec.Reason)
		}
	})

	t.Run("out of range port '99999' is denied", func(t *testing.T) {
		dec := engine.IsURLInScope("https://app.example.com:99999/test", allowedSchemes, allowedPorts)
		if dec.InScope {
			t.Errorf("expected denied for out-of-range port, got in-scope: %s", dec.Reason)
		}
	})

	t.Run("valid port 443 is allowed", func(t *testing.T) {
		dec := engine.IsURLInScope("https://app.example.com/test", allowedSchemes, allowedPorts)
		if !dec.InScope {
			t.Errorf("expected allowed for port 443, got denied: %s", dec.Reason)
		}
	})
}
