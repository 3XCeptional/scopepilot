// Package scope implements the scope-enforcement engine. It determines whether
// a given host, URL, or IP address falls within a program's authorized scope.
// Exclusions override inclusions. The engine fails closed — any ambiguous input
// is treated as out-of-scope.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/dhiren/pentest-automation/internal/config"
	"github.com/dhiren/pentest-automation/internal/normalize"
)

// Engine validates targets against program scope rules.
type Engine struct {
	programID string
	includes  []config.ScopeRule
	excludes  []config.ScopeRule
}

// Decision represents a scope check result.
type Decision struct {
	InScope     bool   `json:"in_scope"`
	Reason      string `json:"reason"`
	MatchedRule string `json:"matched_rule,omitempty"`
}

// NewEngine creates a scope engine for a program.
func NewEngine(programID string, scopeCfg config.ScopeConfig) *Engine {
	return &Engine{
		programID: programID,
		includes:  scopeCfg.Include,
		excludes:  scopeCfg.Exclude,
	}
}

// IncludeRules returns a defensive copy of the include rules.
func (e *Engine) IncludeRules() []config.ScopeRule {
	r := make([]config.ScopeRule, len(e.includes))
	copy(r, e.includes)
	return r
}

// ExcludeRules returns a defensive copy of the exclude rules.
func (e *Engine) ExcludeRules() []config.ScopeRule {
	r := make([]config.ScopeRule, len(e.excludes))
	copy(r, e.excludes)
	return r
}

// IsHostInScope checks whether the given hostname is in scope.
// Only checks host-level exclusion types (exact_host, wildcard_host).
// Path-prefix exclusions are checked separately in IsURLInScope.
func (e *Engine) IsHostInScope(host string) Decision {
	host = normalize.Host(host)
	if host == "" {
		return Decision{InScope: false, Reason: "empty host after normalization"}
	}

	// Check host-level exclusions first — they override inclusions.
	for _, rule := range e.excludes {
		if rule.Type == "path_prefix" {
			continue // handled in IsURLInScope
		}
		if e.matchHostRule(rule, host) {
			return Decision{InScope: false, Reason: fmt.Sprintf("excluded by rule type=%s value=%s", rule.Type, rule.Value), MatchedRule: rule.Value}
		}
	}

	// Check inclusions.
	for _, rule := range e.includes {
		if e.matchHostRule(rule, host) {
			return Decision{InScope: true, Reason: fmt.Sprintf("included by rule type=%s value=%s", rule.Type, rule.Value), MatchedRule: rule.Value}
		}
	}

	return Decision{InScope: false, Reason: "host does not match any scope rule"}
}

// IsURLInScope checks if a URL is fully in scope, including scheme, host, port, and path.
func (e *Engine) IsURLInScope(rawURL string, allowedSchemes []string, allowedPorts []int) Decision {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Decision{InScope: false, Reason: fmt.Sprintf("invalid URL: %v", err)}
	}

	// Check scheme.
	schemeOk := false
	for _, s := range allowedSchemes {
		if parsed.Scheme == s {
			schemeOk = true
			break
		}
	}
	if !schemeOk {
		return Decision{InScope: false, Reason: fmt.Sprintf("scheme %q not allowed", parsed.Scheme)}
	}

	// Check host.
	hostDec := e.IsHostInScope(parsed.Hostname())
	if !hostDec.InScope {
		return hostDec
	}

	// Check port.
	port := parsed.Port()
	portInt := 0
	if port == "" {
		if parsed.Scheme == "https" {
			portInt = 443
		} else {
			portInt = 80
		}
	} else {
		n, err := fmt.Sscanf(port, "%d", &portInt)
		if n != 1 || err != nil || portInt <= 0 || portInt > 65535 {
			return Decision{InScope: false, Reason: fmt.Sprintf("invalid port %q", port)}
		}
	}
	portOk := false
	for _, p := range allowedPorts {
		if p == portInt {
			portOk = true
			break
		}
	}
	if !portOk {
		return Decision{InScope: false, Reason: fmt.Sprintf("port %d not allowed", portInt)}
	}

	// Check path exclusions.
	for _, rule := range e.excludes {
		if rule.Type == "path_prefix" && e.matchHostRule(rule, parsed.Hostname()) {
			if strings.HasPrefix(parsed.Path, rule.Value) {
				return Decision{InScope: false, Reason: fmt.Sprintf("path %q excluded by path_prefix rule %s", parsed.Path, rule.Value), MatchedRule: rule.Value}
			}
		}
	}

	return Decision{InScope: true, Reason: "URL matches scope", MatchedRule: hostDec.MatchedRule}
}

// IsIPInScope checks if an IP address is in scope and not in a blocked range.
func (e *Engine) IsIPInScope(ip net.IP) Decision {
	// Always block reserved/private ranges.
	if isBlockedIP(ip) {
		return Decision{InScope: false, Reason: fmt.Sprintf("IP %s is in a blocked range", ip.String())}
	}

	for _, rule := range e.includes {
		if rule.Type == "cidr" {
			_, cidr, err := net.ParseCIDR(rule.Value)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return Decision{InScope: true, Reason: fmt.Sprintf("IP matches CIDR %s", rule.Value), MatchedRule: rule.Value}
			}
		}
	}

	return Decision{InScope: false, Reason: "IP does not match any scope CIDR"}
}

func (e *Engine) matchHostRule(rule config.ScopeRule, host string) bool {
	switch rule.Type {
	case "exact_host":
		return strings.EqualFold(host, normalize.Host(rule.Value))
	case "wildcard_host":
		return matchWildcard(rule.Value, host, rule.IncludeApex)
	case "path_prefix":
		// For path_prefix rules, match the host portion.
		return strings.EqualFold(host, normalize.Host(rule.Host))
	default:
		return false
	}
}

// matchWildcard checks if host matches a wildcard pattern like "*.example.com".
// When includeApex is true, the pattern also matches the bare apex
// (e.g. "*.example.com" matches both "sub.example.com" and "example.com").
func matchWildcard(pattern, host string, includeApex bool) bool {
	pattern = normalize.Host(pattern)
	host = normalize.Host(host)

	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := pattern[1:] // ".example.com"
	if strings.HasSuffix(host, suffix) {
		return true
	}

	// When includeApex is set, also check if host is exactly the apex
	// (the domain without the "*." prefix).
	if includeApex {
		apex := pattern[2:] // "example.com"
		return strings.EqualFold(host, apex)
	}

	return false
}

// isBlockedIP returns true for loopback, link-local, multicast, CGNAT,
// private, reserved, documentation, and cloud-metadata addresses.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Normalize to 4-byte or 16-byte form.
	// Save original because To4() returns nil for IPv6 addresses.
	orig := ip
	ip = ip.To4()
	if ip == nil {
		ip = orig.To16()
	}

	blockedCIDRs := []string{
		// Loopback
		"127.0.0.0/8",
		"::1/128",
		// Link-local
		"169.254.0.0/16",
		"fe80::/10",
		// Unique Local Addresses (IPv6 private, RFC 4193)
		"fc00::/7",
		// Multicast
		"224.0.0.0/4",
		"ff00::/8",
		// CGNAT (RFC 6598)
		"100.64.0.0/10",
		// Private (RFC 1918)
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// Reserved / Documentation
		"0.0.0.0/8",
		"240.0.0.0/4",
		"198.18.0.0/15",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		// Cloud metadata (common)
		"169.254.169.254/32",
	}

	for _, cidr := range blockedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
