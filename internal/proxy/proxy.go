// Package proxy implements the scope enforcement HTTP gateway. It wraps
// http.Handler and validates every request against all safety layers before
// forwarding, including kill-switch, allowed schemes/ports, scope rules,
// path exclusions, DNS validation, and per-host rate limiting.
//
// The package also exposes a programmatic API (CheckURL, RunSafeCheck,
// ScopeSummary, RateLimitStatus) that the MCP server wraps as typed tools
// for LLM agents.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/config"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/normalize"
	"github.com/dhiren/pentest-automation/internal/ratelimit"
	"github.com/dhiren/pentest-automation/internal/scope"
)

// Config defines the configuration for a Proxy instance.
type Config struct {
	ListenAddr           string
	ProgramID            string
	ScopeCfg             config.ScopeConfig
	Limits               config.LimitsConfig
	AllowedSchemes       []string
	AllowedPorts         []int
	DryRun               bool
	ActiveTestingEnabled bool
	PersistentAudit      *audit.PersistentLogger // optional SQLite-backed audit
}

// Proxy is the scope enforcement HTTP gateway. It embeds all safety components
// so their methods are directly available.
type Proxy struct {
	*scope.Engine
	*ratelimit.PerHostLimiter
	*audit.Logger
	*killswitch.Switch
	Config

	// ca is the root Certificate Authority used for TLS MitM decryption.
	ca *CA

	// httpClient is used to forward allowed requests. It includes a
	// CheckRedirect that re-validates redirect targets against all safety
	// layers, and a custom DialContext that pins connections to DNS results
	// resolved at validation time (prevents DNS rebinding).
	httpClient *http.Client

	// lookupHostFn abstracts DNS resolution for testability. Defaults to
	// net.DefaultResolver.LookupHost.
	lookupHostFn func(ctx context.Context, host string) ([]string, error)

	// dialFn abstracts the outbound TCP dial used by CONNECT tunnels, for
	// testability. Defaults to net.DialTimeout.
	dialFn func(network, addr string, timeout time.Duration) (net.Conn, error)

	// resolvedIPs stores the IPs resolved for each host during safety
	// validation, so the transport's DialContext can connect directly to
	// those IPs (preventing DNS rebinding attacks).
	resolvedIPs map[string][]string
	mu          sync.RWMutex
}

const maxResolvedIPs = 10000

// storeResolvedIPs adds a host→IPs entry and evicts randomly when over cap.
func (p *Proxy) storeResolvedIPs(host string, ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.resolvedIPs) >= maxResolvedIPs {
		for k := range p.resolvedIPs {
			delete(p.resolvedIPs, k)
			break
		}
	}
	p.resolvedIPs[host] = ips
}

// SetDNSOverride replaces the DNS lookup function with a custom one.
// Used by tests to avoid real DNS lookups. Pass nil to restore default.
func (p *Proxy) SetDNSOverride(fn func(ctx context.Context, host string) ([]string, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if fn == nil {
		p.lookupHostFn = net.DefaultResolver.LookupHost
	} else {
		p.lookupHostFn = fn
	}
}

// SetDialOverride replaces the outbound TCP dial function used by CONNECT
// tunnels. Used by tests to redirect connections. Pass nil to restore default.
func (p *Proxy) SetDialOverride(fn func(network, addr string, timeout time.Duration) (net.Conn, error)) {
	if fn == nil {
		p.dialFn = net.DialTimeout
	} else {
		p.dialFn = fn
	}
}

// NewProxy creates a new Proxy from the given Config.
func NewProxy(cfg Config) *Proxy {
	auditLogger := audit.NewLogger(10000)
	if cfg.PersistentAudit != nil {
		auditLogger = cfg.PersistentAudit.Logger
	}
	p := &Proxy{
		Engine:         scope.NewEngine(cfg.ProgramID, cfg.ScopeCfg),
		PerHostLimiter: ratelimit.NewPerHostLimiter(cfg.Limits.RequestsPerSecondPerHost, cfg.Limits.RequestsPerSecondPerHost),
		Logger:         auditLogger,
		Switch:         &killswitch.Switch{},
		Config:         cfg,
		lookupHostFn:   net.DefaultResolver.LookupHost,
		resolvedIPs:    make(map[string][]string),
	}

	// Set defaults for allowed schemes and ports.
	if len(p.AllowedSchemes) == 0 {
		p.AllowedSchemes = []string{"https"}
	}
	if len(p.AllowedPorts) == 0 {
		p.AllowedPorts = []int{443}
	}

	// Create an http.Client with:
	//   - A custom DialContext that pins connections to the IPs resolved at
	//     validation time (prevents DNS rebinding).
	//   - Redirect re-validation against all safety layers.
	p.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// After the first redirect, re-validate the target URL.
			if len(via) >= 1 {
				if err := p.validateRedirectTarget(req.URL); err != nil {
					return err
				}
			}
			// Allow up to 10 redirects.
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 15 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if p.dialFn != nil {
					return p.dialFn(network, addr, 30*time.Second)
				}

				// addr is "host:port" — strip port to get the hostname.
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					// Fall back to normal DNS if addr is malformed.
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}

				// Check if we have a pinned IP for this host.
				p.mu.RLock()
				ips, ok := p.resolvedIPs[host]
				p.mu.RUnlock()

				if ok && len(ips) > 0 {
					// Connect directly to the first resolved IP (preserving
					// the original port). The Host header is set separately
					// by the http.Client so the server still sees the real
					// hostname.
					dialAddr := net.JoinHostPort(ips[0], port)
					return (&net.Dialer{}).DialContext(ctx, network, dialAddr)
				}

				// Fall back to normal system DNS resolution.
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}

	return p
}

// ---------------------------------------------------------------------------
// Helper method: writeJSON is a small utility used by all JSON responses.
// ---------------------------------------------------------------------------

func (p *Proxy) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[proxy] writeJSON encode error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Safety-layer helper methods (each independently testable)
// ---------------------------------------------------------------------------

// CheckKillSwitch returns true if the global kill switch is active, meaning
// all traffic should be halted.
func (p *Proxy) CheckKillSwitch() bool {
	return p.Switch.IsActive()
}

// ParseAndNormalizeURL extracts the target URL from the incoming request and
// normalizes it. It returns the parsed URL, the normalized string, or an
// error if the URL is invalid or missing a host, OR if the Host header
// and request-line URL disagree (prevents scope bypass via Host header spoofing).
func (p *Proxy) ParseAndNormalizeURL(r *http.Request) (*url.URL, string, error) {
	// Reconstruct the full URL from the request.
	scheme := r.URL.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	// Protect against Host header mismatch: if the request-line carries an
	// absolute URL (e.g. "GET http://internal/admin HTTP/1.1") whose host
	// differs from the Host header, an attacker could trick scope validation
	// into checking the Host header while forwarding to the request-line URL.
	if r.URL.IsAbs() && r.URL.Host != "" && r.Host != "" && r.URL.Host != r.Host {
		return nil, "", fmt.Errorf("Host header %q does not match request-line host %q", r.Host, r.URL.Host)
	}

	raw := scheme + "://" + r.Host + r.URL.RequestURI()

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Hostname() == "" {
		return nil, "", fmt.Errorf("missing host in URL")
	}
	normalized, err := normalize.URL(raw)
	if err != nil {
		return nil, "", fmt.Errorf("normalize error: %w", err)
	}
	return parsed, normalized, nil
}

// ValidateScheme returns true if the scheme is in the allowed list. When
// AllowedSchemes is empty, all schemes are allowed.
func (p *Proxy) ValidateScheme(scheme string) bool {
	if len(p.AllowedSchemes) == 0 {
		return true
	}
	for _, s := range p.AllowedSchemes {
		if scheme == s {
			return true
		}
	}
	return false
}

// ValidatePort returns the port as an integer and true if it is in the
// allowed list. If the port string is empty, it infers 80 or 443 from the
// scheme. When AllowedPorts is empty, all ports are allowed.
func (p *Proxy) ValidatePort(portStr, scheme string) (int, bool) {
	portInt := 0
	if portStr == "" {
		switch scheme {
		case "https":
			portInt = 443
		default:
			portInt = 80
		}
	} else {
		fmt.Sscanf(portStr, "%d", &portInt)
	}
	if len(p.AllowedPorts) == 0 {
		return portInt, true
	}
	for _, ap := range p.AllowedPorts {
		if ap == portInt {
			return portInt, true
		}
	}
	return portInt, false
}

// CheckHostScope checks the host against the scope engine. It returns true
// if the host is in scope (exclusions override inclusions).
func (p *Proxy) CheckHostScope(host string) (bool, string) {
	dec := p.IsHostInScope(host)
	return dec.InScope, dec.Reason
}

// CheckPathExclusion returns true if the path (on the given host) is
// excluded by a path_prefix rule.
func (p *Proxy) CheckPathExclusion(host, path string) bool {
	for _, rule := range p.ScopeCfg.Exclude {
		if rule.Type == "path_prefix" {
			// Match host portion.
			ruleHost := normalize.Host(rule.Host)
			if ruleHost == "" || strings.EqualFold(host, ruleHost) {
				if strings.HasPrefix(path, rule.Value) {
					return true
				}
			}
		}
	}
	return false
}

// LookupHost resolves the host to IP addresses using the configured lookup
// function.
func (p *Proxy) LookupHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.lookupHostFn(ctx, host)
}

// IsBlockedIP returns true if the IP is in a blocked/reserved/private range.
func (p *Proxy) IsBlockedIP(ip net.IP) bool {
	return isBlockedIP(ip)
}

// ValidateIPs checks every resolved IP against the blocked-IP list. Returns
// true if all IPs are safe (none blocked), false if any IP is blocked.
func (p *Proxy) ValidateIPs(ips []string) (bool, string) {
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if p.IsBlockedIP(ip) {
			return false, fmt.Sprintf("IP %s is in a blocked/private range", ipStr)
		}
	}
	return true, ""
}

// CheckRateLimit returns true if the host has not exceeded its per-host rate
// limit.
func (p *Proxy) CheckRateLimit(host string) bool {
	return p.Allow(host)
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

// dryRunResponse is the JSON body for DryRun mode decisions.
type dryRunResponse struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProgramID string `json:"program_id"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	DryRun    bool   `json:"dry_run"`
}

// denyResponse is the JSON body for denied requests.
type denyResponse struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProgramID string `json:"program_id"`
}

// WriteDryRunResponse writes a 200 JSON response with the decision that WOULD
// have been made, without forwarding the request.
func (p *Proxy) WriteDryRunResponse(w http.ResponseWriter, allowed bool, reason, host, urlStr string) {
	body := dryRunResponse{
		Allowed:   allowed,
		Reason:    reason,
		ProgramID: p.ProgramID,
		Host:      host,
		URL:       urlStr,
		DryRun:    true,
	}
	p.writeJSON(w, http.StatusOK, body)
}

// WriteDenyResponse writes a 403 JSON response with the denial reason.
func (p *Proxy) WriteDenyResponse(w http.ResponseWriter, reason string) {
	body := denyResponse{
		Allowed:   false,
		Reason:    reason,
		ProgramID: p.ProgramID,
	}
	p.writeJSON(w, http.StatusForbidden, body)
}

// LogDecision logs an audit entry for the given event type and data.
func (p *Proxy) LogDecision(eventType string, data map[string]interface{}) {
	p.Logger.Log("proxy", eventType, data)
}

// ---------------------------------------------------------------------------
// Request forwarding
// ---------------------------------------------------------------------------

// ForwardRequest forwards the incoming request to the target server via the
// configured http.Client. It handles response body streaming and header
// copying. After forwarding, it applies response redaction.
func (p *Proxy) ForwardRequest(w http.ResponseWriter, r *http.Request) {
	// Resolve DNS and store the resolved IPs so the transport's DialContext
	// connects directly to these IPs (preventing DNS rebinding).
	targetHost := normalize.Host(r.URL.Hostname())
	if targetHost != "" && net.ParseIP(targetHost) == nil {
		if ips, dnsErr := p.LookupHost(targetHost); dnsErr == nil {
			if _, reason := p.ValidateIPs(ips); reason == "" {
				p.storeResolvedIPs(targetHost, ips)
			}
		}
	}

	// Build the outgoing request.
	targetURL := r.URL.String()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		p.WriteDenyResponse(w, fmt.Sprintf("failed to create outgoing request: %v", err))
		return
	}

	// Copy headers from the original request.
	for key, values := range r.Header {
		for _, val := range values {
			outReq.Header.Add(key, val)
		}
	}

	// Send the request.
	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		// If this was a redirect blocked by our CheckRedirect, the error
		// contains the message we returned.
		p.writeJSON(w, http.StatusForbidden, denyResponse{
			Allowed:   false,
			Reason:    fmt.Sprintf("forward error (possibly blocked redirect): %v", err),
			ProgramID: p.ProgramID,
		})
		return
	}
	defer resp.Body.Close()

	// Copy response headers (then redact sensitive ones).
	for key, values := range resp.Header {
		for _, val := range values {
			w.Header().Add(key, val)
		}
	}

	// Apply response redaction: strip Authorization, Cookie, Set-Cookie.
	RedactResponseHeaders(w.Header())

	// Copy status code and body.
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write([]byte{}); err != nil {
		log.Printf("[proxy] error writing header: %v", err)
	}

	// Read and write body in chunks.
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				log.Printf("[proxy] error writing body: %v", werr)
				break
			}
		}
		if err != nil {
			break
		}
	}
}

// validateRedirectTarget checks a redirect target URL against all safety
// layers. It returns nil if the redirect is safe, or an error if it should
// be blocked.
func (p *Proxy) validateRedirectTarget(targetURL *url.URL) error {
	host := normalize.Host(targetURL.Hostname())
	if host == "" {
		return fmt.Errorf("redirect target missing host")
	}

	// Check scheme.
	if !p.ValidateScheme(targetURL.Scheme) {
		return fmt.Errorf("redirect target scheme %q not allowed", targetURL.Scheme)
	}

	// Check port.
	if _, ok := p.ValidatePort(targetURL.Port(), targetURL.Scheme); !ok {
		return fmt.Errorf("redirect target port %q not allowed", targetURL.Port())
	}

	// Check host scope.
	inScope, reason := p.CheckHostScope(host)
	if !inScope {
		return fmt.Errorf("redirect target out of scope: %s", reason)
	}

	// Check path exclusion.
	if p.CheckPathExclusion(host, targetURL.Path) {
		return fmt.Errorf("redirect target path %q excluded", targetURL.Path)
	}

	// Resolve and validate IPs.
	ips, err := p.LookupHost(host)
	if err != nil {
		return fmt.Errorf("redirect target DNS resolution failed: %w", err)
	}
	if ok, ipReason := p.ValidateIPs(ips); !ok {
		return fmt.Errorf("redirect target blocked: %s", ipReason)
	}

	// Store resolved IPs so the transport's DialContext can connect directly
	// to these IPs (preventing DNS rebinding on redirects).
	p.storeResolvedIPs(host, ips)

	return nil
}

// RedactResponseHeaders removes sensitive headers (Authorization, Cookie,
// Set-Cookie) from the response header map.
func RedactResponseHeaders(header http.Header) {
	header.Del("Authorization")
	header.Del("Cookie")
	header.Del("Set-Cookie")
}

// ---------------------------------------------------------------------------
// ServeHTTP — the core request handler
// ---------------------------------------------------------------------------

// ServeHTTP implements http.Handler. It runs every request through all safety
// layers before deciding to deny, dry-run, or forward.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health check endpoint — bypasses all safety layers.
	if r.URL.Path == "/health" {
		p.writeHealth(w)
		return
	}

	// CONNECT requests open a raw TCP tunnel (used for HTTPS via an HTTP
	// proxy). They run the full safety chain then hijack the connection and
	// relay bytes, rather than forwarding through the http.Client.
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// 1. Global kill switch.
	if p.CheckKillSwitch() {
		reason := "global kill switch is active"
		p.LogDecision("block", map[string]interface{}{
			"reason":     reason,
			"host":       r.Host,
			"method":     r.Method,
			"url":        r.URL.String(),
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] BLOCK %s %s - %s", r.Method, r.Host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 2. Parse and normalize URL.
	parsedURL, normalizedURL, err := p.ParseAndNormalizeURL(r)
	if err != nil {
		reason := fmt.Sprintf("invalid request URL: %v", err)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       r.Host,
			"method":     r.Method,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, r.Host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	host := normalize.Host(parsedURL.Hostname())
	requestURI := normalizedURL

	// 3. Active testing gate — if active testing is not enabled, deny all
	// forwarding requests.
	if !p.ActiveTestingEnabled {
		reason := "active testing disabled for this program"
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 4. Validate scheme.
	if !p.ValidateScheme(parsedURL.Scheme) {
		reason := fmt.Sprintf("scheme %q not allowed", parsedURL.Scheme)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"scheme":     parsedURL.Scheme,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 5. Validate port.
	portStr := parsedURL.Port()
	_, portOK := p.ValidatePort(portStr, parsedURL.Scheme)
	if !portOK {
		reason := fmt.Sprintf("port %q not allowed", portStr)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"port":       portStr,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 6. Check host against scope (exclusions override inclusions).
	inScope, scopeReason := p.CheckHostScope(host)
	if !inScope {
		reason := fmt.Sprintf("host out of scope: %s", scopeReason)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 7. Check path exclusions.
	if p.CheckPathExclusion(host, parsedURL.Path) {
		reason := fmt.Sprintf("path %q excluded by path_prefix rule", parsedURL.Path)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"path":       parsedURL.Path,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 8. Resolve DNS and validate IPs.
	ips, dnsErr := p.LookupHost(host)
	if dnsErr != nil {
		reason := fmt.Sprintf("DNS resolution failed for %s: %v", host, dnsErr)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	if ok, ipReason := p.ValidateIPs(ips); !ok {
		reason := fmt.Sprintf("host %s resolves to blocked IP: %s", host, ipReason)
		p.LogDecision("block", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"ips":        ips,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] BLOCK %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// Store resolved IPs so the transport's DialContext can connect directly
	// to these IPs (preventing DNS rebinding attacks).
	p.storeResolvedIPs(host, ips)

	// 9. DryRun mode — check BEFORE rate limiting since no request is forwarded.
	if p.DryRun {
		p.LogDecision("dry_run", map[string]interface{}{
			"decision":   "allow",
			"host":       host,
			"url":        requestURI,
			"method":     r.Method,
			"program_id": p.ProgramID,
		})
		p.WriteDryRunResponse(w, true, "request would be allowed", host, requestURI)
		return
	}

	// 10. Check per-host rate limit (skipped in dry-run mode).
	if !p.CheckRateLimit(host) {
		reason := fmt.Sprintf("rate limit exceeded for host %s", host)
		p.LogDecision("deny", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"url":        requestURI,
			"program_id": p.ProgramID,
		})
		log.Printf("[proxy] DENY %s %s - %s", r.Method, host, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 11. Forward the request.
	p.LogDecision("allow", map[string]interface{}{
		"host":       host,
		"url":        requestURI,
		"method":     r.Method,
		"program_id": p.ProgramID,
		"ips":        ips,
	})
	log.Printf("[proxy] ALLOW %s %s%s", r.Method, host, parsedURL.Path)
	// Rewrite request URL to the validated target so ForwardRequest and any
	// downstream code send traffic to the same host that passed scope validation.
	// Without this, an attacker could send an absolute request-line URL
	// (e.g. "GET http://internal/admin HTTP/1.1") with a different Host header
	// to bypass scope validation — the validator checks r.Host, but
	// ForwardRequest uses r.URL.String().
	r.URL = parsedURL
	p.ForwardRequest(w, r)
}

// writeHealth writes a standard health check JSON response.
func (p *Proxy) writeHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","program_id":"` + p.ProgramID + `"}`))
}

// getCA returns the CA instance, initializing it lazily if necessary.
func (p *Proxy) getCA() (*CA, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ca == nil {
		ca, err := NewCA()
		if err != nil {
			return nil, err
		}
		p.ca = ca
	}
	return p.ca, nil
}

// handleConnect services a CONNECT request by hijacking the connection, performing
// a TLS MitM handshake using a dynamically-issued certificate, and decrypting/filtering
// HTTPS requests in a loop.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}

	logDeny := func(reason string, extra map[string]interface{}) {
		data := map[string]interface{}{
			"reason":     reason,
			"authority":  authority,
			"method":     r.Method,
			"program_id": p.ProgramID,
		}
		for k, v := range extra {
			data[k] = v
		}
		p.LogDecision("deny", data)
	}

	// 1. Global kill switch.
	if p.CheckKillSwitch() {
		reason := "global kill switch is active"
		p.LogDecision("block", map[string]interface{}{
			"reason":     reason,
			"authority":  authority,
			"method":     r.Method,
			"program_id": p.ProgramID,
		})
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 2. Active testing gate.
	if !p.ActiveTestingEnabled {
		reason := "active testing disabled for this program"
		logDeny(reason, nil)
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 3. Parse host:port.
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		reason := fmt.Sprintf("invalid CONNECT authority %q: %v", authority, err)
		logDeny(reason, nil)
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	host = normalize.Host(host)

	// 4. Validate port.
	if !p.ValidateScheme("https") {
		reason := "scheme \"https\" not allowed"
		logDeny(reason, nil)
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	port, portOK := p.ValidatePort(portStr, "https")
	if !portOK {
		reason := fmt.Sprintf("port %q not allowed", portStr)
		logDeny(reason, map[string]interface{}{"host": host, "port": portStr})
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 5. Host scope check.
	inScope, scopeReason := p.CheckHostScope(host)
	if !inScope {
		reason := fmt.Sprintf("host out of scope: %s", scopeReason)
		logDeny(reason, map[string]interface{}{"host": host})
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// 6. DNS resolution + IP blocklist.
	ips, dnsErr := p.LookupHost(host)
	if dnsErr != nil {
		reason := fmt.Sprintf("DNS resolution failed for %s: %v", host, dnsErr)
		logDeny(reason, map[string]interface{}{"host": host})
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	if ok, ipReason := p.ValidateIPs(ips); !ok {
		reason := fmt.Sprintf("host %s resolves to blocked IP: %s", host, ipReason)
		p.LogDecision("block", map[string]interface{}{
			"reason":     reason,
			"host":       host,
			"ips":        ips,
			"program_id": p.ProgramID,
		})
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}

	// Store resolved IPs for the http.Client's DialContext.
	p.storeResolvedIPs(host, ips)

	// 7. Hijack connection and establish a simple TCP tunnel.
	hj, ok := w.(http.Hijacker)
	if !ok {
		reason := "CONNECT not supported: response writer is not a hijacker"
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		reason := fmt.Sprintf("hijack failed: %v", err)
		log.Printf("[connect] DENY %s - %s", authority, reason)
		p.WriteDenyResponse(w, reason)
		return
	}
	defer clientConn.Close()

	// Write 200 Connection established.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		log.Printf("[proxy] CONNECT write 200 failed: %v", err)
		return
	}

	// Dial target using the resolved IPs (with DNS rebind protection).
	dial := p.dialFn
	if dial == nil {
		dial = net.DialTimeout
	}
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	targetConn, err := dial("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[connect] dial failed for %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[connect] TUNNEL %s (%s -> %s)", authority, clientConn.RemoteAddr(), targetAddr)

	// Bidirectional relay.
	var wg sync.WaitGroup
	wg.Add(2)
	var upBytes, downBytes int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, clientConn)
		upBytes = n
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, targetConn)
		downBytes = n
	}()

	wg.Wait()
	log.Printf("[connect] CLOSE %s (up: %d down: %d bytes)", authority, upBytes, downBytes)
}

// ForwardDecryptedRequest forwards a decrypted HTTP request and writes the response back to the client connection.
func (p *Proxy) ForwardDecryptedRequest(conn net.Conn, r *http.Request) error {
	// Build the outgoing request.
	targetURL := r.URL.String()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"allowed":false,"reason":"failed to create outgoing request: %v"}`, err))),
		}
		resp.Header.Set("Content-Type", "application/json")
		return resp.Write(conn)
	}

	// Copy headers.
	for key, values := range r.Header {
		for _, val := range values {
			outReq.Header.Add(key, val)
		}
	}

	// Send the request.
	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		respBlock := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"allowed":false,"reason":"forward error: %v"}`, err))),
		}
		respBlock.Header.Set("Content-Type", "application/json")
		return respBlock.Write(conn)
	}
	defer resp.Body.Close()

	// Redact sensitive headers from response.
	RedactResponseHeaders(resp.Header)

	// Write response to the connection.
	return resp.Write(conn)
}

func writeDenyResp(conn net.Conn, reason string) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"allowed":false,"reason":"%s"}`, reason))),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Write(conn)
}

func writeDryRunResp(conn net.Conn, host, url string) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"allowed":true,"dry_run":true,"reason":"request would be allowed","host":"%s","url":"%s"}`, host, url))),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Write(conn)
}

// ---------------------------------------------------------------------------
// Package-level blocked-IP check (mirrors scope.isBlockedIP)
// ---------------------------------------------------------------------------

// isBlockedIP returns true for loopback, link-local, multicast, CGNAT,
// private, reserved, documentation, and cloud-metadata addresses.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	orig := ip
	ip = ip.To4()
	if ip == nil {
		ip = orig.To16()
	}

	blockedCIDRs := []string{
		"127.0.0.0/8",
		"::1/128",
		"169.254.0.0/16",
		"fe80::/10",
		"224.0.0.0/4",
		"ff00::/8",
		"100.64.0.0/10",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"0.0.0.0/8",
		"240.0.0.0/4",
		"198.18.0.0/15",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
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

// ---------------------------------------------------------------------------
// Programmatic API: CheckURL, RunSafeCheck, ScopeSummary, RateLimitStatus
// These are used by the MCP server to expose proxy controls as typed tools.
// ---------------------------------------------------------------------------

// CheckResult represents the result of validating a single URL against all
// safety layers (no actual HTTP request is made).
type CheckResult struct {
	URL          string          `json:"url"`
	Allowed      bool            `json:"allowed"`
	ScopeResult  *scope.Decision `json:"scope_result,omitempty"`
	BlockedIP    bool            `json:"blocked_ip,omitempty"`
	DeniedScheme bool            `json:"denied_scheme,omitempty"`
	RateLimited  bool            `json:"rate_limited,omitempty"`
	Reason       string          `json:"reason"`
}

// ScopeSummary provides a snapshot of the current program scope configuration.
type ScopeSummary struct {
	ProgramID      string   `json:"program_id"`
	IncludeCount   int      `json:"include_count"`
	ExcludeCount   int      `json:"exclude_count"`
	AllowedSchemes []string `json:"allowed_schemes,omitempty"`
	AllowedPorts   []int    `json:"allowed_ports,omitempty"`
}

// HostState represents the rate-limit state for a single host.
type HostState struct {
	Host          string  `json:"host"`
	Tokens        float64 `json:"tokens"`
	Capacity      int     `json:"capacity"`
	RatePerSecond float64 `json:"rate_per_second"`
}

// RateLimitState provides a snapshot of the current rate limiter.
type RateLimitState struct {
	Hosts []HostState `json:"hosts"`
}

// CheckURL validates a single URL against all safety layers and returns a
// structured decision. No actual HTTP request is made. This is the primary
// entry point for the MCP server's check_url and run_safe_check tools.
func (p *Proxy) CheckURL(rawURL string) (*CheckResult, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return &CheckResult{
			URL:     rawURL,
			Allowed: false,
			Reason:  fmt.Sprintf("invalid URL: %v", err),
		}, nil
	}

	if parsedURL.Hostname() == "" {
		return &CheckResult{
			URL:     rawURL,
			Allowed: false,
			Reason:  "missing host in URL",
		}, nil
	}

	host := normalize.Host(parsedURL.Hostname())

	// 1. Kill switch check.
	if p.CheckKillSwitch() {
		return &CheckResult{
			URL:     rawURL,
			Allowed: false,
			Reason:  "global kill switch is active",
		}, nil
	}

	// 2. Active testing gate.
	if !p.ActiveTestingEnabled {
		return &CheckResult{
			URL:     rawURL,
			Allowed: false,
			Reason:  "active testing disabled for this program",
		}, nil
	}

	// 3. Scheme validation.
	if !p.ValidateScheme(parsedURL.Scheme) {
		return &CheckResult{
			URL:          rawURL,
			Allowed:      false,
			DeniedScheme: true,
			Reason:       fmt.Sprintf("scheme %q not allowed", parsedURL.Scheme),
		}, nil
	}

	// 4. Port validation.
	if _, portOK := p.ValidatePort(parsedURL.Port(), parsedURL.Scheme); !portOK {
		return &CheckResult{
			URL:     rawURL,
			Allowed: false,
			Reason:  fmt.Sprintf("port %q not allowed", parsedURL.Port()),
		}, nil
	}

	// 5. Check if host is a blocked IP directly.
	if ip := net.ParseIP(host); ip != nil {
		if p.IsBlockedIP(ip) {
			return &CheckResult{
				URL:       rawURL,
				Allowed:   false,
				BlockedIP: true,
				Reason:    fmt.Sprintf("IP %s is in a blocked/private range", host),
			}, nil
		}
	}

	// 6. DNS resolution + IP validation (for hostnames, not bare IPs).
	if net.ParseIP(host) == nil {
		ips, dnsErr := p.LookupHost(host)
		if dnsErr != nil {
			return &CheckResult{
				URL:     rawURL,
				Allowed: false,
				Reason:  fmt.Sprintf("DNS resolution failed for %s: %v", host, dnsErr),
			}, nil
		}
		if ok, ipReason := p.ValidateIPs(ips); !ok {
			return &CheckResult{
				URL:       rawURL,
				Allowed:   false,
				BlockedIP: true,
				Reason:    fmt.Sprintf("host %s resolves to blocked IP: %s", host, ipReason),
			}, nil
		}
	}

	// 7. Host scope check.
	scopeDec := p.IsURLInScope(rawURL, p.AllowedSchemes, p.AllowedPorts)
	if !scopeDec.InScope {
		return &CheckResult{
			URL:         rawURL,
			Allowed:     false,
			ScopeResult: &scopeDec,
			Reason:      scopeDec.Reason,
		}, nil
	}

	// 8. Path exclusion check.
	if p.CheckPathExclusion(host, parsedURL.Path) {
		return &CheckResult{
			URL:         rawURL,
			Allowed:     false,
			ScopeResult: &scopeDec,
			Reason:      fmt.Sprintf("path %q excluded by path_prefix rule", parsedURL.Path),
		}, nil
	}

	// 9. (Rate limit check intentionally skipped — CheckURL is a pure validation
	// API that does not forward requests. Rate limiting only applies in
	// ServeHTTP when requests are actually forwarded.)

	// 10. All checks passed.
	return &CheckResult{
		URL:         rawURL,
		Allowed:     true,
		ScopeResult: &scopeDec,
		Reason:      "URL passed all safety checks",
	}, nil
}

// RunSafeCheck validates a batch of URLs through all safety layers without
// making any actual HTTP requests. Each URL is independently checked.
// Results are returned in the same order as the input URLs.
func (p *Proxy) RunSafeCheck(urls []string) []*CheckResult {
	results := make([]*CheckResult, 0, len(urls))
	for _, u := range urls {
		result, err := p.CheckURL(u)
		if err != nil {
			results = append(results, &CheckResult{
				URL:     u,
				Allowed: false,
				Reason:  err.Error(),
			})
		} else {
			results = append(results, result)
		}
	}
	return results
}

// ScopeSummary returns a summary of the current scope configuration.
func (p *Proxy) ScopeSummary() ScopeSummary {
	return ScopeSummary{
		ProgramID:      p.ProgramID,
		IncludeCount:   len(p.ScopeCfg.Include),
		ExcludeCount:   len(p.ScopeCfg.Exclude),
		AllowedSchemes: p.AllowedSchemes,
		AllowedPorts:   p.AllowedPorts,
	}
}

// RateLimitStatus returns a snapshot of the current rate limiter state.
// Note: the underlying PerHostLimiter does not expose its internal bucket
// map, so this returns an empty host list. Extend PerHostLimiter if full
// introspection is needed.
func (p *Proxy) RateLimitStatus() *RateLimitState {
	return &RateLimitState{
		Hosts: []HostState{},
	}
}
