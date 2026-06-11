package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/db"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/proxy"
)

// ListTools returns the definitions of all available MCP tools.
// isKnownTool reports whether name matches a tool advertised by ListTools.
// Lets the JSON-RPC layer treat a bare tool name as a callable method.
func (s *Server) isKnownTool(name string) bool {
	for _, t := range s.ListTools() {
		if t.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) ListTools() []ToolDef {
	tools := []ToolDef{
		{
			Name:        "get_scope_status",
			Description: "Returns a summary of the current program scope, including include/exclude rule counts and program ID.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program_id":      map[string]interface{}{"type": "string"},
					"include_count":   map[string]interface{}{"type": "integer"},
					"exclude_count":   map[string]interface{}{"type": "integer"},
					"allowed_schemes": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					"allowed_ports":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}},
				},
			},
		},
		{
			Name:        "check_url",
			Description: "Validates a single URL against all safety layers (scheme, blocked IPs, scope rules, rate limits) and returns a structured decision. No actual HTTP request is made.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The URL to validate against safety policies.",
					},
				},
				"required":             []string{"url"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url":           map[string]interface{}{"type": "string"},
					"allowed":       map[string]interface{}{"type": "boolean"},
					"scope_result":  map[string]interface{}{"type": "object"},
					"blocked_ip":    map[string]interface{}{"type": "boolean"},
					"denied_scheme": map[string]interface{}{"type": "boolean"},
					"rate_limited":  map[string]interface{}{"type": "boolean"},
					"reason":        map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "get_audit_log",
			Description: "Returns recent audit log entries. Optionally filter by event type.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"event_type": map[string]interface{}{
						"type":        "string",
						"description": "Optional event type filter (e.g., 'tool_invocation', 'kill_switch')",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of entries to return (default: 50)",
						"minimum":     float64(1),
						"maximum":     float64(1000),
					},
				},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type":  "array",
				"items": map[string]interface{}{"type": "object"},
			},
		},
		{
			Name:        "get_recent_decisions",
			Description: "Returns the 50 most recent audit decisions (newest first).",
			InputSchema: map[string]interface{}{
				"type": "object", "properties": map[string]interface{}{}, "required": []string{}, "additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object"}},
		},
		{
			Name:        "get_ratelimit_status",
			Description: "Returns the current rate limiter state per host.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hosts": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
						},
					},
				},
			},
		},
		{
			Name:        "activate_kill_switch",
			Description: "Activates the kill switch to immediately halt all testing activity. Requires a reason explaining why the switch was triggered.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "The reason for activating the kill switch.",
					},
				},
				"required":             []string{"reason"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"active":       map[string]interface{}{"type": "boolean"},
					"activated_at": map[string]interface{}{"type": "string"},
					"activated_by": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "deactivate_kill_switch",
			Description: "Deactivates the kill switch, allowing testing activity to resume. Requires a secret deactivation token.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token": map[string]interface{}{
						"type":        "string",
						"description": "The secret deactivation token defined by SCOPEPILOT_DEACTIVATION_TOKEN.",
					},
				},
				"required":             []string{"token"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"active":       map[string]interface{}{"type": "boolean"},
					"activated_at": map[string]interface{}{"type": "string"},
					"activated_by": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "is_kill_switch_active",
			Description: "Returns whether the kill switch is currently activated.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"active": map[string]interface{}{"type": "boolean"},
				},
			},
		},
		{
			Name:        "run_safe_check",
			Description: "Takes a list of URLs and runs each through the proxy in dry-run mode. Returns structured results showing which URLs are safe to scan and which are blocked. This is the primary tool that BBOT/Nuclei should call through.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"urls": map[string]interface{}{
						"type":        "array",
						"description": "List of URLs to validate against safety policies.",
						"items":       map[string]interface{}{"type": "string"},
					},
				},
				"required":             []string{"urls"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"results": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"url":           map[string]interface{}{"type": "string"},
								"allowed":       map[string]interface{}{"type": "boolean"},
								"scope_result":  map[string]interface{}{"type": "object"},
								"blocked_ip":    map[string]interface{}{"type": "boolean"},
								"denied_scheme": map[string]interface{}{"type": "boolean"},
								"rate_limited":  map[string]interface{}{"type": "boolean"},
								"reason":        map[string]interface{}{"type": "string"},
							},
						},
					},
				},
			},
		},
		{
			Name:        "validate_hosts",
			Description: "Pure rule-based scope check for hostnames. Checks each host against the program's scope rules (exact_host, wildcard_host, CIDR) with NO DNS resolution or IP blocklist checks. Useful for post-recon triage when you already know the IPs are safe.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"hosts": map[string]interface{}{
						"type":        "array",
						"description": "List of hostnames to check against scope rules.",
						"items":       map[string]interface{}{"type": "string"},
						"minItems":    float64(1),
						"maxItems":    float64(100),
					},
				},
				"required":             []string{"hosts"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"host":     map[string]interface{}{"type": "string"},
						"in_scope": map[string]interface{}{"type": "boolean"},
						"reason":   map[string]interface{}{"type": "string"},
					},
				},
			},
		},
		{
			Name:        "health",
			Description: "Returns the current health status of the proxy, MCP server, program scope, and kill switch. Useful for monitoring and diagnostics.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"proxy": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"status": map[string]interface{}{"type": "string"},
							"listen": map[string]interface{}{"type": "string"},
							"uptime": map[string]interface{}{"type": "string"},
						},
					},
					"mcp": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"status": map[string]interface{}{"type": "string"},
						},
					},
					"program_id":  map[string]interface{}{"type": "string"},
					"kill_switch": map[string]interface{}{"type": "boolean"},
				},
			},
		},
		{
			Name:        "scope_shape",
			Description: "Analyzes the program's scope rules and returns a shape description: whether wildcards or CIDRs are present, rule counts, and a hunting strategy recommendation.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{},
				"required":             []string{},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"has_wildcards":    map[string]interface{}{"type": "boolean"},
					"has_cidr":         map[string]interface{}{"type": "boolean"},
					"exact_host_count": map[string]interface{}{"type": "number"},
					"wildcard_count":   map[string]interface{}{"type": "number"},
					"recommendation":   map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "recall_engagement",
			Description: "Returns prior assets, findings, and tested endpoints for a program. Use this at the start of a hunt session so the agent resumes from where it left off.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{
						"type":        "string",
						"description": "The program ID to recall engagement data for.",
					},
				},
				"required":             []string{"program"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{"type": "string"},
					"assets": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"host":       map[string]interface{}{"type": "string"},
								"source":     map[string]interface{}{"type": "string"},
								"first_seen": map[string]interface{}{"type": "string"},
								"last_seen":  map[string]interface{}{"type": "string"},
								"in_scope":   map[string]interface{}{"type": "boolean"},
							},
						},
					},
					"findings": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"id":       map[string]interface{}{"type": "string"},
								"host":     map[string]interface{}{"type": "string"},
								"title":    map[string]interface{}{"type": "string"},
								"severity": map[string]interface{}{"type": "string"},
								"status":   map[string]interface{}{"type": "string"},
							},
						},
					},
					"tested_endpoints": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"host":     map[string]interface{}{"type": "string"},
								"endpoint": map[string]interface{}{"type": "string"},
								"check":    map[string]interface{}{"type": "string"},
								"result":   map[string]interface{}{"type": "string"},
							},
						},
					},
				},
			},
		},
		{
			Name:        "record_assets",
			Description: "Records a batch of discovered hostnames for a program. Used by recon tools to persist subdomain/enumeration results so the agent can track coverage and avoid re-scanning.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{
						"type":        "string",
						"description": "The program ID these assets belong to.",
					},
					"hosts": map[string]interface{}{
						"type":        "array",
						"description": "List of hostnames discovered.",
						"items":       map[string]interface{}{"type": "string"},
						"minItems":    float64(1),
						"maxItems":    float64(1000),
					},
					"source": map[string]interface{}{
						"type":        "string",
						"description": "Source of the discovery (e.g. bbot, nuclei, manual). Optional.",
					},
				},
				"required":             []string{"program", "hosts"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program":  map[string]interface{}{"type": "string"},
					"recorded": map[string]interface{}{"type": "integer"},
				},
			},
		},
		{
			Name:        "record_finding",
			Description: "Records a security finding for a program. Findings are persisted and returned by recall_engagement for later analysis and reporting.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{
						"type":        "string",
						"description": "The program ID this finding belongs to.",
					},
					"host": map[string]interface{}{
						"type":        "string",
						"description": "The affected hostname.",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Finding title (e.g. 'Open S3 Bucket', 'XSS in login').",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"description": "Severity level: critical, high, medium, low, info.",
					},
					"poc_ref": map[string]interface{}{
						"type":        "string",
						"description": "Optional reference or evidence (URL, curl command, screenshot path).",
					},
				},
				"required":             []string{"program", "host", "title", "severity"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{"type": "string"},
					"status":     map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "mark_tested",
			Description: "Records that a specific endpoint was tested with a particular check and the result. Use this after each nuclei/bbot check so the agent can avoid re-testing and track coverage.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{
						"type":        "string",
						"description": "The program ID.",
					},
					"host": map[string]interface{}{
						"type":        "string",
						"description": "The hostname that was tested.",
					},
					"endpoint": map[string]interface{}{
						"type":        "string",
						"description": "The full URL or path that was tested (e.g. https://host.com/admin or /api/users).",
					},
					"check": map[string]interface{}{
						"type":        "string",
						"description": "What check was run (e.g. nuclei template ID like 'tech-detect', or 'scope_check').",
					},
					"result": map[string]interface{}{
						"type":        "string",
						"description": "Outcome: not_vulnerable, vulnerable, error, timeout, skipped.",
					},
				},
				"required":             []string{"program", "host", "endpoint", "check", "result"},
				"additionalProperties": false,
			},
			OutputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"status": map[string]interface{}{"type": "string"},
				},
			},
		},
	}

	s.mu.RLock()
	specialistsRegistered := len(s.specialists) > 0
	s.mu.RUnlock()
	if specialistsRegistered {
		tools = append(tools, specialistToolDefinitions()...)
	}

	return tools
}

func specialistToolDefinitions() []ToolDef {
	targets := map[string]interface{}{
		"type":        "array",
		"description": "Authorized hostnames to assess.",
		"items":       map[string]interface{}{"type": "string"},
		"minItems":    float64(1),
		"maxItems":    float64(100),
	}
	result := map[string]interface{}{"type": "object"}
	return []ToolDef{
		{
			Name:        "run_recon_specialist",
			Description: "Runs bounded passive BBOT reconnaissance after scope and kill-switch checks.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{"targets": targets},
				"required":             []string{"targets"},
				"additionalProperties": false,
			},
			OutputSchema: result,
		},
		{
			Name:        "run_vuln_specialist",
			Description: "Runs bounded Nuclei vulnerability checks after scope and kill-switch checks.",
			InputSchema: map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{"targets": targets},
				"required":             []string{"targets"},
				"additionalProperties": false,
			},
			OutputSchema: result,
		},
		{
			Name:        "run_gate_specialist",
			Description: "Runs verified-only Gate checks after scope, kill-switch, bearer-auth, and separate operator-approval checks.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"targets": targets,
					"approval_token": map[string]interface{}{
						"type":        "string",
						"description": "Separate operator approval token configured on the server.",
					},
				},
				"required":             []string{"targets", "approval_token"},
				"additionalProperties": false,
			},
			OutputSchema: result,
		},
	}
}

// validateParams checks that params contains all required fields and no
// unknown fields, according to the tool's input schema.
func validateParams(tool ToolDef, params map[string]interface{}) error {
	schema := tool.InputSchema
	if params == nil {
		params = map[string]interface{}{}
	}

	// Check required fields.
	reqRaw, hasRequired := schema["required"]
	if hasRequired {
		switch req := reqRaw.(type) {
		case []interface{}:
			for _, r := range req {
				field, ok := r.(string)
				if !ok {
					continue
				}
				if _, exists := params[field]; !exists {
					return fmt.Errorf("missing required parameter %q", field)
				}
			}
		case []string:
			for _, field := range req {
				if _, exists := params[field]; !exists {
					return fmt.Errorf("missing required parameter %q", field)
				}
			}
		}
	}

	// Check for unknown fields (if additionalProperties is false).
	propsRaw, hasProps := schema["properties"]
	additionalProps := true
	if ap, ok := schema["additionalProperties"]; ok {
		if b, ok := ap.(bool); ok && !b {
			additionalProps = false
		}
	}

	if !additionalProps && hasProps {
		props, ok := propsRaw.(map[string]interface{})
		if ok {
			for k := range params {
				if _, known := props[k]; !known {
					return fmt.Errorf("unknown parameter %q", k)
				}
			}
		}
	}

	return nil
}

// CallTool dispatches a tool call by name with the given parameters.
// It validates parameters against the tool's schema, invokes the underlying
// implementation, logs the invocation to the audit log, and returns the
// structured result.
func (s *Server) callTool(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	tools := s.ListTools()

	var toolDef *ToolDef
	for _, t := range tools {
		if t.Name == name {
			toolDef = &t
			break
		}
	}
	if toolDef == nil {
		return nil, fmt.Errorf("unknown tool: %q", name)
	}

	if err := validateParams(*toolDef, params); err != nil {
		return nil, fmt.Errorf("invalid parameters for %q: %w", name, err)
	}

	var result interface{}
	var err error

	switch name {
	case "get_scope_status":
		result = s.handleGetScopeStatus()

	case "check_url":
		result, err = s.handleCheckURL(params)

	case "get_audit_log":
		result = s.handleGetAuditLog(params)

	case "get_recent_decisions":
		result = s.store.RecentEntries(50)

	case "get_ratelimit_status":
		result = s.handleGetRateLimitStatus()

	case "activate_kill_switch":
		result = s.handleActivateKillSwitch(params)

	case "deactivate_kill_switch":
		result, err = s.handleDeactivateKillSwitch(params)

	case "is_kill_switch_active":
		result = s.handleIsKillSwitchActive()

	case "run_safe_check":
		result, err = s.handleRunSafeCheck(params)

	case "run_recon_specialist", "run_vuln_specialist", "run_gate_specialist":
		result, err = s.handleRunSpecialist(ctx, name, params)

	case "validate_hosts":
		result, err = s.handleValidateHosts(params)

	case "health":
		result = s.handleHealth()

	case "scope_shape":
		result = s.handleScopeShape()

	case "recall_engagement":
		result, err = s.handleRecallEngagement(params)

	case "record_assets":
		result, err = s.handleRecordAssets(params)

	case "record_finding":
		result, err = s.handleRecordFinding(params)

	case "mark_tested":
		result, err = s.handleMarkTested(params)

	default:
		return nil, fmt.Errorf("unknown tool: %q", name)
	}

	// Log the invocation (after execution so we know the result).
	s.logToolInvocation(name, params, result, err)

	return result, err
}

// --- Tool handlers ---

func (s *Server) handleGetScopeStatus() map[string]interface{} {
	summary := s.prx.ScopeSummary()

	return map[string]interface{}{
		"program_id":      summary.ProgramID,
		"include_count":   summary.IncludeCount,
		"exclude_count":   summary.ExcludeCount,
		"allowed_schemes": summary.AllowedSchemes,
		"allowed_ports":   summary.AllowedPorts,
	}
}

func (s *Server) handleCheckURL(params map[string]interface{}) (*proxy.CheckResult, error) {
	rawURL, _ := params["url"].(string)
	if rawURL == "" {
		return nil, fmt.Errorf("parameter 'url' must be a non-empty string")
	}
	return s.prx.CheckURL(rawURL)
}

func (s *Server) handleGetAuditLog(params map[string]interface{}) []*audit.Entry {
	eventType, _ := params["event_type"].(string)

	limit := 50
	if l, ok := params["limit"]; ok {
		if li, ok := l.(float64); ok {
			limit = int(li)
		}
	}

	if eventType != "" {
		return s.store.SearchEntries(eventType, "")
	}
	return s.store.RecentEntries(limit)
}

func (s *Server) handleGetRateLimitStatus() *proxy.RateLimitState {
	return s.prx.RateLimitStatus()
}

func (s *Server) handleActivateKillSwitch(params map[string]interface{}) killswitch.KillSwitchStatus {
	reason, _ := params["reason"].(string)
	by := "mcp:" + reason
	if reason == "" {
		by = "mcp:unknown"
	}

	s.ks.Activate(by)

	s.store.LogEntry("mcp", "kill_switch", map[string]interface{}{
		"action": "activate",
		"reason": reason,
		"by":     by,
	})

	return s.ks.Status()
}

func (s *Server) handleDeactivateKillSwitch(params map[string]interface{}) (killswitch.KillSwitchStatus, error) {
	// Read the deactivation token under lock.
	s.mu.RLock()
	token := s.deactivationToken
	s.mu.RUnlock()

	if token == "" {
		s.store.LogEntry("mcp", "kill_switch", map[string]interface{}{
			"action": "deactivate_denied",
			"reason": "kill switch deactivation not configured — operator must set SCOPEPILOT_DEACTIVATION_TOKEN",
		})
		return killswitch.KillSwitchStatus{}, fmt.Errorf("kill switch deactivation not configured — operator must set SCOPEPILOT_DEACTIVATION_TOKEN")
	}

	callerToken, _ := params["token"].(string)
	if !secureEqual(callerToken, token) {
		s.store.LogEntry("mcp", "kill_switch", map[string]interface{}{
			"action": "deactivate_denied",
			"reason": "invalid deactivation token",
		})
		return killswitch.KillSwitchStatus{}, fmt.Errorf("invalid deactivation token")
	}

	s.ks.Deactivate()

	s.store.LogEntry("mcp", "kill_switch", map[string]interface{}{
		"action": "deactivate",
	})

	return s.ks.Status(), nil
}

func (s *Server) handleIsKillSwitchActive() map[string]interface{} {
	return map[string]interface{}{
		"active": s.ks.IsActive(),
	}
}

func (s *Server) handleRunSafeCheck(params map[string]interface{}) (map[string]interface{}, error) {
	urlsRaw, ok := params["urls"]
	if !ok {
		return nil, fmt.Errorf("missing 'urls' parameter")
	}

	urlsIface, ok := urlsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'urls' must be an array of strings")
	}

	urls := make([]string, 0, len(urlsIface))
	for i, u := range urlsIface {
		// A safety gateway must reject malformed target input loudly rather
		// than silently dropping it — a skipped element looks identical to a
		// passed check to the caller, which is exactly the kind of gap this
		// gate exists to close.
		rawURL, ok := u.(string)
		if !ok {
			return nil, fmt.Errorf("'urls' must be an array of strings (element %d is %T)", i, u)
		}
		// Normalize: ensure URL has a scheme
		if !strings.Contains(rawURL, "://") {
			rawURL = "https://" + rawURL
		}
		if _, err := url.Parse(rawURL); err == nil {
			urls = append(urls, rawURL)
		}
	}

	results := s.prx.RunSafeCheck(urls)
	return map[string]interface{}{
		"results": results,
	}, nil
}

func (s *Server) handleRunSpecialist(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	if s.ks.IsActive() {
		return nil, fmt.Errorf("kill switch is active; specialist execution denied")
	}

	targets, err := specialistTargets(params["targets"])
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	runner := s.specialists[name]
	cfg := s.specialistConfig
	gateToken := s.gateApprovalToken
	s.mu.RUnlock()
	if runner == nil {
		return nil, fmt.Errorf("specialist %q is not registered", name)
	}

	if name == "run_gate_specialist" {
		if gateToken == "" {
			return nil, fmt.Errorf("gate specialist approval is not configured")
		}
		approvalToken, _ := params["approval_token"].(string)
		if !secureEqual(approvalToken, gateToken) {
			return nil, fmt.Errorf("gate specialist approval denied")
		}
		cfg.AllowExploitation = true
	}

	return runner.Run(ctx, targets, cfg)
}

func specialistTargets(raw interface{}) ([]string, error) {
	var targets []string
	switch values := raw.(type) {
	case []interface{}:
		targets = make([]string, 0, len(values))
		for _, value := range values {
			target, ok := value.(string)
			if !ok || target == "" {
				return nil, fmt.Errorf("targets must contain non-empty strings")
			}
			targets = append(targets, target)
		}
	case []string:
		targets = append(targets, values...)
	default:
		return nil, fmt.Errorf("targets must be an array of strings")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if len(targets) > 100 {
		return nil, fmt.Errorf("at most 100 targets are allowed")
	}
	return targets, nil
}

// --- New tool handlers ---

type hostScopeResult struct {
	Host    string `json:"host"`
	InScope bool   `json:"in_scope"`
	Reason  string `json:"reason"`
}

func (s *Server) handleValidateHosts(params map[string]interface{}) ([]hostScopeResult, error) {
	hostsRaw, ok := params["hosts"]
	if !ok {
		return nil, fmt.Errorf("missing 'hosts' parameter")
	}
	hostsIface, ok := hostsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'hosts' must be an array of strings")
	}
	if len(hostsIface) == 0 {
		return nil, fmt.Errorf("'hosts' must contain at least one host")
	}
	if len(hostsIface) > 100 {
		return nil, fmt.Errorf("'hosts' must contain at most 100 hosts")
	}

	results := make([]hostScopeResult, 0, len(hostsIface))
	for i, h := range hostsIface {
		host, ok := h.(string)
		if !ok {
			return nil, fmt.Errorf("'hosts' must be an array of strings (element %d is %T)", i, h)
		}
		if host == "" {
			return nil, fmt.Errorf("'hosts' must not contain empty strings (element %d)", i)
		}
		// Pure scope rule check — no DNS, no IP blocklist.
		dec := s.prx.IsHostInScope(host)
		results = append(results, hostScopeResult{
			Host:    host,
			InScope: dec.InScope,
			Reason:  dec.Reason,
		})
	}
	return results, nil
}

func (s *Server) handleHealth() map[string]interface{} {
	uptime := time.Since(s.startedAt).Round(time.Second).String()
	return map[string]interface{}{
		"proxy": map[string]interface{}{
			"status": "ok",
			"listen": s.prx.ListenAddr,
			"uptime": uptime,
		},
		"mcp": map[string]interface{}{
			"status": "ok",
		},
		"program_id":  s.prx.ProgramID,
		"kill_switch": s.ks.IsActive(),
	}
}

func (s *Server) handleScopeShape() map[string]interface{} {
	rules := s.prx.IncludeRules()

	exactCount := 0
	wildcardCount := 0
	hasCIDR := false

	for _, r := range rules {
		switch r.Type {
		case "exact_host":
			exactCount++
		case "wildcard_host":
			wildcardCount++
		case "cidr":
			hasCIDR = true
		}
	}

	rec := ""
	if exactCount > 0 && wildcardCount == 0 && !hasCIDR {
		rec = "Exact-host only scope: subdomain enumeration adds no value. " +
			"Focus on endpoint discovery and nuclei against known hosts."
	} else if wildcardCount > 0 {
		rec = "Wildcard scope detected: subdomain enumeration is valuable. " +
			"Run passive recon (BBOT) first, then nuclei against subdomains."
	} else if hasCIDR {
		rec = "CIDR scope detected: port scanning and service discovery recommended."
	}

	return map[string]interface{}{
		"has_wildcards":      wildcardCount > 0,
		"has_cidr":           hasCIDR,
		"exact_host_count":   float64(exactCount),
		"wildcard_count":     float64(wildcardCount),
		"recommendation":     rec,
	}
}

// --- Track-D: engagement memory tools ---

func (s *Server) handleRecallEngagement(params map[string]interface{}) (map[string]interface{}, error) {
	program, _ := params["program"].(string)
	if program == "" {
		return nil, fmt.Errorf("parameter 'program' must be a non-empty string")
	}

	assets, _ := s.store.GetAssets(program)
	findings, _ := s.store.GetFindings(program)
	tested, _ := s.store.GetTested(program)

	assetResults := make([]interface{}, 0, len(assets))
	for _, a := range assets {
		assetResults = append(assetResults, map[string]interface{}{
			"host":       a.Host,
			"source":     a.Source,
			"first_seen": a.FirstSeen.Format(time.RFC3339),
			"last_seen":  a.LastSeen.Format(time.RFC3339),
			"in_scope":   a.InScope,
		})
	}

	findingResults := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		findingResults = append(findingResults, map[string]interface{}{
			"id":       f.ID,
			"host":     f.Host,
			"title":    f.Title,
			"severity": f.Severity,
			"status":   f.Status,
		})
	}

	testedResults := make([]interface{}, 0, len(tested))
	for _, te := range tested {
		testedResults = append(testedResults, map[string]interface{}{
			"host":     te.Host,
			"endpoint": te.Endpoint,
			"check":    te.Check,
			"result":   te.Result,
		})
	}

	return map[string]interface{}{
		"program":          program,
		"assets":           assetResults,
		"findings":         findingResults,
		"tested_endpoints": testedResults,
	}, nil
}

func (s *Server) handleRecordAssets(params map[string]interface{}) (map[string]interface{}, error) {
	program, _ := params["program"].(string)
	if program == "" {
		return nil, fmt.Errorf("parameter 'program' must be a non-empty string")
	}

	hostsRaw, ok := params["hosts"]
	if !ok {
		return nil, fmt.Errorf("missing 'hosts' parameter")
	}
	hostsIface, ok := hostsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'hosts' must be an array of strings")
	}
	if len(hostsIface) == 0 {
		return nil, fmt.Errorf("'hosts' must contain at least one host")
	}
	if len(hostsIface) > 1000 {
		return nil, fmt.Errorf("'hosts' must contain at most 1000 hosts")
	}

	source, _ := params["source"].(string)

	assets := make([]db.Asset, 0, len(hostsIface))
	for i, h := range hostsIface {
		host, ok := h.(string)
		if !ok {
			return nil, fmt.Errorf("'hosts' must be an array of strings (element %d is %T)", i, h)
		}
		if host == "" {
			return nil, fmt.Errorf("'hosts' must not contain empty strings (element %d)", i)
		}
		assets = append(assets, db.Asset{Host: host, Source: source})
	}

	if err := s.store.RecordAssets(program, assets); err != nil {
		return nil, fmt.Errorf("failed to record assets: %w", err)
	}

	return map[string]interface{}{
		"program":  program,
		"recorded": len(assets),
	}, nil
}

func (s *Server) handleRecordFinding(params map[string]interface{}) (map[string]interface{}, error) {
	program, _ := params["program"].(string)
	if program == "" {
		return nil, fmt.Errorf("parameter 'program' must be a non-empty string")
	}

	host, _ := params["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("parameter 'host' must be a non-empty string")
	}

	title, _ := params["title"].(string)
	if title == "" {
		return nil, fmt.Errorf("parameter 'title' must be a non-empty string")
	}

	severity, _ := params["severity"].(string)
	switch severity {
	case "critical", "high", "medium", "low", "info":
		// valid
	default:
		return nil, fmt.Errorf("parameter 'severity' must be one of: critical, high, medium, low, info (got %q)", severity)
	}

	pocRef, _ := params["poc_ref"].(string)

	finding := db.Finding{
		Title:    title,
		Severity: severity,
		Host:     host,
		Status:   "open",
		PoCRef:   pocRef,
	}

	if err := s.store.RecordFinding(program, &finding); err != nil {
		return nil, fmt.Errorf("failed to record finding: %w", err)
	}

	return map[string]interface{}{
		"finding_id": finding.ID,
		"status":     "recorded",
	}, nil
}

func (s *Server) handleMarkTested(params map[string]interface{}) (map[string]interface{}, error) {
	program, _ := params["program"].(string)
	if program == "" {
		return nil, fmt.Errorf("parameter 'program' must be a non-empty string")
	}

	host, _ := params["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("parameter 'host' must be a non-empty string")
	}

	endpoint, _ := params["endpoint"].(string)
	if endpoint == "" {
		return nil, fmt.Errorf("parameter 'endpoint' must be a non-empty string")
	}

	check, _ := params["check"].(string)
	if check == "" {
		return nil, fmt.Errorf("parameter 'check' must be a non-empty string")
	}

	result, _ := params["result"].(string)
	switch result {
	case "not_vulnerable", "vulnerable", "error", "timeout", "skipped":
		// valid
	default:
		return nil, fmt.Errorf("parameter 'result' must be one of: not_vulnerable, vulnerable, error, timeout, skipped (got %q)", result)
	}

	te := db.TestedEndpoint{
		Host:     host,
		Endpoint: endpoint,
		Check:    check,
		Result:   result,
	}

	if err := s.store.MarkTested(program, te); err != nil {
		return nil, fmt.Errorf("failed to mark tested: %w", err)
	}

	return map[string]interface{}{
		"status": "recorded",
	}, nil
}
