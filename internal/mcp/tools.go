package mcp

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/proxy"
)

// ListTools returns the definitions of all available MCP tools.
func (s *Server) ListTools() []ToolDef {
	return []ToolDef{
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
func (s *Server) CallTool(name string, params map[string]interface{}) (interface{}, error) {
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

	case "get_ratelimit_status":
		result = s.handleGetRateLimitStatus()

	case "activate_kill_switch":
		result = s.handleActivateKillSwitch(params)

	case "deactivate_kill_switch":
		result, err = s.handleDeactivateKillSwitch(params)

	case "is_kill_switch_active":
		result = s.handleIsKillSwitchActive()

	case "run_safe_check":
		result = s.handleRunSafeCheck(params)

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
	if callerToken != token {
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

func (s *Server) handleRunSafeCheck(params map[string]interface{}) map[string]interface{} {
	urlsRaw, ok := params["urls"]
	if !ok {
		return map[string]interface{}{
			"results": []*proxy.CheckResult{},
			"error":   "missing 'urls' parameter",
		}
	}

	urlsIface, ok := urlsRaw.([]interface{})
	if !ok {
		return map[string]interface{}{
			"results": []*proxy.CheckResult{},
			"error":   "'urls' must be an array of strings",
		}
	}

	urls := make([]string, 0, len(urlsIface))
	for _, u := range urlsIface {
		if s, ok := u.(string); ok {
			// Normalize: ensure URL has a scheme
			if !strings.Contains(s, "://") {
				s = "https://" + s
			}
			if _, err := url.Parse(s); err == nil {
				urls = append(urls, s)
			}
		}
	}

	results := s.prx.RunSafeCheck(urls)
	return map[string]interface{}{
		"results": results,
	}
}
