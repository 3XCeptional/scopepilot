import sys

with open("internal/mcp/tools.go", "r") as f:
    content = f.read()

# 1. Change return []ToolDef to tools := []ToolDef
content = content.replace("func (s *Server) ListTools() []ToolDef {\n\treturn []ToolDef{", "func (s *Server) ListTools() []ToolDef {\n\ttools := []ToolDef{")

# 2. Append to ListTools
old_list_tools_end = "\t\t},\n\t}\n}"
new_list_tools_end = """		},
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
}"""
content = content.replace(old_list_tools_end, new_list_tools_end)

# 3. Add to callTool switch
old_call_tool = """	case "run_safe_check":
		result = s.handleRunSafeCheck(params)

	default:"""
new_call_tool = """	case "run_safe_check":
		result = s.handleRunSafeCheck(params)

	case "run_recon_specialist", "run_vuln_specialist", "run_gate_specialist":
		result, err = s.handleRunSpecialist(ctx, name, params)

	default:"""
content = content.replace(old_call_tool, new_call_tool)

# 4. Append handleRunSpecialist and specialistTargets at the end of the file
append_funcs = """

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
		if approvalToken != gateToken {
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
"""
content += append_funcs

with open("internal/mcp/tools.go", "w") as f:
    f.write(content)

print("Patch applied")
