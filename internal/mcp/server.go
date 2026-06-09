// Package mcp implements a Model Context Protocol server that exposes
// ScopePilot's controls as typed tools callable via JSON-RPC 2.0.
//
// The server wraps the proxy, audit logger, and kill switch into a set of
// tools that can be invoked by LLM agents (Hermes, Claude, Codex) to
// interact with the scope-enforcing proxy safely.
//
// JSON-RPC endpoint: POST /mcp with body {"method":"...","params":{...},"id":1}
package mcp

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/dhiren/pentest-automation/internal/audit"
	"github.com/dhiren/pentest-automation/internal/killswitch"
	"github.com/dhiren/pentest-automation/internal/proxy"
)

// ToolDef describes a single callable tool with typed JSON Schema input/output.
type ToolDef struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	InputSchema  map[string]interface{} `json:"input_schema"`
	OutputSchema map[string]interface{} `json:"output_schema"`
}

// jsonrpcRequest is a JSON-RPC 2.0 request.
type jsonrpcRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	ID      interface{}            `json:"id"`
}

// jsonrpcResponse is a JSON-RPC 2.0 response.
type jsonrpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// rpcError is a JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
var (
	errParse          = &rpcError{Code: -32700, Message: "Parse error"}
	errInvalidReq     = &rpcError{Code: -32600, Message: "Invalid Request"}
	errMethodNotFound = &rpcError{Code: -32601, Message: "Method not found"}
	errInvalidParams  = &rpcError{Code: -32602, Message: "Invalid params"}
	errInternal       = &rpcError{Code: -32603, Message: "Internal error"}
)

// Server is a JSON-RPC 2.0 server that exposes ScopePilot tools.
type Server struct {
	mu                sync.RWMutex
	prx               *proxy.Proxy
	audit             *audit.Logger
	ks                *killswitch.Switch
	programID         string
	apiKey            string
	deactivationToken string
}

// NewServer creates a new MCP server wrapping the given proxy, audit logger,
// and kill switch.
func NewServer(prx *proxy.Proxy, auditLog *audit.Logger, ks *killswitch.Switch) *Server {
	return &Server{
		prx:   prx,
		audit: auditLog,
		ks:    ks,
	}
}

// SetProgramID sets the program ID reported by scope-status tools.
func (s *Server) SetProgramID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.programID = id
}

// SetAPIKey sets an optional API key for bearer-token authentication.
// If set, all incoming requests must include an Authorization: Bearer ***
// header. If empty, authentication is skipped (local dev mode).
func (s *Server) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = key
}

// SetDeactivationToken sets the required token for deactivating the kill switch.
// If empty, deactivation is always denied.
func (s *Server) SetDeactivationToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deactivationToken = token
}

// programID gets the current program ID.
func (s *Server) getProgramID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.programID
}

// logToolInvocation records a tool invocation in the audit log.
func (s *Server) logToolInvocation(toolName string, params map[string]interface{}, result interface{}, err error) {
	data := map[string]interface{}{
		"tool":   toolName,
		"params": params,
	}
	if err != nil {
		data["error"] = err.Error()
	}
	if result != nil {
		data["result_type"] = resultTypeName(result)
	}
	s.audit.Log("mcp", "tool_invocation", data)
}

// resultTypeName returns a short type description for structured results.
func resultTypeName(result interface{}) string {
	switch result.(type) {
	case *proxy.CheckResult:
		return "check_result"
	case []*proxy.CheckResult:
		return "check_results"
	case proxy.ScopeSummary:
		return "scope_summary"
	case *proxy.RateLimitState:
		return "ratelimit_state"
	case killswitch.KillSwitchStatus:
		return "killswitch_status"
	case map[string]interface{}:
		return "generic_map"
	case bool:
		return "boolean"
	case []*audit.Entry:
		return "audit_entries"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 HTTP handler
// ---------------------------------------------------------------------------

// ServeHTTP implements http.Handler. It accepts POST requests at any path
// and processes JSON-RPC 2.0 request bodies.
//
// MCP should only be exposed on localhost or behind authentication.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   errInvalidReq,
			ID:      nil,
		})
		return
	}

	// API key authentication: if an apiKey is configured, require
	// Authorization: Bearer <key> on every request.
	s.mu.RLock()
	key := s.apiKey
	s.mu.RUnlock()
	if key != "" {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+key {
			s.writeJSON(w, http.StatusUnauthorized, jsonrpcResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32001, Message: "unauthorized"},
				ID:      nil,
			})
			return
		}
	}

	var req jsonrpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   errParse,
			ID:      nil,
		})
		return
	}

	if req.JSONRPC != "2.0" {
		s.writeJSON(w, http.StatusBadRequest, jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   errInvalidReq,
			ID:      req.ID,
		})
		return
	}

	// Handle the method.
	var resp jsonrpcResponse

	switch req.Method {
	case "list_tools":
		resp = jsonrpcResponse{
			JSONRPC: "2.0",
			Result:  s.ListTools(),
			ID:      req.ID,
		}

	case "call_tool":
		if req.Params == nil {
			resp = jsonrpcResponse{
				JSONRPC: "2.0",
				Error:   errInvalidParams,
				ID:      req.ID,
			}
			break
		}

		toolName, _ := req.Params["name"].(string)
		toolParams, _ := req.Params["arguments"].(map[string]interface{})
		if toolParams == nil {
			toolParams = map[string]interface{}{}
		}

		result, err := s.CallTool(toolName, toolParams)
		if err != nil {
			resp = jsonrpcResponse{
				JSONRPC: "2.0",
				Error: &rpcError{
					Code:    -32602,
					Message: err.Error(),
				},
				ID: req.ID,
			}
		} else {
			resp = jsonrpcResponse{
				JSONRPC: "2.0",
				Result:  result,
				ID:      req.ID,
			}
		}

	default:
		resp = jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   errMethodNotFound,
			ID:      req.ID,
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// writeJSON is a small helper to write a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[mcp] writeJSON encode error: %v", err)
	}
}
