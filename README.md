# ScopePilot

A model-agnostic, rootless-Podman scope enforcement gateway for authorized security testing. Works with Hermes, Claude, Codex, OpenClaw, and any MCP-compatible agent.

**Current**: v0.1.0 — Safety gate MVP. All core packages built and tested.

## What It Does

ScopePilot sits between an operator's recon tools (BBOT, Nuclei, custom scripts) and their targets. Every request passes through a safety chain:

```
target list → scope check → DNS revalidation → IP blocklist → rate limit
→ kill switch check → audit log → [forward to target only if ALL pass]
```

## Quick Start

```bash
make doctor        # Check Go, Podman environment
export SCOPEPILOT_MCP_API_KEY="$(openssl rand -hex 32)"
export SCOPEPILOT_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
make build         # Build containers
make test          # Run all Go tests (9 packages, 200+ tests)
make up            # Start ScopePilot + PostgreSQL + fixture
make test-unit     # Unit tests only
make logs          # Tail logs
make clean         # Stop and remove containers
```

## Architecture

```text
┌─ ScopePilot ────────────────────────────────────┐
│                                                   │
│  cmd/pentest  ◄── CLI entry point                 │
│     │                                             │
│  internal/mcp  ◄── authenticated JSON-RPC (:9090)  │
│     │            core + bounded specialist tools    │
│  internal/proxy  ◄── HTTP proxy (:8443)            │
│     │            scope enforcement on every req    │
│  internal/scope  ◄── host/URL/IP scope matching    │
│  internal/normalize ◄── URL/host/IDN normalization │
│  internal/ratelimit ◄── per-host token bucket      │
│  internal/killswitch ◄── global program kill       │
│  internal/audit  ◄── append-oriented audit log     │
│  internal/config ◄── YAML config + validation      │
│                                                   │
│  internal/adapter ◄── BBOT/Nuclei safe wrappers    │
│                     (MCP-scope-filtered execution)  │
│                                                   │
│  containers/scopepilot/Containerfile               │
│  containers/fixture/Containerfile                  │
│  compose.yaml                                      │
└───────────────────────────────────────────────────┘
```

## MCP Tools

ScopePilot exposes 8 core tools plus 3 registered specialist tools. All MCP
requests require `Authorization: Bearer $SCOPEPILOT_MCP_API_KEY`.

| Tool | Purpose |
|------|---------|
| `get_scope_status` | Current scope summary (include/exclude counts) |
| `check_url` | Validate a single URL against all safety layers |
| `get_audit_log` | Recent audit entries (filter by event type) |
| `get_ratelimit_status` | Per-host rate limiter state |
| `activate_kill_switch` | Stop all activity (requires reason) |
| `deactivate_kill_switch` | Resume after kill |
| `is_kill_switch_active` | Check kill switch status |
| `run_safe_check` | Batch URL validation — primary BBOT/Nuclei entry point |
| `run_recon_specialist` | Bounded passive BBOT specialist |
| `run_vuln_specialist` | Low-impact Nuclei specialist |
| `run_gate_specialist` | Separately approved Gate specialist |

`run_gate_specialist` also requires `SCOPEPILOT_GATE_APPROVAL_TOKEN`.

## Safety Chain (every request)

1. **Kill switch** — global halt if active
2. **URL parse & normalize** — IDN→Punycode, lowercase, sort query params
3. **Scheme validation** — only allowed schemes (default: https)
4. **Port validation** — only allowed ports (default: 443)
5. **Host scope** — exact_host, wildcard_host matching
6. **Path exclusion** — path_prefix exclusions override inclusions
7. **DNS resolution** — immediate resolve, every IP validated
8. **IP blocklist** — loopback, private, link-local, multicast, CGNAT, documentation, cloud-metadata blocked
9. **Rate limit** — per-host token bucket
10. **Redirect revalidation** — every redirect target re-checked through entire chain
11. **Audit log** — every allow/deny recorded
12. **Response redaction** — Authorization, Cookie, Set-Cookie headers stripped

The proxy deliberately rejects HTTPS `CONNECT` tunneling because encrypted
tunnels would bypass path exclusions and per-request rate limits. Active HTTPS
scanner execution remains blocked until a TLS-aware worker/proxy design is
implemented.

## Containers

All services run in rootless Podman containers on Apple Silicon (arm64):

| Container | Base | Privileges | Ports |
|-----------|------|-----------|-------|
| scopepilot | distroless/static-debian12:nonroot | cap_drop ALL, no-new-privs | 8443 (proxy), 9090 (MCP) |
| fixture | alpine:3.21 | cap_drop ALL, no-new-privs | 8080 (test HTTP) |
| postgres | postgres:17-alpine | cap_drop ALL, no-new-privs | internal only |

- No privileged containers
- No host networking
- No Podman socket mounts
- Read-only root filesystem (scopepilot)
- CPU limit: 0.5, Memory limit: 256MB
- Internal bridge network (no external gateway)

## Development

```bash
# All tests pass with race detector
go test -race ./...

# Build CLI binary
go build ./cmd/pentest/

# Vet
go vet ./...
```

## Project Status

- [x] Configuration schema + validation
- [x] URL/host/IDN normalization
- [x] Scope engine (include/exclude, wildcard, path_prefix, CIDR)
- [x] IP blocklist (17 blocked ranges)
- [x] DNS revalidation and redirect validation
- [x] Per-host rate limiting
- [x] Global/program kill switches
- [x] Append-oriented audit log with redaction
- [x] Full safety-chain HTTP proxy
- [x] JSON-RPC 2.0 MCP server with 8 tools
- [x] Authenticated specialist MCP registration
- [x] BBOT/Nuclei adapters require the scope proxy and fail closed for unenforceable VPN namespaces
- [x] Containerfiles (scopepilot, fixture, WireGuard)
- [x] compose.yaml (rootless Podman)
- [x] Makefile (12 targets)
- [x] PostgreSQL-backed audit storage in the container build
- [x] Embedded operator dashboard
- [ ] Containerized scanner workers and TLS-aware HTTPS enforcement
- [ ] Enforced Proton VPN egress for scanner/proxy traffic

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
