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
make build         # Build containers
make test          # Run all Go tests (9 packages, 200+ tests)
make up            # Start ScopePilot + fixture via Podman Compose
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
│  internal/mcp  ◄── JSON-RPC 2.0 server (:9090)    │
│     │            8 typed tools for agents          │
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

ScopePilot exposes 8 typed JSON-RPC 2.0 tools for agent integration:

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

## Containers

All services run in rootless Podman containers on Apple Silicon (arm64):

| Container | Base | Privileges | Ports |
|-----------|------|-----------|-------|
| scopepilot | distroless/static-debian12:nonroot | cap_drop ALL, no-new-privs | 8443 (proxy), 9090 (MCP) |
| fixture | alpine:3.21 | cap_drop ALL, no-new-privs | 8080 (test HTTP) |

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
- [x] BBOT/Nuclei safe adapter (scope-filtered execution)
- [x] Containerfiles (scopepilot, fixture)
- [x] compose.yaml (rootless Podman)
- [x] Makefile (12 targets)
- [ ] Proton VPN gateway (deferred)
- [ ] PostgreSQL + Redis (deferred — using in-memory)
- [ ] Specialist agents (deferred)
- [ ] Dashboard (deferred)

## License

This project is currently unlicensed. All rights reserved.
