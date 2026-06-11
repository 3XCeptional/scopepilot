# ScopePilot

[![Go](https://github.com/3XCeptional/pentest-automation/actions/workflows/test.yml/badge.svg)](https://github.com/3XCeptional/pentest-automation/actions)
[![Release](https://github.com/3XCeptional/pentest-automation/actions/workflows/release.yml/badge.svg)](https://github.com/3XCeptional/pentest-automation/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/3XCeptional/pentest-automation)](https://goreportcard.com/report/github.com/3XCeptional/pentest-automation)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Put ScopePilot in front of your recon tools and you **physically cannot** send
> a request to an out-of-scope host. One proxy. Every tool. Every byte logged.

A scope-enforcing HTTPS CONNECT proxy for bug bounty hunting. Works with
curl, ffuf, nuclei, httpx, your browser — any tool that speaks HTTP proxy.

## Install

```bash
# macOS — Homebrew
brew install 3XCeptional/tap/scopepilot

# Any platform — Go install
go install github.com/3XCeptional/pentest-automation/cmd/pentest@latest

# Or download a static binary from GitHub Releases
curl -sSL https://github.com/3XCeptional/pentest-automation/releases/latest/download/scopepilot_linux_amd64.tar.gz | tar xz

# Container — pull the published image from GitHub Container Registry
podman pull ghcr.io/3XCeptional/scopepilot:latest
```

**No Docker or Podman required** to run the gate. Single static binary.

```bash
# Generate config + start
scopepilot init                          # interactive wizard
export SCOPEPILOT_MCP_API_KEY=$openssl rand -hex 32)"
scopepilot server --config scope.yaml    # proxy :8443 | MCP :9090

# Every tool is now scope-gated — physically cannot hit out-of-scope
export https_proxy=http://127.0.0.1:8443
curl -sk https://in-scope.com            # ✅ CONNECT tunnel — allowed
curl -sk https://out-of-scope.com        # ❌ 403 — blocked by proxy

# Watch live decisions as they happen
scopepilot watch
```

## Use as Upstream Proxy

Set ScopePilot as your upstream proxy in any tool. All traffic is
scope-gated — out-of-scope requests are blocked with 403 before they leave.

```bash
# curl / ffuf / httpx / nuclei
export http_proxy=http://127.0.0.1:8443
export https_proxy=http://127.0.0.1:8443

# Browser (Firefox)
# Settings → Network Settings → Manual proxy → HTTP Proxy: 127.0.0.1:8443
# ✓ Same proxy for HTTPS

# Browser (Chrome)
# Settings → System → Open proxy settings → HTTP Proxy: 127.0.0.1:8443

# Burp Suite
# Proxy → Options → Upstream Proxy Server → 127.0.0.1:8443

# ZAP
# Tools → Options → Network → Connection → Proxy: 127.0.0.1:8443
```

No per-tool configuration. Set it once, every tool is scope-safe.

## Demo

```bash
# 30-second test drive
scopepilot init                          # name: crystal
                                         # domains: client.laplace-groupe.com
export SCOPEPILOT_MCP_API_KEY=*** rand -hex 32)
scopepilot server --config scope.yaml    # start proxy

# In another terminal:
export https_proxy=http://127.0.0.1:8443
curl -sk https://client.laplace-groupe.com/app/connexion  # ✅ 200
curl -sk https://google.com                                # ❌ 403
scopepilot check https://google.com                        # ❌ out of scope
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
13. **HTTPS CONNECT tunnel** — host/port scope-gated. Once a tunnel is
    established, traffic inside it is relayed verbatim — it is a CONNECT
    allowlist, NOT a per-request filter. **Path-prefix exclusions and
    per-host rate limiting do not apply inside an established HTTPS tunnel.**
    Full per-request filtering would require TLS interception with a
    client-trusted CA, which is intentionally out of scope.
    Documented limitation; host, port, IP, rate-limit checks still apply.

The proxy accepts HTTPS CONNECT tunneling. Set your `https_proxy` to the
proxy address and every tool — curl, ffuf, nuclei, httpx, browser — is
scope-gated through the full safety chain.

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

### Compose (using published image)

To run from the published GHCR image instead of building locally, replace
the `build:` block in `compose.yaml` with the `image:` field:

```yaml
  scopepilot:
    image: ghcr.io/3XCeptional/scopepilot:latest
    ports:
      - "127.0.0.1:8443:8443"
      - "127.0.0.1:9090:9090"
    expose:
      - "8443"
      - "9090"
    networks:
      - scopepilot-net
      - scopepilot-data
    volumes:
      - ./config:/etc/scopepilot:ro
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    environment:
      SCOPEPILOT_MCP_API_KEY: ${SCOPEPILOT_MCP_API_KEY:?set SCOPEPILOT_MCP_API_KEY}
      SCOPEPILOT_DEACTIVATION_TOKEN: ${SCOPEPILOT_DEACTIVATION_TOKEN:-}
      SCOPEPILOT_GATE_APPROVAL_TOKEN: ${SCOPEPILOT_GATE_APPROVAL_TOKEN:-}
    healthcheck:
      test: ["CMD", "/scopepilot", "health", "--proxy-url=http://127.0.0.1:8443", "--mcp-url=http://127.0.0.1:9090"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    command: ["server", "--config=/etc/scopepilot/config.yaml", "--listen-proxy=:8443", "--listen-mcp=:9090"]
```

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
