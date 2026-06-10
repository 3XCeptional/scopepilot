# ScopePilot Threat Model

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  T1: macOS Host ⇄ Podman VM (kernel boundary)                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  T2: Container ⇄ Container (network boundary)              │  │
│  │  ┌──────────────────────┐   ┌──────────────────────────┐   │  │
│  │  │  scopepilot          │   │  scopepilot-fixture      │   │  │
│  │  │  T3/T4: MCP+Proxy   │   │  (test HTTP)             │   │  │
│  │  │  ────────────────    │   └──────────────────────────┘   │  │
│  │  │  API boundary        │                                   │  │
│  │  └──────────────────────┘                                   │  │
│  │           │                                                 │  │
│  │           │ T5/T6: Egress boundary                          │  │
│  │           ▼                                                 │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │  External (Internet)                                  │   │  │
│  │  │  - In-scope targets (ALLOW)                          │   │  │
│  │  │  - Out-of-scope hosts (DENY)                         │   │  │
│  │  │  - Private IPs / metadata (BLOCK)                    │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Asset Inventory

| Asset | Type | Sensitivity | Location |
|-------|------|-------------|----------|
| MCP API key | Credential | Critical | env var / flag / file |
| Scope config | Configuration | High | /etc/scopepilot/config.yaml |
| Audit log | Data | Medium | in-memory ring buffer |
| Resolved IPs cache | Data | Low | in-memory map |
| TLS session keys | Ephemeral | Low | CONNECT tunnel only |
| Deactivation token | Credential | Critical | env var only |

## Threat Agent Profiles

| Agent | Capability | Motivation |
|-------|------------|------------|
| Unauthenticated network attacker | Can send HTTP to :8443/:9090 from localhost | Bypass scope, access internal resources |
| Compromised container | Can execute inside Podman network | Escalate to host or pivot to targets |
| Rogue MCP client | Has valid API key | Misuse specialist tools, disable kill switch |
| DNS rebind attacker | Controls DNS for target domain | Bypass IP blocklist |

## Attack Trees

### A1: Scope Bypass via DNS Rebinding (CONNECT)

```
Attacker controls DNS for evil.com
  └── Proxy resolves evil.com → valid IP at CheckURL time
  └── After allow, DNS changes evil.com → 169.254.169.254
  └── handleConnect re-resolves at dial time → detects mismatch
  └── [MITIGATED] handleConnect does second LookupHost + ValidateIPs
  └── dial is pinned to validated IP from first resolution
```

### A2: Kill Switch Bypass

```
Attacker obtains deactivation token
  └── Calls deactivate_kill_switch MCP tool
  └── Server compares via ConstantTimeCompare
  └── [MITIGATED] Token compared with crypto/subtle
  └── [MITIGATED] Token never in config or logs (env-only)
  └── [MITIGATED] Audit log redacts token field
```

### A3: Out-of-Scope Access via CONNECT

```
Attacker sends CONNECT to out-of-scope-host:443
  └── handleConnect calls CheckURL
  └── CheckURL: scope check fails → deny
  └── [MITIGATED] Full safety chain runs before tunnel
```

## Security Controls Mapping

| Control | Location | MITRE ATT&CK |
|---------|----------|--------------|
| Input validation (URL parse) | proxy.go ServeHTTP | T1190 |
| Kill switch | killswitch/ | T1485 (denial) |
| Scope engine | scope/scope.go | T1046 (network scanning) |
| DNS rebind protection | proxy.go handleConnect + resolvedIPs | T1583.001 |
| Rate limiting | ratelimit/ | T1499 (endpoint DoS) |
| Audit logging | audit/ | T1078 (credentials) |
| MCP auth (Bearer token) | mcp/server.go APIKey | T1190 (exploit public-facing) |
| Constant-time comparison | mcp/server.go secureEqual | T1555 (credentials) |
| No-new-privileges | Containerfile / Podman | T1068 |
| Read-only rootfs | Containerfile | T1003 (OS credential dumping) |
| Localhost-only bind | compose.yaml | T1190 |
