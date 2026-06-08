# Threat Model

**Version**: 0.1.0 (Phase 0)
**Status**: Initial draft — will be refined as implementation proceeds

## System Overview

The Pentest Automation Platform is a local-first reconnaissance system for authorized bug-bounty programs. It runs entirely in rootless Podman containers on a single macOS host. The AI agent (Hermes + DeepSeek) acts as the operator-facing driver, while the controller, scope proxy, and VPN gateway are hard safety systems.

## Assets

| Asset | Sensitivity | Location |
|-------|------------|----------|
| Program scope/policy | High | PostgreSQL |
| Target observations/evidence | High | PostgreSQL + volume |
| VPN private keys | Critical | Podman secrets |
| API keys (model provider) | Critical | Podman secrets |
| Audit logs | Medium | PostgreSQL |
| Agent plans/approvals | Medium | PostgreSQL |
| Findings/reports | High | PostgreSQL + reports/ |
| Malware samples (operator-supplied) | Critical | Quarantine volume |
| Wordlists/signatures | Low | signatures/ + PostgreSQL |

## Trust Boundaries

```text
┌─────────────────────────────────────────────────────────┐
│ macOS Host                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ agent    │  │controller│  │  vpn-gateway         │  │
│  │ (read-   │  │ (Go API) │  │  (NET_ADMIN only)    │  │
│  │  only fs)│  │          │  │  ┌────────────────┐  │  │
│  └────┬─────┘  └────┬─────┘  │  │ WireGuard      │  │  │
│       │             │        │  │ tunnel         │──┼──┼──► Proton VPN → targets
│  ┌────┴─────────────┴────┐   │  └────────────────┘  │  │
│  │    agent network      │   └──────────────────────┘  │
│  └───────────────────────┘                             │
│       │                                                │
│  ┌────┴────────────────────────────────────────────┐   │
│  │    data network (postgres + redis)              │   │
│  └─────────────────────────────────────────────────┘   │
│       │                                                │
│  ┌────┴────────────────────────────────────────────┐   │
│  │    worker network                               │   │
│  │  ┌──────────┐     ┌──────────────┐              │   │
│  │  │ worker   │────►│ scope-proxy  │──► targets   │   │
│  │  └──────────┘     │ (egress      │   (or VPN)   │   │
│  │                    │  gatekeeper) │              │   │
│  │                    └──────────────┘              │   │
│  └─────────────────────────────────────────────────┘   │
│       │                                                │
│  ┌────┴────────────────────────────────────────────┐   │
│  │    sandbox network (ISOLATED, NO EGRESS)        │   │
│  │  ┌──────────────┐                               │   │
│  │  │ mal-sandbox  │  ◄── NO external route        │   │
│  │  └──────────────┘                               │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Threats

### T1: Agent escapes containment

**Risk**: Agent bypasses controller API, reaches target networks, Podman socket, or host.
**Mitigation**: Agent container has read-only rootfs, no capabilities, only controller API network. No host mounts, no Podman socket. Controller validates all tool calls independently of model instructions.
**Test**: Verify agent cannot reach targets, workers, databases, VPN, Podman, or public internet.

### T2: Scope bypass via DNS rebinding

**Risk**: Worker resolves scope.com to 10.0.0.1, which changes to 169.254.169.254 between validation and connection.
**Mitigation**: DNS resolved at connection time by scope proxy; revalidates on new connections. Private/reserved IPs blocked.
**Test**: Mock DNS server that rotates answers; verify scope proxy rejects out-of-scope addresses.

### T3: Scope bypass via redirect chains

**Risk**: In-scope host redirects to out-of-scope host.
**Mitigation**: Scope proxy validates every redirect target against program scope. Fails closed.
**Test**: Fixture returns redirects to out-of-scope hosts; verify proxy blocks them.

### T4: VPN tunnel leak

**Risk**: Traffic bypasses VPN when tunnel is down.
**Mitigation**: Firewall kill switch blocks all non-tunnel traffic. Pauses jobs on tunnel state change.
**Test**: Kill WireGuard interface; verify no packets leave on any other interface.

### T5: Malware sample escapes sandbox

**Risk**: Malicious sample breaks out of rootless Podman container.
**Mitigation**: No-egress network, all capabilities dropped, no-new-privileges, seccomp profile, CPU/memory/PID limits, ephemeral sandbox destroyed after use.
**Test**: Verify sandbox has no external, VPN, controller, worker, db, agent, or host connectivity.

### T6: Prompt injection from target content

**Risk**: Target response contains instructions that the model executes.
**Mitigation**: External content labeled clearly in context. System policy separate from observations. Controller validates all tool calls independently. Bounded parsers extract required fields rather than passing raw pages.
**Test**: Fixture serves hostile instruction-like content; verify agent does not follow it.

### T7: Cross-program data leakage

**Risk**: Discoveries from program A used to scan program B without authorization.
**Mitigation**: Agent memory is program-scoped. Signatures require manual approval before cross-program use.
**Test**: Attempt to use program A discoveries in program B context; verify rejection.

### T8: Credential/secrets exposure

**Risk**: Secrets in logs, reports, model context, or evidence files.
**Mitigation**: Redaction in logs and reports. Secrets in Podman secrets, never in images or source. Sanitization before model context.
**Test**: Verify no secrets in log output, reports, or agent-accessible evidence.

## Assumptions

1. The macOS host is trusted and not compromised.
2. Rootless Podman provides meaningful isolation between containers.
3. The operator has explicit written authorization for all tested assets.
4. Proton VPN WireGuard tunnel is reliable when configured.
5. The operator does not deliberately bypass safety controls.
6. DeepSeek model is accessed via API (remote) with operator opt-in for what data leaves the machine.

## Limitations (Phase 0)

1. Rootless Podman provides weaker isolation than a dedicated VM or hardware separation.
2. The malware sandbox in rootless Podman is NOT a substitute for a dedicated malware analysis VM.
3. Network timing side-channels may exist between containers on the same Podman host.
4. The Go scope proxy adds latency to every request (acceptable trade-off for safety).
