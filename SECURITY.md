# Security Policy

## Scope Enforcement

This platform is designed for AUTHORIZED testing only. Every network request passes through a scope-enforcement layer that:

1. Validates the initial destination against program scope
2. Validates every redirect target against program scope
3. Resolves DNS immediately before connecting and validates all returned addresses
4. Revalidates DNS on new connections (DNS rebinding defense)
5. Blocks loopback, link-local, multicast, CGNAT, private, reserved, and cloud-metadata addresses
6. Enforces per-host and global rate limits
7. Fails closed on any ambiguity

## Kill Switches

- **Global kill switch**: `pentest stop` — stops ALL activity across ALL programs
- **Per-program kill switch**: Stops activity for a specific program only
- Both are immediate and irreversible without explicit operator action

## Agent Containment

The AI agent (Hermes + DeepSeek) operates under strict constraints:
- No direct target-network access
- No Podman socket access
- No host shell access
- No database credentials
- No VPN control
- Can only operate through versioned, typed controller tools
- Cannot broaden scope, raise limits, disable logging, or bypass safety controls

## Reporting Vulnerabilities

If you discover a security issue in this platform itself, please:
1. Do not open a public issue
2. Document the finding with reproduction steps
3. Contact the repository maintainer directly

## Safe Harbor

This platform is designed for authorized security testing. Users must:
- Have explicit written authorization for all tested assets
- Comply with all program policies and restrictions
- Never use this platform for unauthorized testing
