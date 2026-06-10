# ScopePilot Architecture Diagrams

## Container Topology (Current State)

```mermaid
graph TB
    subgraph "macOS Host"
        CLI[pentest CLI<br/>discover, scan, watch, status]
        CURL[curl / browser<br/>http_proxy=:8443]
    end

    subgraph "scopepilot-net (bridge, internal)"
        SP[scope-proxy container<br/>:8443 proxy<br/>:9090 MCP<br/>read-only rootfs<br/>cap_drop ALL]
        FIX[fixture container<br/>:8080 test HTTP<br/>synthetic endpoints]
    end

    subgraph "Safety Components"
        KS[kill switch<br/>global halt]
        RL[rate limiter<br/>per-host token bucket]
        AUD[audit log<br/>recent 10k entries]
        SCOPE[scope engine<br/>exact_host + wildcard]
        DNS[DNS resolver<br/>immediate resolution<br/>rebinding protection]
    end

    subgraph "External World"
        TARGET[in-scope targets<br/>example.com<br/>api.example.com<br/>sub.example.com]
        BLOCKED[out-of-scope<br/>blocked by gate]
    end

    CLI -->|MCP JSON-RPC :9090| SP
    CURL -->|CONNECT tunnel :8443| SP
    SP -->|scope validation| SCOPE
    SP -->|isActive?| KS
    SP -->|Allow(host)?| RL
    SP -->|log decision| AUD
    SP -->|resolve + validate| DNS
    SP -->|forward / deny| TARGET
    SP -->|deny| BLOCKED
    FIX -->|test requests| SP
```

## Request Flow (CONNECT Tunnel + Forward)

```mermaid
sequenceDiagram
    participant C as client (curl/browser)
    participant P as scope-proxy :8443
    participant KS as kill switch
    participant SC as scope engine
    participant DNS as DNS resolver
    participant RL as rate limiter
    participant AUD as audit log
    participant T as target

    Note over C,T: HTTP Forward (non-CONNECT)
    C->>P: GET /page HTTP/1.1
    P->>KS: CheckKillSwitch()
    KS-->>P: false (ok)
    P->>SC: IsHostInScope(host)
    SC-->>P: true
    P->>DNS: LookupHost(host)
    DNS-->>P: [IPs]
    P->>P: ValidateIPs(IPs)
    P->>RL: CheckRateLimit(host)
    RL-->>P: true
    P->>AUD: LogDecision("allow", ...)
    P->>P: ForwardRequest(w, r)
    P->>T: GET /page
    T-->>P: response
    P-->>C: response

    Note over C,T: HTTPS CONNECT Tunnel
    C->>P: CONNECT host:443 HTTP/1.1
    P->>KS: CheckKillSwitch()
    KS-->>P: false
    P->>P: parse host:port
    P->>P: build synthURL https://host:443
    P->>P: CheckURL(synthURL)
    P->>SC: scope check
    SC-->>P: pass
    P->>DNS: LookupHost(host)
    DNS-->>P: [IPs]
    P->>P: ValidateIPs(IPs)
    P->>RL: CheckRateLimit(host)
    RL-->>P: pass
    P->>AUD: LogDecision("allow")
    P->>P: Hijack()
    P->>C: HTTP/1.1 200 Connection Established
    P->>P: io.Copy (bidirectional relay)
    Note over C,T: encrypted TLS flows through tunnel
    C->>T: GET / HTTPS (inside tunnel)
    T-->>C: response (inside tunnel)
    P-->>P: tunnel closed by either side
    P->>AUD: log tunnel close + byte count
```

## Scope Decision Tree (Updated with CONNECT)

```mermaid
flowchart TD
    REQ[Incoming Request] --> CONNECT{Method == CONNECT?}
    CONNECT -->|yes| CONN_HANDLE[handleConnect]
    CONNECT -->|no| FWD[forward handler]

    CONN_HANDLE --> KS{global kill switch?}
    KS -->|active| DENY[403 Forbidden]
    KS -->|inactive| ACTIVE{ActiveTesting enabled?}
    ACTIVE -->|no| DENY
    ACTIVE -->|yes| PARSE[Parse host:port]
    PARSE --> SCHEME{Scheme allowed?<br/>synthURL = https://host:port}
    SCHEME -->|no| DENY
    SCHEME -->|yes| PORT{443 allowed?}
    PORT -->|no| DENY
    PORT -->|yes| HOST{In scope?<br/>exact_host / wildcard}
    HOST -->|no| DENY
    HOST -->|yes| DNS{Resolve + validate<br/>blocked IPs}
    DNS -->|blocked IP| DENY
    DNS -->|valid IP| RATE{Rate limit ok?}
    RATE -->|exceeded| DENY
    RATE -->|ok| ALLOW[200 + Hijack<br/>bidirectional TCP relay<br/>log CONNECT allow]

    FWD --> KS2{global kill switch?}
    KS2 -->|active| DENY2[write deny response]
    KS2 -->|inactive| HEALTH{Path == /health?}
    HEALTH -->|yes| HEALTH_RESP[return enriched JSON:<br/>status, kill_switch,<br/>scope counts, last_denied]
    HEALTH -->|no| ACTIVE2{ActiveTesting enabled?}
    ACTIVE2 -->|no| DENY2
    ACTIVE2 -->|yes| SCHEME2{Scheme allowed?}
    SCHEME2 -->|no| DENY2
    SCHEME2 -->|yes| PORT2{Port allowed?}
    PORT2 -->|no| DENY2
    PORT2 -->|yes| HOST2{In scope?}
    HOST2 -->|exclude match| DENY2
    HOST2 -->|no match| DENY2
    HOST2 -->|include match| PATH{Path excluded?}
    PATH -->|prefix match| DENY2
    PATH -->|no exclude| DNS2{DNS + IP validate}
    DNS2 -->|blocked| DENY2
    DNS2 -->|ok| RATE2{Rate limit}
    RATE2 -->|ok| FWD_REQ[ForwardRequest<br/>log allow]
    RATE2 -->|exceeded| WAIT[queue/delay]
```

## Threat Model — Trust Boundaries

| Boundary | From | To | Risk | Mitigation |
|----------|------|----|------|------------|
| T1 | macOS host | Podman VM | Process isolation escape | Rootless Podman, no-new-privs |
| T2 | Container | Container | Network lateral movement | Internal bridge, no gateway |
| T3 | Scope-proxy | External (HTTPS) | Out-of-scope data exfiltration | Safety chain on CONNECT + forward |
| T4 | MCP client | MCP server | Unauthorized tool invocation | Bearer token auth + audit |
| T5 | curl/browser | Proxy :8443 | Proxy bypass | Localhost-only bind |
| T6 | CONNECT tunnel (opaque TCP) | Target | Path-prefix scope bypass | Documented limitation |
