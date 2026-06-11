# ScopePilot Distributed Hunt Architecture

## Problem

Single-agent hunting is sequential: one agent drives one proxy, analyzes results, then acts.
While the agent analyzes a JS bundle, no recon happens. While recon runs, the agent is idle.

## Solution — Commander + Worker Pool

```
ORCHESTRATOR (you / driving agent)
  │
  ├── spawns workers per scope target
  ├── deep-analyzes results while workers execute
  ├── builds payloads from analysis
  ├── spawns new workers with crafted payloads
  └── all workers route through ScopePilot proxy
          │
          ▼
    TASK QUEUE (scoped, rate-limited, prioritized)
          │
          ▼
    WORKER POOL (parallel agents)
     ┌─────────┐ ┌─────────┐ ┌─────────┐
     │ worker1 │ │ worker2 │ │ workerN │
     │ recon   │ │ vuln    │ │ payload │
     └────┬────┘ └────┬────┘ └────┬────┘
          │           │           │
          ▼           ▼           ▼
    ┌─────────────────────────────────────┐
    │       SCOPEPILOT PROXY :8445         │
    │  (every worker's traffic scoped)     │
    └─────────────────────────────────────┘
          │
          ▼
    IN-SCOPE TARGETS
```

## Components

### 1. Task Queue (`internal/queue/queue.go`)

JSON-lines file at `~/.scopepilot/queue.jsonl`. Each line:

```json
{"id":"uuid","target":"client.example-target.com","type":"recon","priority":1,"status":"pending","created":"2026-06-11T05:00:00Z","depends_on":null}
```

| Field | Values |
|-------|--------|
| `type` | `recon`, `vuln`, `payload`, `analyze`, `report` |
| `status` | `pending`, `running`, `done`, `failed`, `blocked` |
| `priority` | 1 (highest) to 5 (lowest) |
| `depends_on` | task ID that must complete first |

Queue validates every task against the scope engine before accepting it. A task for `google.com` is rejected with "out of scope".

### 2. Worker Spawner (`cmd/pentest/main.go` — `spawn` subcommand)

```
pentest spawn --queue-id <uuid> --agent codex|claude|agy
```

Each worker is a disposable agent session with:
- Scoped target URL
- Allowed techniques from scope config
- Proxy address (`http://127.0.0.1:8445`)
- Rate limit (max 3 req/s per host across all workers)
- Write-only result channel (can't modify queue)

Worker template:

```bash
export http_proxy=http://127.0.0.1:8445
export https_proxy=http://127.0.0.1:8445
codex exec "Hunt for IDOR on client.example-target.com. 
  Every request must go through http_proxy. 
  Rate limit: 3 req/s. 
  Report findings as JSON to /tmp/result_<uuid>.json"
```

### 3. Scope-Bound Task Distribution

- Every task is validated against ScopePilot's MCP `check_url` before enqueue
- Workers spawn with the proxy pre-configured — cannot bypass it
- Worker commands are restricted to target's allowed techniques
- Out-of-scope tasks rejected at queue level, not worker level

### 4. Result Channel

Each worker writes results to `~/.scopepilot/results/<uuid>.json`:

```json
{"task_id":"uuid","status":"done","findings":[{"type":"idor","endpoint":"/api/clients/123","severity":"critical"}],"artifacts":["/tmp/response_123.json"],"duration_sec":45}
```

Orchestrator polls the results directory. When results appear, it:
1. Reads the finding
2. Analyzes response data
3. Spawns new tasks based on findings (e.g., found API endpoint → spawn IDOR worker)
4. Builds payloads from response patterns

### 5. Payload Builder

While workers execute, the orchestrator:
- Deep-analyzes JS bundles for API routes
- Extracts parameter patterns from responses
- Builds fuzz lists from observed patterns
- Crafts JWT attacks from token analysis
- Stores payloads in `~/.scopepilot/payloads/` for workers to consume

## CLI Usage

```bash
# Start the commander
pentest queue init --program example-program

# Add tasks
pentest queue add --target client.example-target.com --type recon --priority 1
pentest queue add --target example-target.com --type recon --priority 2

# Show queue
pentest queue list

# Start workers (non-blocking, runs in background)
pentest spawn --max-workers 3

# Watch results stream in
pentest watch

# Analyze results and build next-gen tasks
pentest analyze --from results/latest
pentest queue add --from analysis.json
```

## How Scope Is Read and Passed to Workers

ScopePilot loads scope from a YAML config file at startup. The scope config looks like:

```yaml
programs:
  - id: example-program
    scope:
      include:
        - type: exact_host
          value: "client.example-target.com"
        - type: exact_host
          value: "example-target.com"
      exclude: []
```

### Scope Reading Flow

```
1. User runs: pentest server --config example-program.yaml
2. config.LoadConfig("example-program.yaml") → parses YAML into config.ProgramConfig
3. scope.NewEngine(programID, progCfg.Scope) → creates scope Engine
   - Engine stores include rules (exact_host, wildcard_host)
   - Engine stores exclude rules (path_prefix, exact_host)
4. Engine is embedded in Proxy struct
5. Proxy.CheckURL("https://client.example-target.com/app/connexion"):
   - Calls Engine.CheckHost("client.example-target.com")
   - Engine iterates include rules → match found → ALLOW
   - Engine iterates exclude rules → no match → ALLOW
   - Returns (allowed bool, reason string)
6. queue.Add(task) validates target BEFORE enqueue:
   - Parses target URL to extract hostname
   - Calls scope.NewEngine or proxy.CheckURL to validate
   - If DENIED → task rejected with "out of scope" error
   - If ALLOWED → task written to queue file
```

### Scope Validation in the Queue

The queue's `Add()` method:

```go
func (q *Queue) Add(task Task, validateScope func(target string) bool) error {
    if !validateScope(task.Target) {
        return fmt.Errorf("target %q is out of scope", task.Target)
    }
    // write to JSON-lines file
}
```

When the queue is created during server startup:

```go
// In runServer():
scopeValidator := func(target string) bool {
    result, err := prx.CheckURL(target)
    return err == nil && result != nil && result.Allowed
}
taskQueue := queue.NewQueue(queuePath, scopeValidator)
```

### Worker Type: Container Scanners (BBOT/Nuclei)

Standard scanner tools run in Podman containers. Each container:
- Reads the scope config from mounted volume
- Routes all traffic through the proxy
- Writes results to shared evidence directory
- Automatically rate-limited by the proxy

Container worker spec:

| Field | Value |
|-------|-------|
| Image | `docker.io/bbot/bbot:latest` or `projectdiscovery/nuclei:latest` |
| Network | `scopepilot-net` (Podman internal bridge) |
| Capabilities | `cap_drop ALL`, `no-new-privileges` |
| Resources | 0.5 CPU, 256MB RAM |
| Proxy | `HTTP_PROXY=http://scopepilot:8443` |
| Mounts | Config:ro, Evidence:rw |

### Worker Type: AI Agent (Codex/Claude/agy)

For deep analysis and chained attacks, AI agents run as parallel process workers:

```bash
# Spawn a Codex worker for IDOR testing
pentest spawn --agent codex --task-id <uuid>

# The spawned agent gets:
export http_proxy=http://127.0.0.1:8445
export https_proxy=http://127.0.0.1:8445
codex exec "Hunt for IDOR on client.example-target.com.
  Rate limit: 3 req/s.
  Every request must go through the proxy.
  Report findings to ~/.scopepilot/results/<uuid>.json"
```

AI agent worker lifecycle:

1. Orchestrator pops task from queue
2. Spawns codex/claude/agy with scoped goal + proxy config
3. Worker runs autonomously, all traffic through proxy
4. Worker writes findings to results directory
5. Orchestrator polls results, analyzes, chains
6. New tasks auto-created from findings

### Worker Comparison

| Aspect | Container Scanner | AI Agent |
|--------|-----------------|----------|
| Tool | BBOT, Nuclei | Codex, Claude, agy |
| Isolation | Podman container | Process-level |
| Scope check | Pre-validated + proxy | Pre-validated + proxy |
| Output | Structured JSON | Free-form + JSON |
| Chaining | Manual | Auto-chained by orchestrator |
| Deep analysis | No | Yes (JS bundles, payloads) |

| Worker | Tool | Purpose |
|--------|------|---------|
| Recon | codex/agy | Subdomain discovery, tech detection, endpoint enumeration |
| Vuln | codex | Targeted vulnerability probing (IDOR, XSS, SQLi) |
| Payload | agent | Builds custom payloads from analysis |
| Analyze | orca | Deep response analysis, pattern extraction |
| Report | codex | Write findings report from results |

## Rate Limiting Across Workers

The proxy enforces per-host rate limits. All workers share the same proxy, so:
- 3 workers hitting `client.example-target.com` share the same 3 req/s bucket
- If one worker uses all 3 tokens, others queue at the proxy level
- No worker can bypass the rate limit by spawning more workers

## State Persistence

- Queue: `~/.scopepilot/queue.jsonl` (append-only, replayable)
- Results: `~/.scopepilot/results/<uuid>.json`
- Payloads: `~/.scopepilot/payloads/<uuid>.json`
- Worker logs: `~/.scopepilot/logs/<worker_id>.log`

If the orchestrator crashes mid-hunt:
1. Restart: `pentest queue list` shows all pending/running tasks
2. Running workers finish and write results
3. `pentest queue retry --failed` re-queues failed tasks
4. No data loss — queue is append-only

## Future: Auto-Chaining

When completed tasks chain together automatically:
- Recon finds endpoint `/api/v3/checkout-bff/inquiry`
- Task queue auto-creates vuln task for that endpoint
- Vuln task finds IDOR on order tokens
- Queue auto-creates payload task to craft token enumeration
- Payload worker runs with crafted token list
- Orchestrator monitors results, reports finding

## Implementation Phases

| Phase | What | When |
|-------|------|------|
| 1 | Task queue (JSON-lines, validate against scope, CRUD) | Now |
| 2 | Worker spawner (codex/exec/claude --print with proxy) | Next |
| 3 | Result channel + orchestrator loop | Next |
| 4 | Payload builder (JS analysis, param extraction) | Later |
| 5 | Auto-chaining (recon→vuln→payload chains) | Later |
