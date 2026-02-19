# Secator Go Migration PoC Design

**Date:** 2026-02-19
**Status:** Approved
**Approach:** Go-Native Redesign with Machinery

## Overview

Proof of concept for migrating secator from Python to Go, using Machinery for distributed task execution. The PoC will be contained in a `go/` folder at the project root.

### Motivation

1. **Performance bottlenecks** — CPU-bound processing, memory usage, concurrency limits in Python
2. **Deployment simplicity** — Single binary distribution instead of Python environments and dependencies
3. **Celery/Airflow pain** — Distributed execution backends causing reliability and maintenance issues

## Project Structure

```
go/
├── cmd/
│   └── secator/
│       └── main.go              # CLI entry (cobra)
│
├── internal/                    # Private implementation
│   ├── engine/
│   │   ├── runner.go            # Core runner interface + base impl
│   │   ├── executor.go          # Process execution (cmd wrapper)
│   │   └── pipeline.go          # Channel-based stream processing
│   │
│   ├── tasks/
│   │   ├── registry.go          # Task registration + discovery
│   │   ├── httpx/
│   │   │   └── httpx.go         # httpx task implementation
│   │   └── nuclei/
│   │       └── nuclei.go        # nuclei task implementation
│   │
│   ├── workflow/
│   │   ├── loader.go            # YAML workflow parser
│   │   ├── dag.go               # DAG builder for task dependencies
│   │   └── executor.go          # Workflow execution engine
│   │
│   ├── store/                   # Backends (addons equivalent)
│   │   ├── store.go             # Store interface
│   │   ├── mongodb/
│   │   ├── gcs/
│   │   └── api/
│   │
│   └── broker/                  # Machinery abstraction
│       ├── broker.go            # Broker interface
│       └── machinery/           # Machinery implementation
│
├── pkg/                         # Public API
│   ├── types/                   # Output types (Url, Vuln, Port, etc.)
│   │   ├── types.go             # Base OutputType interface
│   │   ├── url.go
│   │   ├── vulnerability.go
│   │   └── ...
│   │
│   └── config/                  # Configuration
│       └── config.go
│
├── configs/                     # YAML definitions
│   ├── workflows/
│   ├── scans/
│   └── profiles/
│
├── testdata/                    # Test fixtures
│   ├── httpx_output.json
│   ├── nuclei_output.json
│   ├── workflows/
│   └── *.txt                    # Benchmark target lists
│
├── benchmark/                   # Comparison benchmarks
│   └── comparison_test.go
│
├── scripts/
│   └── compare.sh               # Manual comparison script
│
├── go.mod
└── go.sum
```

## Core Types & Interfaces

### OutputType Interface

```go
type OutputType interface {
    Type() string                      // "url", "vulnerability", "port", etc.
    UUID() string                      // Unique identifier for deduplication
    Source() string                    // Task that produced this
    Timestamp() time.Time
    ToMap() map[string]any             // Serialization
    SetContext(ctx map[string]any)     // Inject runtime context
}
```

### Runner Interface

```go
type Runner interface {
    Name() string
    Run(ctx context.Context, inputs []string) <-chan OutputType
    Status() Status  // Pending, Running, Success, Failure
}

type Task interface {
    Runner
    Command() string                           // e.g., "httpx"
    InputType() string                         // "url", "host", "ip"
    OutputTypes() []string                     // ["url", "subdomain"]
    Install() error                            // Auto-installation
    Parse(line []byte) ([]OutputType, error)   // Parse single output line
}
```

### Store Interface

```go
type Store interface {
    Name() string
    SaveRunner(ctx context.Context, r *RunnerState) error
    UpdateRunner(ctx context.Context, id string, r *RunnerState) error
    SaveFinding(ctx context.Context, f OutputType) error
    UpdateFinding(ctx context.Context, id string, f OutputType) error
    FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error)
    Close() error
}
```

### Broker Interface

```go
type Broker interface {
    RegisterTask(name string, handler TaskHandler) error
    Enqueue(ctx context.Context, task string, args []any) (JobID, error)
    EnqueueWorkflow(ctx context.Context, w WorkflowSpec) (JobID, error)
    Results(ctx context.Context, jobID JobID) <-chan OutputType
    Status(ctx context.Context, jobID JobID) (JobStatus, error)
    Close() error
}
```

## Pipeline Architecture

Channel-based streaming throughout:

- `Runner.Run()` returns `<-chan OutputType` — native Go streaming
- `bufio.Scanner` for line-by-line subprocess output parsing
- Fan-out via goroutine pool with `sync.WaitGroup`
- Context cancellation for graceful shutdown
- Stores receive items inline as they stream through

```go
func (p *Pipeline) Run(ctx context.Context, inputs []string) <-chan OutputType {
    out := make(chan OutputType, 100)

    go func() {
        defer close(out)
        current := inputsToChan(inputs)

        for _, stage := range p.stages {
            current = p.runStage(ctx, stage, current)
        }

        for result := range current {
            p.persistToStores(ctx, result)
            out <- result
        }
    }()

    return out
}
```

## Machinery Integration

- Supports all Machinery backends: Redis, AMQP, SQS, MongoDB
- Workflows map to Machinery chains/groups natively
- Results serialized as JSON through result backend
- Worker mode with configurable concurrency
- Context cancellation for graceful shutdown

```go
func NewBroker(cfg Config) (*MachineryBroker, error) {
    mcfg := &config.Config{
        Broker:          cfg.BrokerURL,        // redis://localhost:6379
        DefaultQueue:    cfg.DefaultQueue,
        ResultBackend:   cfg.ResultBackend,
        ResultsExpireIn: cfg.ResultsTTL,
    }

    server, err := machinery.NewServer(mcfg)
    // ...
}
```

## Task Implementation Pattern

Tasks self-register via `init()`:

```go
func init() {
    registry.Register("httpx", func() Task { return &Httpx{} })
}

type Httpx struct {
    executor *engine.Executor
    opts     Options
}

func (h *Httpx) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
    out := make(chan types.OutputType, 100)

    go func() {
        defer close(out)
        // Execute command, parse output, emit to channel
    }()

    return out
}

func (h *Httpx) Parse(line []byte) ([]types.OutputType, error) {
    // Parse JSON line, return URL + Certificate + Subdomain outputs
}
```

## Workflow System

- YAML structure matches Python secator exactly — same workflow files work
- DAG built from `_group` (parallel) and regular keys (sequential)
- Conditions evaluated via expression parser
- Results tracked by type for `targets_` extraction

```yaml
type: workflow
name: domain_recon
tasks:
  _group:                    # Parallel
    httpx:
      tech_detect: true
    nuclei:
      severity: [critical, high]

  wafw00f:                   # Sequential (after group)
    targets_: [url.url]
```

## CLI Interface

Mirrors Python secator exactly:

```bash
secator x httpx example.com          # Run task
secator w domain_recon example.com   # Run workflow
secator s full_scan example.com      # Run scan
secator worker                        # Start worker
secator health                        # Check tools
```

Same flags: `-o`, `-p`, `--json`, `--store`

## Store Implementations

### MongoDB
- Collections: `tasks`, `workflows`, `scans`, `findings`
- Same document schema as Python
- Duplicate detection via aggregation pipeline

### GCS
- File uploads for screenshots, stored responses
- Returns `gs://` paths for uploaded files

### API
- Configurable endpoints with placeholder substitution
- Same auth header pattern as Python

## Testing Strategy

| Level | Description |
|-------|-------------|
| Unit | Parser tests with fixtures from Python test suite |
| Integration | Full task/workflow execution against real targets |
| Compatibility | Automated comparison of Python vs Go JSON output |
| Benchmark | `testing.B` benchmarks + comparison script |

## PoC Scope

### In Scope

| Component | Scope |
|-----------|-------|
| Tasks | `httpx`, `nuclei` with full parsing |
| Workflow | YAML loader + DAG executor (chain, group) |
| CLI | `x`, `w`, `s` commands with same flags |
| Stores | MongoDB, GCS, API (all three addons) |
| Broker | Machinery with Redis/AMQP/SQS/MongoDB support |
| Worker | `secator worker` with configurable concurrency |
| Testing | Unit, integration, compatibility, benchmarks |

### Out of Scope

- All 40+ tasks (only httpx + nuclei)
- Scans (workflow-of-workflows)
- AI task
- Profiles (aggressive, stealth)
- Exporters (CSV, GDrive)
- Airflow backend

## Success Criteria

| Criterion | Validation |
|-----------|------------|
| **Performance** | Benchmark showing Go faster than Python |
| **Code simplicity** | Subjective review of code quality |
| **Deployment** | Single `go build` produces working binary |
| **Output compatibility** | JSON matches Python field-for-field |
| **Workflow compatibility** | Same YAML files work in both versions |
| **Store compatibility** | Same MongoDB schema, same API calls |

## Decision Point

**If success criteria met:**
- Proceed with full migration
- Port remaining 40+ tasks incrementally
- Deprecate Python version over time

**If not met:**
- Document what failed and why
- Consider hybrid approach or staying with Python
