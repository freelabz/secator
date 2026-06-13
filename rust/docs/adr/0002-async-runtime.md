# ADR-0002: Async runtime — Tokio

**Status:** Accepted (chosen by maintainer)

## Context
The workload is I/O-bound and concurrency-heavy: many concurrent subprocesses with
streamed stdout, HTTP calls (providers/installer/api), a distributed work queue, and live
progress to the terminal. We need cancellation, timeouts, channels, and process control.

## Decision
Use **Tokio** (async/await) as the runtime: `rt-multi-thread`, `process` (subprocess +
streamed stdout), `sync` (mpsc/oneshot/broadcast for the result/progress buses), `time`
(timeouts/throttling), `macros`.

- Runners stream `OutputItem` through a Tokio `mpsc` `ResultSink`.
- The local executor is a Tokio task pool; the remote executor uses async Redis.
- `async fn` in traits (stable) for `Runner`/`Transport`/`Serializer` where it helps.

## Consequences
- First-class cancellation/timeout and backpressure for the streaming model.
- Async ecosystem alignment (reqwest, redis aio).
- Subprocess monitoring (CPU/mem/kill) pairs Tokio with `sysinfo`.
- Async trait object ergonomics need care (boxing/`async-trait` where dyn dispatch is
  required); acceptable.

## Alternatives considered
- *std threads + channels (+rayon)*: simpler, closer to the current per-task
  subprocess+monitor-thread model, but weaker for the distributed/streaming/cancellation
  story. Rejected as the default; some CPU-bound bits may still use blocking pools.
