# Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-clean-rewrite.md) | Clean rewrite in Rust (not a port) | Accepted |
| [0002](0002-async-runtime.md) | Async runtime — Tokio | Accepted |
| [0003](0003-distributed-transport.md) | Distributed from day one — `Transport` trait, Redis Streams default | Accepted (default provisional) |
| [0004](0004-data-model.md) | Data model & serialization | Accepted |
| [0005](0005-expression-evaluator.md) | Expression evaluator (no `eval`) | Accepted |
| [0006](0006-task-definition.md) | Task definition strategy & MVP scope | Accepted |
| [0007](0007-cli-and-ui.md) | CLI framework & terminal UI | Accepted (UI provisional) |

Open items tracked in these ADRs: terminal-UI stack (0007), NATS-vs-Redis long-term
default (0003), built-in-vs-manifest plugin story for hook-bearing external tools (0006),
CPE/CVE version-matching approach (PLAN §8).
