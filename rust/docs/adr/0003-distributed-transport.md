# ADR-0003: Distributed execution from day one — `Transport` trait, Redis Streams default

**Status:** Accepted (distributed-from-day-one chosen by maintainer); default broker
provisional.

## Context
Secator's hallmark is local/remote parity: the same workflow runs in-process or fanned out
to workers. The Python tool achieves this with Celery (default `filesystem://` broker,
optional Redis), pickling live objects across the wire. We want this parity from the start,
without pickle and without coupling the engine to one broker.

## Decision
- Define a **`Transport` trait** (`secator-exec`) as the seam between the DAG engine and
  execution. The DAG is compiled to `WorkUnit`s with chain/group/chord edges; the transport
  submits units and streams back state/progress/results.
- Ship **two implementations from day one**:
  - `LocalTransport` — in-process Tokio task pool; zero infra; the default and the
    *reference behavior* the remote impl must match.
  - `RemoteTransport` — **Redis Streams** with consumer groups as the work queue, plus a
    results/progress channel; `secator worker` consumes units.
- **Wire format**: `OutputItem` via serde (JSON default; msgpack/bincode optional).
  Explicit and language-neutral — **no pickle**. Large result sets may move as id lists
  rehydrated from a store once `secator-query` exists (mirrors the Mongo optimization).

## Why Redis Streams (default)
- Already part of the Python stack as the production broker option (operational familiarity).
- Consumer groups give work distribution + acks + redelivery; streams give ordered,
  persistent result/progress channels.
- Single dependency for queue + lightweight result transport.

## Consequences
- Two code paths to test at parity from M4 (local) → M5 (remote).
- Redis becomes the recommended infra for distributed mode; local mode stays infra-free.
- The trait keeps us free to add a NATS JetStream backend (documented alternative) or an
  AMQP one without touching the engine.

## Alternatives considered
- *Local-first, distribution later*: faster to a working tool, but the maintainer chose
  distributed-from-day-one to lock the transport seam early. We still build `LocalTransport`
  first as the reference.
- *NATS JetStream as default*: excellent fit (subjects + durable consumers), but less
  existing operational footprint in the project. Kept as the primary alternative; revisit
  before M5 ships.
- *Embedded/no-broker distributed (e.g. gRPC mesh)*: more moving parts; rejected for v1.
