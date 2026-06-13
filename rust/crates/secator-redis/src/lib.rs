//! Redis Streams transport (Python Celery + Redis broker parity).
//!
//! Two streams per deployment:
//! * `secator:units` — task queue. Clients `XADD`; workers `XREADGROUP`.
//! * `secator:results:<job_id>` — per-job result stream. Worker `XADD`s
//!   `ResultEnvelope` frames; clients `XREAD` until a `Finished` frame arrives.
//!
//! Consumer groups give us at-least-once delivery + automatic load balancing:
//! every worker picks one entry. Worker-side failure handling: dropped units
//! (worker died mid-task without ACK) stay in the pending-entry list and can
//! be re-claimed via `XCLAIM` by any other consumer in the group. A dedicated
//! supervisor that periodically rescues stale entries isn't shipped — operators
//! rely on Redis' built-in PEL inspection for now.

use std::collections::BTreeMap;
use std::time::Duration;

use redis::streams::{StreamReadOptions, StreamReadReply};
use redis::AsyncCommands;
use tokio::sync::mpsc;

use secator_exec::wire::{now_secs, ResultEnvelope, WorkUnit};
use secator_model::OutputItem;

/// Default Redis Stream name for the task queue. Configurable via `RedisTransport::with_units_stream`.
pub const DEFAULT_UNITS_STREAM: &str = "secator:units";
/// Default consumer group name used by workers.
pub const DEFAULT_GROUP: &str = "secator-workers";

/// Pull a UTF-8 string out of whatever `redis::Value` variant the server returned
/// for an `XREAD`/`XREADGROUP` field. Redis 0.27 uses `BulkString`/`SimpleString`.
fn redis_value_to_string(v: &redis::Value) -> Option<String> {
    match v {
        redis::Value::BulkString(b) => std::str::from_utf8(b).ok().map(String::from),
        redis::Value::SimpleString(s) => Some(s.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub enum RedisError {
    Connect(String),
    Send(String),
    Recv(String),
    Decode(String),
    Worker(String),
}

impl std::fmt::Display for RedisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedisError::Connect(s) => write!(f, "redis connect: {s}"),
            RedisError::Send(s) => write!(f, "redis send: {s}"),
            RedisError::Recv(s) => write!(f, "redis recv: {s}"),
            RedisError::Decode(s) => write!(f, "redis decode: {s}"),
            RedisError::Worker(s) => write!(f, "worker error: {s}"),
        }
    }
}
impl std::error::Error for RedisError {}

impl From<redis::RedisError> for RedisError {
    fn from(e: redis::RedisError) -> Self { RedisError::Send(e.to_string()) }
}

/// Client-side Redis transport: enqueue WorkUnits, tail their result streams.
#[derive(Clone)]
pub struct RedisTransport {
    client: redis::Client,
    units_stream: String,
    poll_block_ms: u64,
}

impl RedisTransport {
    /// Open a transport against `url` (e.g. `redis://127.0.0.1:6379/0`).
    pub fn open(url: &str) -> Result<Self, RedisError> {
        let client = redis::Client::open(url).map_err(|e| RedisError::Connect(e.to_string()))?;
        Ok(RedisTransport {
            client,
            units_stream: DEFAULT_UNITS_STREAM.into(),
            poll_block_ms: 500,
        })
    }

    pub fn with_units_stream(mut self, name: impl Into<String>) -> Self {
        self.units_stream = name.into();
        self
    }

    pub fn with_poll_block_ms(mut self, ms: u64) -> Self {
        self.poll_block_ms = ms;
        self
    }

    /// Health probe (`PING`). Returns `true` if Redis is reachable.
    pub async fn ping(&self) -> bool {
        match self.client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let r: redis::RedisResult<String> =
                    redis::cmd("PING").query_async(&mut conn).await;
                r.is_ok()
            }
            Err(_) => false,
        }
    }

    /// Submit a unit + tail its result stream until the Finished frame arrives.
    /// Mirrors `FileTransport::execute_task`.
    pub async fn execute_task(
        &self,
        task_class: &str,
        inputs: Vec<String>,
        opts: BTreeMap<String, String>,
        reports_folder: Option<std::path::PathBuf>,
        tx: mpsc::Sender<OutputItem>,
    ) -> Result<String, RedisError> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let unit = WorkUnit {
            job_id: job_id.clone(),
            unit_id: uuid::Uuid::new_v4().to_string(),
            task_class: task_class.to_string(),
            inputs,
            opts,
            reports_folder: reports_folder.map(|p| p.to_string_lossy().into_owned()),
            submitted_at: now_secs(),
        };
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let payload = serde_json::to_string(&unit)
            .map_err(|e| RedisError::Send(format!("encode: {e}")))?;
        let _: String = conn
            .xadd(&self.units_stream, "*", &[("unit", payload)])
            .await
            .map_err(RedisError::from)?;
        secator_debug::debug!("redis", "submitted unit job_id={job_id} class={task_class}");
        self.tail_results(&job_id, tx).await
    }

    /// Tail `secator:results:<job_id>` and dispatch frames to `tx`.
    async fn tail_results(
        &self,
        job_id: &str,
        tx: mpsc::Sender<OutputItem>,
    ) -> Result<String, RedisError> {
        let stream = format!("secator:results:{job_id}");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let mut last_id = "0".to_string();
        let last_status = String::from("UNKNOWN");
        let opts = StreamReadOptions::default().block(self.poll_block_ms as usize);
        loop {
            let reply: StreamReadReply = conn
                .xread_options(&[&stream], &[&last_id], &opts)
                .await
                .map_err(|e| RedisError::Recv(e.to_string()))?;
            if reply.keys.is_empty() {
                continue;
            }
            for key in reply.keys {
                for entry in key.ids {
                    last_id = entry.id.clone();
                    let payload = entry.map.get("frame").and_then(redis_value_to_string);
                    let Some(s) = payload else { continue };
                    let env: ResultEnvelope = match serde_json::from_str(&s) {
                        Ok(e) => e,
                        Err(e) => {
                            return Err(RedisError::Decode(e.to_string()));
                        }
                    };
                    match env {
                        ResultEnvelope::Started { .. } => {}
                        ResultEnvelope::Item { value } => {
                            if let serde_json::Value::Object(map) = value {
                                if let Some(item) = OutputItem::from_map(
                                    &map,
                                    &secator_model::OutputMap::new(),
                                ) {
                                    if tx.send(item).await.is_err() {
                                        return Ok(last_status);
                                    }
                                }
                            }
                        }
                        ResultEnvelope::Finished { status, .. } => {
                            secator_debug::debug!("redis", "job {job_id} finished status={status}");
                            return Ok(status);
                        }
                        ResultEnvelope::WorkerError { message, .. } => {
                            return Err(RedisError::Worker(message));
                        }
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------- Worker side

/// Server-side helper — pull WorkUnits off the stream via a consumer group.
pub struct RedisWorker {
    client: redis::Client,
    units_stream: String,
    group: String,
    consumer: String,
    block_ms: usize,
}

impl RedisWorker {
    pub fn new(url: &str, consumer_name: impl Into<String>) -> Result<Self, RedisError> {
        let client = redis::Client::open(url).map_err(|e| RedisError::Connect(e.to_string()))?;
        Ok(RedisWorker {
            client,
            units_stream: DEFAULT_UNITS_STREAM.into(),
            group: DEFAULT_GROUP.into(),
            consumer: consumer_name.into(),
            block_ms: 0,
        })
    }

    /// Idempotent — `XGROUP CREATE` is safe to call repeatedly thanks to `MKSTREAM`.
    pub async fn ensure_group(&self) -> Result<(), RedisError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let res: Result<String, redis::RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.units_stream)
            .arg(&self.group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;
        match res {
            Ok(_) => Ok(()),
            // BUSYGROUP = group already exists, which is what we want.
            Err(e) if e.to_string().contains("BUSYGROUP") => Ok(()),
            Err(e) => Err(RedisError::Send(e.to_string())),
        }
    }

    /// Pull one WorkUnit (blocks until a unit appears or `block_ms` elapses).
    pub async fn pull(&self) -> Result<Option<(String, WorkUnit)>, RedisError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(1)
            .block(self.block_ms);
        let reply: StreamReadReply = conn
            .xread_options(&[&self.units_stream], &[">"], &opts)
            .await
            .map_err(|e| RedisError::Recv(e.to_string()))?;
        for key in reply.keys {
            for entry in key.ids {
                let payload = entry.map.get("unit").and_then(redis_value_to_string);
                if let Some(s) = payload {
                    let unit: WorkUnit = serde_json::from_str(&s)
                        .map_err(|e| RedisError::Decode(e.to_string()))?;
                    secator_debug::debug!("redis.worker", "pulled job_id={} unit_id={}", unit.job_id, unit.unit_id);
                    return Ok(Some((entry.id, unit)));
                }
            }
        }
        Ok(None)
    }

    /// Ack a delivered entry (Python Celery's ack-after-process).
    pub async fn ack(&self, entry_id: &str) -> Result<(), RedisError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let _: i64 = conn
            .xack(&self.units_stream, &self.group, &[entry_id])
            .await
            .map_err(RedisError::from)?;
        Ok(())
    }

    /// Append a `ResultEnvelope` frame to `secator:results:<job_id>`.
    pub async fn emit(&self, job_id: &str, env: &ResultEnvelope) -> Result<(), RedisError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| RedisError::Connect(e.to_string()))?;
        let payload = serde_json::to_string(env)
            .map_err(|e| RedisError::Send(format!("encode: {e}")))?;
        let _: String = conn
            .xadd(format!("secator:results:{job_id}"), "*", &[("frame", payload)])
            .await
            .map_err(RedisError::from)?;
        Ok(())
    }
}

/// Drain `secator:results:<job_id>` from `start_id` until a terminal frame.
/// Used by tests + by the `secator worker tail` subcommand.
pub async fn drain_results(
    url: &str,
    job_id: &str,
    timeout: Duration,
) -> Result<Vec<ResultEnvelope>, RedisError> {
    let client = redis::Client::open(url).map_err(|e| RedisError::Connect(e.to_string()))?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| RedisError::Connect(e.to_string()))?;
    let stream = format!("secator:results:{job_id}");
    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    let mut last_id = "0".to_string();
    while std::time::Instant::now() < deadline {
        let opts = StreamReadOptions::default().block(100);
        let reply: StreamReadReply = conn
            .xread_options(&[&stream], &[&last_id], &opts)
            .await
            .map_err(|e| RedisError::Recv(e.to_string()))?;
        for key in reply.keys {
            for entry in key.ids {
                last_id = entry.id.clone();
                let s = entry.map.get("frame").and_then(redis_value_to_string);
                let Some(s) = s else { continue };
                let env: ResultEnvelope = serde_json::from_str(&s)
                    .map_err(|e| RedisError::Decode(e.to_string()))?;
                let terminal = matches!(env, ResultEnvelope::Finished { .. } | ResultEnvelope::WorkerError { .. });
                out.push(env);
                if terminal {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: skip if no Redis available (CI without redis-server should pass).
    async fn redis_available() -> Option<RedisTransport> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".into());
        let t = RedisTransport::open(&url).ok()?;
        if t.ping().await { Some(t) } else { None }
    }

    #[tokio::test]
    async fn open_with_invalid_url_returns_error() {
        let err = RedisTransport::open("not-a-url");
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn ping_without_server_returns_false() {
        // Port 1 is reserved / nothing listens there.
        let t = RedisTransport::open("redis://127.0.0.1:1/0").unwrap();
        assert!(!t.ping().await);
    }

    #[tokio::test]
    async fn end_to_end_unit_and_result_when_redis_available() {
        let Some(t) = redis_available().await else {
            eprintln!("skipping: no redis server available");
            return;
        };
        // Spin up a fake worker: pull the unit, ack, emit Started+Finished, then return.
        let consumer = format!("test-{}", uuid::Uuid::new_v4());
        let worker = RedisWorker::new(
            &std::env::var("REDIS_URL").unwrap_or("redis://127.0.0.1:6379/0".into()),
            consumer,
        )
        .unwrap();
        worker.ensure_group().await.unwrap();

        // Spawn the worker loop.
        let h = tokio::spawn(async move {
            // Wait briefly to be sure the client has XADD'd.
            if let Ok(Some((id, unit))) = worker.pull().await {
                worker
                    .emit(
                        &unit.job_id,
                        &ResultEnvelope::Started { worker_id: "test-worker".into() },
                    )
                    .await
                    .unwrap();
                worker
                    .emit(
                        &unit.job_id,
                        &ResultEnvelope::Finished {
                            worker_id: "test-worker".into(),
                            status: "SUCCESS".into(),
                            findings: 0,
                            errors: 0,
                            elapsed_seconds: 0.01,
                        },
                    )
                    .await
                    .unwrap();
                worker.ack(&id).await.unwrap();
                Some(unit.job_id)
            } else {
                None
            }
        });

        // Client side: submit + tail.
        let (tx, mut rx) = mpsc::channel::<OutputItem>(8);
        let status = t
            .execute_task("noop", vec![], BTreeMap::new(), None, tx)
            .await;
        assert!(status.is_ok(), "execute_task returned {:?}", status);
        let _ = h.await;
        // No items were emitted (worker only Started + Finished).
        assert!(rx.try_recv().is_err());
    }
}
