//! Worker daemon: pulls `WorkUnit`s from a [`FileBroker`], runs them through a
//! `CommandRunner`, and streams typed results back over the broker's per-job JSONL
//! channel. Mirrors Python `secator worker` / Celery worker semantics.
//!
//! Pure library — the binary entry point lives in `secator-cli`'s `worker` subcommand
//! so a single `secator` binary serves both the client and the daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use secator_exec::broker::FileBroker;
use secator_exec::wire::{ControlMsg, ResultEnvelope, WorkUnit};
use secator_exec::TaskLookup;
use secator_metrics::Metrics;
use secator_model::OutputItem;
use secator_runner::CommandRunner;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub enum WorkerError {
    Broker(String),
}
impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Broker(s) => write!(f, "worker broker: {s}"),
        }
    }
}
impl std::error::Error for WorkerError {}

/// Tuneable knobs (Python `--concurrency`, `--id`, plus a handful of dev knobs).
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub id: String,
    /// Number of parallel claim+process loops (each one handles a unit at a time).
    pub concurrency: usize,
    /// How often the heartbeat sentinel is touched.
    pub heartbeat_interval: Duration,
    /// How often the poll loop scans `tasks/` when no work is pending.
    pub poll_interval: Duration,
    /// Maximum wall time a single task may run before being killed (Python
    /// `transport.task_max_timeout`). `None` ⇒ unlimited.
    pub task_max_timeout: Option<Duration>,
    /// Recycle the worker after handling this many tasks (Python
    /// `transport.worker_max_tasks_per_child`, default 20). `None` ⇒ never.
    pub worker_max_tasks_per_child: Option<u64>,
    /// Self-exit after this long with no work claimed (Python
    /// `transport.worker_kill_after_idle_seconds`). `None` ⇒ never.
    pub worker_kill_after_idle: Option<Duration>,
    /// Subprocess RSS ceiling — over this and the runner kills the child
    /// (Python `transport.task_memory_limit_mb`). `None` ⇒ unlimited.
    pub task_memory_limit_mb: Option<u64>,
}
impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig {
            id: format!("worker-{}", uuid::Uuid::new_v4().simple()),
            concurrency: 4,
            heartbeat_interval: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
            task_max_timeout: None,
            worker_max_tasks_per_child: None,
            worker_kill_after_idle: None,
            task_memory_limit_mb: None,
        }
    }
}

/// The worker. Hold a strong reference to it on the main task; call `run()` and `.await`.
pub struct Worker {
    pub config: WorkerConfig,
    pub broker: FileBroker,
    pub lookup: Arc<dyn TaskLookup>,
    /// Optional Prometheus metrics sink — None when `--metrics-addr` isn't set.
    pub metrics: Option<Arc<Metrics>>,
    /// Number of tasks this worker has processed since start. Bumped after
    /// each `process_unit`. Drives `worker_max_tasks_per_child`.
    processed_tasks: std::sync::atomic::AtomicU64,
    /// Unix seconds of the last time a unit was claimed (or the worker started).
    /// Drives `worker_kill_after_idle`.
    last_active: std::sync::atomic::AtomicU64,
    /// Set by the recycle/idle watchdog when the worker should stop on its own.
    self_shutdown: std::sync::atomic::AtomicBool,
}

impl Worker {
    pub fn new(broker: FileBroker, lookup: Arc<dyn TaskLookup>, config: WorkerConfig) -> Self {
        Worker {
            config,
            broker,
            lookup,
            metrics: None,
            processed_tasks: std::sync::atomic::AtomicU64::new(0),
            last_active: std::sync::atomic::AtomicU64::new(now_secs()),
            self_shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Attach a metrics sink — the CLI calls this after binding the metrics
    /// HTTP server so the worker can increment counters as jobs flow through.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Drive the heartbeat + N claim loops until the supplied shutdown signal
    /// fires OR the worker decides to recycle itself (max-tasks / idle-timeout).
    pub async fn run<F>(self, shutdown: F) -> Result<(), WorkerError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let shared = Arc::new(self);
        let hb = spawn_heartbeat(shared.clone());
        let watchdog = spawn_recycle_watchdog(shared.clone());
        let mut loops: Vec<JoinHandle<()>> = (0..shared.config.concurrency)
            .map(|i| spawn_poll_loop(shared.clone(), i))
            .collect();

        // Race the operator's shutdown signal against our own self-shutdown flag
        // (max-tasks-per-child or idle-timeout reached). Either way we cancel
        // the loops cleanly.
        let self_done = wait_for_self_shutdown(shared.clone());
        tokio::pin!(self_done);
        let shutdown = async move { shutdown.await };
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {}
            _ = &mut self_done => {}
        }

        hb.abort();
        watchdog.abort();
        for h in loops.drain(..) {
            h.abort();
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn wait_for_self_shutdown(worker: Arc<Worker>) {
    while !worker
        .self_shutdown
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Periodic check: if `worker_kill_after_idle` is set and there's been no
/// activity within that window, flip the self-shutdown flag. `Worker::run`
/// awaits this flag and cleans up.
fn spawn_recycle_watchdog(worker: Arc<Worker>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let idle = match worker.config.worker_kill_after_idle {
            Some(d) if d.as_secs() > 0 => d,
            _ => return,
        };
        // Check every (idle/4).max(1s) — granular enough for typical 30s+ idle.
        let tick = Duration::from_secs((idle.as_secs() / 4).max(1));
        loop {
            tokio::time::sleep(tick).await;
            let last = worker
                .last_active
                .load(std::sync::atomic::Ordering::Relaxed);
            if now_secs().saturating_sub(last) >= idle.as_secs() {
                eprintln!(
                    "[INF] {} self-shutdown: idle for >= {} seconds",
                    worker.config.id,
                    idle.as_secs(),
                );
                worker
                    .self_shutdown
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }
    })
}

fn spawn_heartbeat(worker: Arc<Worker>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = worker.broker.heartbeat(&worker.config.id);
            tokio::time::sleep(worker.config.heartbeat_interval).await;
        }
    })
}

fn spawn_poll_loop(worker: Arc<Worker>, slot: usize) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Honor `worker_max_tasks_per_child` + the watchdog's self-shutdown
            // flag. Loops exit cleanly so `Worker::run`'s `select!` can clean
            // up the other side.
            if worker
                .self_shutdown
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(cap) = worker.config.worker_max_tasks_per_child {
                if worker
                    .processed_tasks
                    .load(std::sync::atomic::Ordering::Relaxed)
                    >= cap
                {
                    eprintln!(
                        "[INF] {} self-shutdown: processed >= {} tasks",
                        worker.config.id, cap,
                    );
                    worker
                        .self_shutdown
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }

            // List pending and try to claim one. If nothing, back off.
            let pending = match worker.broker.list_pending() {
                Ok(p) => p,
                Err(_) => {
                    tokio::time::sleep(worker.config.poll_interval).await;
                    continue;
                }
            };
            if pending.is_empty() {
                tokio::time::sleep(worker.config.poll_interval).await;
                continue;
            }
            let mut claimed_one = false;
            for path in pending {
                match worker.broker.claim(&path, &worker.config.id) {
                    Ok(Some((claimed_path, unit))) => {
                        claimed_one = true;
                        worker
                            .last_active
                            .store(now_secs(), std::sync::atomic::Ordering::Relaxed);
                        process_unit(&worker, slot, claimed_path, unit).await;
                        worker
                            .processed_tasks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        worker
                            .last_active
                            .store(now_secs(), std::sync::atomic::Ordering::Relaxed);
                        break; // back to outer poll loop after each unit
                    }
                    Ok(None) => continue, // race lost; try next file
                    Err(_) => continue,
                }
            }
            if !claimed_one {
                tokio::time::sleep(worker.config.poll_interval).await;
            }
        }
    })
}

async fn process_unit(worker: &Worker, _slot: usize, claimed_path: PathBuf, unit: WorkUnit) {
    let worker_id = worker.config.id.clone();
    let job_id = unit.job_id.clone();

    // Look up the task class. Treat a miss as a benign SKIPPED — same UX as the
    // local executor's "skipped X: unknown task class" Info line. Surfacing this as a
    // WorkerError would flip the entire workflow to FAILURE, which is wrong when the
    // workflow tolerates missing tools (Python parity).
    let spec = match worker.lookup.find(&unit.task_class) {
        Some(s) => s,
        None => {
            let _ = worker.broker.append_result(
                &job_id,
                &ResultEnvelope::Started { worker_id: worker_id.clone() },
            );
            let info_item = OutputItem::Info(secator_model::Info {
                message: format!("skipped {}: unknown task class", unit.task_class),
                ..Default::default()
            });
            let _ = worker.broker.append_result(
                &job_id,
                &ResultEnvelope::Item { value: serde_json::Value::Object(info_item.to_map()) },
            );
            let _ = worker.broker.append_result(
                &job_id,
                &ResultEnvelope::Finished {
                    worker_id: worker_id.clone(),
                    status: "SKIPPED".into(),
                    findings: 0,
                    errors: 0,
                    elapsed_seconds: 0.0,
                },
            );
            eprintln!(
                "[INF] {} skipped {} (unknown task class)",
                worker_id, unit.task_class,
            );
            let _ = worker.broker.ack(&claimed_path);
            return;
        }
    };

    // Announce on stderr (operator-facing) + on the results stream (client-facing).
    eprintln!(
        "[INF] {} picked up {} job {} ({} input{})",
        worker_id,
        unit.task_class,
        job_id,
        unit.inputs.len(),
        if unit.inputs.len() == 1 { "" } else { "s" },
    );
    let _ = worker.broker.append_result(
        &job_id,
        &ResultEnvelope::Started { worker_id: worker_id.clone() },
    );

    // Build the runner from the unit's payload.
    let mut runner = CommandRunner::new(spec, unit.inputs.clone());
    runner.opts = unit.opts.clone();
    if let Some(rf) = &unit.reports_folder {
        runner.reports_folder = Some(PathBuf::from(rf));
    }

    // (cmd echo emitted from inside `CommandRunner::run_one_chunk` — per chunk so
    //  `break_task`-style chunked tasks (e.g. `search_vulns`) print one `⚡ <cmd>`
    //  line per subprocess invocation.)

    // Drain the runner's mpsc, count + append each item to the results stream.
    let (tx, mut rx) = mpsc::channel::<OutputItem>(64);
    let broker_clone = worker.broker.clone();
    let job_for_streamer = job_id.clone();
    let metrics_for_streamer = worker.metrics.clone();
    let streamer: JoinHandle<(u32, u32)> = tokio::spawn(async move {
        let mut findings = 0u32;
        let mut errors = 0u32;
        while let Some(item) = rx.recv().await {
            if matches!(item, OutputItem::Error(_)) { errors += 1; }
            if item.is_finding() {
                findings += 1;
                if let Some(m) = &metrics_for_streamer {
                    m.inc_finding(item.type_name());
                }
            }
            let env = ResultEnvelope::Item {
                value: serde_json::Value::Object(item.to_map()),
            };
            let _ = broker_clone.append_result(&job_for_streamer, &env);
        }
        (findings, errors)
    });

    // Run the task (own loop drives the subprocess). If a `task_max_timeout`
    // is configured, race the run against a `tokio::time::timeout` — on the
    // deadline we drop the runner future, which kills the subprocess via
    // `tokio::process::Child::Drop`. The streamer task ends because `tx`
    // (held only by `runner.run`) is dropped, and we surface the timeout as
    // a synthetic Error item before flipping the run to FAILURE.
    let start = Instant::now();
    let timed_out = if let Some(deadline) = worker.config.task_max_timeout {
        match tokio::time::timeout(deadline, runner.run(tx)).await {
            Ok(_) => false,
            Err(_) => {
                let _ = worker.broker.append_result(
                    &job_id,
                    &ResultEnvelope::Item {
                        value: serde_json::Value::Object(
                            OutputItem::Error(secator_model::Error {
                                message: format!(
                                    "task {} killed after {:.0}s (task_max_timeout)",
                                    unit.task_class,
                                    deadline.as_secs_f64(),
                                ),
                                ..Default::default()
                            })
                            .to_map(),
                        ),
                    },
                );
                true
            }
        }
    } else {
        let _ = runner.run(tx).await;
        false
    };
    let (findings, errors) = streamer.await.unwrap_or((0, 0));
    let elapsed = start.elapsed().as_secs_f64();
    let errors = if timed_out { errors + 1 } else { errors };

    // Check for an out-of-band revoke that arrived during the run.
    let revoked = matches!(worker.broker.control_pending(&job_id), Some(ControlMsg::Revoke));
    if revoked {
        worker.broker.ack_control(&job_id, ControlMsg::Revoke);
    }

    let status = if revoked {
        "REVOKED"
    } else if timed_out || errors > 0 {
        "FAILURE"
    } else {
        "SUCCESS"
    };
    let _ = worker.broker.append_result(
        &job_id,
        &ResultEnvelope::Finished {
            worker_id: worker_id.clone(),
            status: status.to_string(),
            findings,
            errors,
            elapsed_seconds: elapsed,
        },
    );
    // Record into the Prometheus registry when one is attached.
    if let Some(m) = &worker.metrics {
        m.inc_task(&unit.task_class, status);
        m.observe_task_seconds(&unit.task_class, elapsed);
        m.inc_errors(errors as u64);
    }
    eprintln!(
        "[INF] {} finished {} (status={status}, findings={findings}, errors={errors}, elapsed={elapsed:.2}s)",
        worker_id, unit.task_class,
    );

    let _ = worker.broker.ack(&claimed_path);
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;
    use secator_exec::FileTransport;
    use secator_options::{FileMode, InputWiring, SingleMode};
    use secator_runner::{
        empty_output_maps, empty_schema, HookRegistry, ItemLoader, TaskSpec, ValidatorRegistry,
    };
    use std::collections::BTreeMap;
    use std::time::Duration;

    /// A fake task that emits two `Subdomain`s and exits — no external binary needed.
    static TEST_TASK: TaskSpec = TaskSpec {
        name: "echo-task",
        description: "test",
        cmd: r#"printf '%s\n' '{"host":"a.example.com","domain":"example.com"}' '{"host":"b.example.com","domain":"example.com"}'"#,
        input_types: &["host"],
        output_types: &["subdomain"],
        tags: &[],
        json_flag: None,
        input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Arg },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None,
        on_regex_loaded: None,
        output_maps: empty_output_maps,
        discriminator: None,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: secator_runner::InstallSpec::EMPTY,
        proxy_caps: secator_runner::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    struct OneTaskLookup;
    impl TaskLookup for OneTaskLookup {
        fn find(&self, name: &str) -> Option<&'static TaskSpec> {
            if name == TEST_TASK.name { Some(&TEST_TASK) } else { None }
        }
    }

    /// Full round-trip: spawn a Worker, run a FileTransport against the same broker
    /// dir, assert the two Subdomain items come back on the client's channel and the
    /// run ends with SUCCESS.
    #[tokio::test]
    async fn worker_round_trip_with_file_transport() {
        let base = std::env::temp_dir().join(format!("secator-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let broker = FileBroker::new(&base).unwrap();

        // Spawn the worker (use a small concurrency so the test runs fast).
        let lookup: Arc<dyn TaskLookup> = Arc::new(OneTaskLookup);
        let cfg = WorkerConfig {
            id: "test-worker".into(),
            concurrency: 1,
            heartbeat_interval: Duration::from_secs(60), // irrelevant for this test
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let worker = Worker::new(broker, lookup, cfg);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let worker_handle = tokio::spawn(async move {
            let _ = worker.run(async move {
                let _ = shutdown_rx.await;
            }).await;
        });

        // Client submits + tails.
        let ft = FileTransport::open(base.clone()).unwrap();
        let (tx, mut rx) = mpsc::channel::<OutputItem>(16);
        let status = ft
            .execute_task("echo-task", vec!["example.com".into()], BTreeMap::new(), None, tx)
            .await
            .expect("execute_task");
        assert_eq!(status, "SUCCESS");

        // Drain any items that landed on the channel.
        let mut got = Vec::new();
        while let Ok(Some(item)) =
            tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        {
            got.push(item);
        }
        assert_eq!(got.len(), 2, "expected 2 subdomains, got {got:?}");

        // Tell the worker to stop.
        let _ = shutdown_tx.send(());
        // Worker run() returns when the shutdown future resolves.
        let _ = tokio::time::timeout(Duration::from_secs(2), worker_handle).await;

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A spec that sleeps long enough to trip a 250ms `task_max_timeout`.
    /// The sleep is invoked via `sh -c` because the runner shells out for cmd
    /// composition; killing the parent (`sh`) takes `sleep` with it (Drop on
    /// `tokio::process::Child`).
    static SLEEP_TASK: TaskSpec = TaskSpec {
        name: "sleep-task",
        description: "sleeps 3s",
        cmd: r#"sh -c 'sleep 3'"#,
        input_types: &["host"],
        output_types: &["subdomain"],
        tags: &[],
        json_flag: None,
        input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Arg },
        item_loaders: &[],
        input_chunk_size: 0,
        on_json_loaded: None,
        on_regex_loaded: None,
        output_maps: empty_output_maps,
        discriminator: None,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: secator_runner::InstallSpec::EMPTY,
        proxy_caps: secator_runner::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };
    struct SleepLookup;
    impl TaskLookup for SleepLookup {
        fn find(&self, name: &str) -> Option<&'static TaskSpec> {
            if name == SLEEP_TASK.name { Some(&SLEEP_TASK) } else { None }
        }
    }

    /// P4 — task_max_timeout: a slow task is killed after the deadline and the
    /// envelope ends with FAILURE.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn task_max_timeout_kills_slow_task() {
        let base = std::env::temp_dir()
            .join(format!("secator-tmt-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&base);
        let broker = FileBroker::new(&base).unwrap();

        let cfg = WorkerConfig {
            id: "tmt-worker".into(),
            concurrency: 1,
            heartbeat_interval: Duration::from_secs(60),
            poll_interval: Duration::from_millis(10),
            task_max_timeout: Some(Duration::from_millis(250)),
            ..Default::default()
        };
        let worker = Worker::new(broker, Arc::new(SleepLookup) as Arc<dyn TaskLookup>, cfg);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let worker_handle = tokio::spawn(async move {
            let _ = worker.run(async move { let _ = shutdown_rx.await; }).await;
        });

        let ft = FileTransport::open(base.clone()).unwrap();
        let (tx, mut rx) = mpsc::channel::<OutputItem>(16);
        let started = std::time::Instant::now();
        let status = ft
            .execute_task("sleep-task", vec!["example.com".into()], BTreeMap::new(), None, tx)
            .await
            .expect("execute_task");
        let elapsed = started.elapsed();
        // Drain any leftover items so the test doesn't hang in CI.
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {}
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), worker_handle).await;
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(status, "FAILURE", "timed-out task should report FAILURE");
        assert!(
            elapsed < Duration::from_secs(2),
            "task should have been killed under 2s; took {elapsed:?}",
        );
    }

    /// P4 — worker_max_tasks_per_child: once the cap is hit the worker
    /// flips its self-shutdown flag and `run()` returns even without an
    /// external shutdown signal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_max_tasks_per_child_recycles() {
        let base = std::env::temp_dir()
            .join(format!("secator-mtpc-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&base);
        let broker = FileBroker::new(&base).unwrap();

        let cfg = WorkerConfig {
            id: "mtpc-worker".into(),
            concurrency: 1,
            heartbeat_interval: Duration::from_secs(60),
            poll_interval: Duration::from_millis(5),
            worker_max_tasks_per_child: Some(2),
            ..Default::default()
        };
        let worker = Worker::new(broker, Arc::new(OneTaskLookup) as Arc<dyn TaskLookup>, cfg);
        let worker_handle = tokio::spawn(async move {
            let _ = worker
                .run(async { std::future::pending::<()>().await })
                .await;
        });

        // Submit 2 jobs — worker should chew through them, then self-shutdown.
        let ft = FileTransport::open(base.clone()).unwrap();
        for _ in 0..2 {
            let (tx, _rx) = mpsc::channel::<OutputItem>(8);
            ft.execute_task("echo-task", vec!["example.com".into()], BTreeMap::new(), None, tx)
                .await
                .expect("execute_task");
        }

        // run() should return on its own (no external shutdown) within a couple
        // seconds — the watchdog polls every 200ms.
        let result = tokio::time::timeout(Duration::from_secs(5), worker_handle).await;
        let _ = std::fs::remove_dir_all(&base);
        assert!(result.is_ok(), "worker run() must return after hitting max-tasks");
    }
}
