//! Execution engine + `Transport` (local + remote).
//!
//! Maps to Python `secator/celery.py`. Walks a `Plan` from `secator-dag`, instantiates
//! `CommandRunner`s for each `Task` node, resolves inputs/opts via extractors over the
//! accumulated results, and streams typed items onto a `ResultSink`. Two transports:
//!
//! - [`LocalTransport`] — in-process Tokio executor (zero infra, the reference behavior).
//! - [`FileTransport`] — file-broker-backed client side; submits to a worker over a
//!   shared directory and tails the JSONL results stream. Worker daemon lives in
//!   `secator-worker`.

pub mod broker;
pub mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use secator_dag::{resolve_inputs, resolve_opts, Plan, TaskPlan};
use secator_expr::{eval_bool, Scope, Value as ExprValue};
use secator_model::{Info, OutputItem, State};
use secator_runner::{CommandRunner, NativeRunner, NativeSpec, ResultSink, TaskSpec};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;

// ----------------------------------------------------------------------- Lookup

/// How the executor finds a registered task SPEC by class name. Provided by the CLI so
/// the executor doesn't depend on `secator-tasks` (decoupling: any task catalog works).
pub trait TaskLookup: Send + Sync {
    fn find(&self, name: &str) -> Option<&'static TaskSpec>;
    /// Look up a native (in-process) spec by name. Default impl returns None so
    /// existing implementors stay backwards-compatible.
    fn find_native(&self, _name: &str) -> Option<&'static NativeSpec> { None }
}

/// A simple static-table lookup that holds both command and native specs.
pub struct StaticLookup {
    specs: Vec<&'static TaskSpec>,
    native_specs: Vec<&'static NativeSpec>,
}
impl StaticLookup {
    pub fn new(specs: Vec<&'static TaskSpec>) -> Self {
        StaticLookup { specs, native_specs: Vec::new() }
    }
    pub fn with_native(mut self, native_specs: Vec<&'static NativeSpec>) -> Self {
        self.native_specs = native_specs;
        self
    }
}
impl TaskLookup for StaticLookup {
    fn find(&self, name: &str) -> Option<&'static TaskSpec> {
        self.specs.iter().find(|s| s.name == name).copied()
    }
    fn find_native(&self, name: &str) -> Option<&'static NativeSpec> {
        self.native_specs.iter().find(|s| s.name == name).copied()
    }
}

// ----------------------------------------------------------------------- Transport

pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;
}

/// In-process plan executor. Walks chain/group edges sequentially (Celery-eager-mode
/// parity); a `remote` `FileTransport` can be attached so each task is submitted to a
/// worker over the broker instead of running in-process. Extractor evaluation +
/// result accumulation always run client-side regardless of routing.
pub struct LocalTransport {
    pub lookup: Arc<dyn TaskLookup>,
    /// When `Some`, every `TaskPlan` is submitted via the broker instead of executed
    /// in-process. The runner pipeline + reporting stays unchanged client-side.
    pub remote: Option<Arc<FileTransport>>,
    /// Propagates `--verbose` to every local `CommandRunner`. When false the
    /// subprocess's stderr is swallowed (default; Python parity).
    pub verbose: bool,
    /// Shared reports folder for every child task of this run. Each task's
    /// `CommandRunner.reports_folder` is set to this path so its `before_init`
    /// / `on_cmd` hooks can write output files under `<reports>/.outputs/`
    /// instead of falling back to `/tmp`. Mirrors Python where every child
    /// runner inherits the outer runner's `reports_folder`.
    pub reports_folder: Option<PathBuf>,
}
impl LocalTransport {
    pub fn new(lookup: Arc<dyn TaskLookup>) -> Self {
        LocalTransport { lookup, remote: None, verbose: false, reports_folder: None }
    }
    pub fn with_remote(mut self, ft: FileTransport) -> Self {
        self.remote = Some(Arc::new(ft));
        self
    }
    pub fn with_verbose(mut self, v: bool) -> Self {
        self.verbose = v;
        self
    }
    pub fn with_reports_folder(mut self, p: PathBuf) -> Self {
        self.reports_folder = Some(p);
        self
    }
    pub fn is_remote(&self) -> bool { self.remote.is_some() }
}
impl Transport for LocalTransport {
    fn name(&self) -> &'static str { "local" }
}

impl LocalTransport {
    /// Execute a plan and stream every typed result onto `tx`. Returns the accumulated
    /// results (also useful for downstream tests).
    pub async fn execute(
        &self,
        plan: &Plan,
        initial_inputs: Vec<String>,
        initial_opts: BTreeMap<String, ExprValue>,
        tx: ResultSink,
    ) -> Vec<OutputItem> {
        let mut results: Vec<OutputItem> = Vec::new();
        execute_node(
            plan,
            &initial_inputs,
            &initial_opts,
            self.lookup.as_ref(),
            self.remote.as_deref(),
            self.verbose,
            self.reports_folder.as_deref(),
            &tx,
            &mut results,
        ).await;
        results
    }
}

fn execute_node<'a>(
    node: &'a Plan,
    inputs: &'a [String],
    opts: &'a BTreeMap<String, ExprValue>,
    lookup: &'a dyn TaskLookup,
    remote: Option<&'a FileTransport>,
    verbose: bool,
    reports_folder: Option<&'a Path>,
    tx: &'a ResultSink,
    results: &'a mut Vec<OutputItem>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        match node {
            Plan::Chain(items) => {
                for item in items {
                    execute_node(item, inputs, opts, lookup, remote, verbose, reports_folder, tx, results).await;
                }
            }
            Plan::Group(items) => {
                // True parallel execution within a `_group` node (Python parity
                // with Celery's `group(...)`). Each branch collects into its own
                // `Vec<OutputItem>` so concurrent writes don't fight; after all
                // branches join, we splice the per-branch buffers into `results`
                // in declaration order so downstream extractors still see a
                // deterministic view. The shared `tx` channel sees every item
                // as it's produced, so the operator's live UI streams correctly.
                if items.len() <= 1 {
                    for item in items {
                        execute_node(item, inputs, opts, lookup, remote, verbose, reports_folder, tx, results).await;
                    }
                    return;
                }
                let mut branch_buffers: Vec<Vec<OutputItem>> =
                    (0..items.len()).map(|_| Vec::new()).collect();
                // `iter_mut` produces disjoint &mut references — exactly what
                // join_all needs to keep the borrow checker happy while still
                // letting every branch write its own results in parallel. The
                // future lifetime is inferred per call and is bounded by the
                // local block, not the outer `'a`.
                {
                    let join = futures_util::future::join_all(
                        items.iter().zip(branch_buffers.iter_mut()).map(|(item, buf)| {
                            execute_node(
                                item,
                                inputs,
                                opts,
                                lookup,
                                remote,
                                verbose,
                                reports_folder,
                                tx,
                                buf,
                            )
                        }),
                    );
                    join.await;
                }
                for buf in branch_buffers {
                    results.extend(buf);
                }
            }
            Plan::Task(tp) => {
                execute_task(tp, inputs, opts, lookup, remote, verbose, reports_folder, tx, results).await;
            }
        }
    })
}

async fn execute_task(
    tp: &TaskPlan,
    inputs: &[String],
    opts: &BTreeMap<String, ExprValue>,
    lookup: &dyn TaskLookup,
    remote: Option<&FileTransport>,
    verbose: bool,
    reports_folder: Option<&Path>,
    tx: &ResultSink,
    results: &mut Vec<OutputItem>,
) {
    // Three-layer merge: ancestor defaults (lowest) < parent runtime opts <
    // task's own static opts (highest). Python parity — `--pf passive` (a
    // runtime profile override) must beat a workflow's
    // `options.passive.default = false`. See B-WF-PASSIVE (#167).
    let mut merged: BTreeMap<String, ExprValue> = tp.ancestor_defaults.clone();
    for (k, v) in opts {
        merged.insert(k.clone(), v.clone());
    }
    for (k, v) in &tp.opts {
        merged.insert(k.clone(), v.clone());
    }
    merged = resolve_opts(tp, results, &merged);

    // Re-evaluate `if:` at exec time against the FULLY merged opts (Python parity)
    // — without this, `'nmap' in opts.scanners` would be evaluated against the
    // top-level CLI opts only, missing the workflow's `scanners: [nmap]` default.
    if let Some(cond) = &tp.condition {
        let mut scope = Scope::new();
        scope.set("opts", opts_to_value(&merged));
        scope.set(
            "targets",
            ExprValue::List(inputs.iter().cloned().map(ExprValue::Str).collect()),
        );
        if !eval_bool(cond, &scope).unwrap_or(true) {
            emit_skipped(tp, &format!("condition `{cond}` evaluated to false"), tx, results).await;
            return;
        }
    }

    let resolved_inputs = resolve_inputs(tp, results, &merged, inputs);
    if resolved_inputs.is_empty() {
        // skip-if-no-inputs (Python parity) — EXCEPT when the spec declares no
        // input_types (e.g. `arp`, `netdetect`, `prompt`). Those tasks read
        // ambient state (kernel ARP table, network interfaces, operator prompt)
        // and should run regardless of upstream output.
        let accepts_no_inputs = lookup
            .find(&tp.class)
            .map(|s| s.input_types.is_empty())
            .or_else(|| lookup.find_native(&tp.class).map(|s| s.input_types.is_empty()))
            .unwrap_or(false);
        if !accepts_no_inputs {
            emit_skipped(tp, "no inputs resolved", tx, results).await;
            return;
        }
    }

    // Route: remote → broker, local → CommandRunner. Both push items through the
    // same `sub_tx` so the post-task draining (tag + accumulate + forward to tx) is
    // shared between modes.
    let (sub_tx, mut sub_rx) = mpsc::channel::<OutputItem>(64);

    if let Some(ft) = remote {
        // Per-task remote execution. The worker handles spec lookup + subprocess.
        let task_class = tp.class.clone();
        let resolved_opts = opts_to_run_opts(&merged);
        let ft_clone = ft.clone();
        let inputs_for_remote = resolved_inputs.clone();
        let rf_for_remote = reports_folder.map(PathBuf::from);
        let handle = tokio::spawn(async move {
            ft_clone
                .execute_task(&task_class, inputs_for_remote, resolved_opts, rf_for_remote, sub_tx)
                .await
        });
        while let Some(mut item) = sub_rx.recv().await {
            tag_meta(&mut item, tp);
            results.push(item.clone());
            if tx.send(item).await.is_err() {
                break;
            }
        }
        if let Ok(Err(e)) = handle.await {
            let err_item = OutputItem::Error(secator_model::Error {
                message: format!("{}: {e}", tp.class),
                ..Default::default()
            });
            results.push(err_item.clone());
            let _ = tx.send(err_item).await;
        }
    } else {
        // In-process execution. Try the command spec first; if absent, fall
        // back to a native spec. Unknown task class → skip with an Info.
        if let Some(spec) = lookup.find(&tp.class) {
            let mut runner = CommandRunner::new(spec, resolved_inputs);
            runner.opts = opts_to_run_opts(&merged);
            runner.aliases = vec![tp.class.to_string()];
            runner.verbose = verbose;
            if let Some(rf) = reports_folder {
                runner.reports_folder = Some(rf.to_path_buf());
            }
            // Print the lifecycle "Task ... started" line (Python parity). The
            // description in parens is the YAML node's description when present,
            // else the SPEC's own description. The `⚡ <cmd>` echo is emitted from
            // inside the runner (per chunk) — Python `break_task` parity.
            let desc = tp.description.as_deref().unwrap_or(spec.description);
            let label = tp.id.split('.').next_back().unwrap_or(&tp.class);
            eprintln!("[INF] Task {label} ({desc}) started");
            let handle = tokio::spawn(async move { runner.run(sub_tx).await });
            while let Some(mut item) = sub_rx.recv().await {
                tag_meta(&mut item, tp);
                results.push(item.clone());
                if tx.send(item).await.is_err() {
                    break;
                }
            }
            let _ = handle.await;
        } else if let Some(nspec) = lookup.find_native(&tp.class) {
            let mut runner = NativeRunner::new(nspec, resolved_inputs);
            runner.opts = opts_to_run_opts(&merged);
            let desc = tp.description.as_deref().unwrap_or(nspec.description);
            let label = tp.id.split('.').next_back().unwrap_or(&tp.class);
            eprintln!("[INF] Task {label} ({desc}) started");
            let handle = tokio::spawn(async move { runner.run(sub_tx).await });
            while let Some(mut item) = sub_rx.recv().await {
                tag_meta(&mut item, tp);
                results.push(item.clone());
                if tx.send(item).await.is_err() {
                    break;
                }
            }
            let _ = handle.await;
        } else {
            emit_skipped(tp, &format!("unknown task class `{}`", tp.class), tx, results).await;
        }
    }
}

fn tag_meta(item: &mut OutputItem, tp: &TaskPlan) {
    let meta = item.meta_mut();
    if meta.source.is_empty() {
        meta.source = tp.class.clone();
    }
    if let Some(anc) = &tp.ancestor_id {
        meta.context.insert("ancestor_id".into(), JsonValue::String(anc.clone()));
    }
    meta.context.insert("node_id".into(), JsonValue::String(tp.id.clone()));
}

/// Emit the lifecycle items that mark a task as SKIPPED (gated `if:` failed,
/// no inputs resolved, or unknown task class). Drivers (Mongo, cloud API) need
/// to see these so the task lands in the database with the right status —
/// before this, gated tasks were silently dropped and Python's per-task
/// SKIPPED records had no Rust equivalent.
async fn emit_skipped(
    tp: &TaskPlan,
    reason: &str,
    tx: &ResultSink,
    results: &mut Vec<OutputItem>,
) {
    let mut info = OutputItem::Info(Info {
        message: format!("skipped {}: {reason}", tp.id),
        task_id: tp.id.clone(),
        ..Default::default()
    });
    tag_meta(&mut info, tp);
    let mut state = OutputItem::State(State {
        task_id: tp.id.clone(),
        state: "SKIPPED".into(),
        ..Default::default()
    });
    tag_meta(&mut state, tp);
    results.push(info.clone());
    results.push(state.clone());
    // Best-effort live emission. A closed receiver means the operator hit
    // Ctrl-C; nothing more we can do, but the items are already in `results`
    // so the post-run driver `on_run_end` still sees them.
    let _ = tx.send(info).await;
    let _ = tx.send(state).await;
}

fn opts_to_value(opts: &BTreeMap<String, ExprValue>) -> ExprValue {
    let map: BTreeMap<String, ExprValue> = opts.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    ExprValue::Map(map)
}

/// Best-effort conversion of typed opts back into the `String,String` map a
/// `CommandRunner` consumes. Lists are joined by comma (matches Python list-opt CLI flow).
fn opts_to_run_opts(opts: &BTreeMap<String, ExprValue>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in opts {
        let s = match v {
            ExprValue::Str(s) => s.clone(),
            ExprValue::Int(i) => i.to_string(),
            ExprValue::Float(f) => f.to_string(),
            ExprValue::Bool(b) => b.to_string(),
            ExprValue::Null => continue,
            ExprValue::List(items) => items
                .iter()
                .filter_map(|x| if let ExprValue::Str(s) = x { Some(s.clone()) } else { None })
                .collect::<Vec<_>>()
                .join(","),
            ExprValue::Map(_) => continue, // not representable as a single CLI value
        };
        out.insert(k.clone(), s);
    }
    out
}

// ----------------------------------------------------------------------- FileTransport

use std::time::Duration;

use crate::broker::{BrokerError, FileBroker};
use crate::wire::{ResultEnvelope, WorkUnit};
use secator_model::OutputMap;

/// Errors returned by `FileTransport::execute_task`.
#[derive(Debug)]
pub enum TransportError {
    Broker(String),
    Worker(String),
    Cancelled,
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Broker(s) => write!(f, "broker: {s}"),
            TransportError::Worker(s) => write!(f, "worker: {s}"),
            TransportError::Cancelled => write!(f, "cancelled"),
        }
    }
}
impl std::error::Error for TransportError {}
impl From<BrokerError> for TransportError {
    fn from(e: BrokerError) -> Self { TransportError::Broker(e.to_string()) }
}

/// Client-side transport backed by a [`FileBroker`]. Submits a single task as a
/// `WorkUnit`, then tails the per-job results stream and forwards typed items onto
/// the supplied `ResultSink`. Symmetrical with [`LocalTransport`] from the caller's
/// POV: same `tx` channel, items arrive live.
#[derive(Clone)]
pub struct FileTransport {
    pub broker: FileBroker,
    pub poll_interval: Duration,
}

impl FileTransport {
    pub fn open(base: PathBuf) -> Result<Self, BrokerError> {
        let broker = FileBroker::new(base)?;
        Ok(FileTransport { broker, poll_interval: Duration::from_millis(50) })
    }

    /// True if any worker has a fresh heartbeat — mirrors Python `is_celery_worker_alive`.
    pub fn worker_alive(&self) -> bool { self.broker.worker_alive() }

    /// Submit a single TaskPlan-equivalent unit, then stream its results live. Returns
    /// the finished status string ("SUCCESS"/"FAILURE") or an error.
    pub async fn execute_task(
        &self,
        task_class: &str,
        inputs: Vec<String>,
        opts: BTreeMap<String, String>,
        reports_folder: Option<PathBuf>,
        tx: ResultSink,
    ) -> Result<String, TransportError> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let unit = WorkUnit {
            job_id: job_id.clone(),
            unit_id: uuid::Uuid::new_v4().to_string(),
            task_class: task_class.to_string(),
            inputs,
            opts,
            reports_folder: reports_folder.map(|p| p.to_string_lossy().into_owned()),
            submitted_at: wire::now_secs(),
        };
        self.broker.enqueue(&unit)?;

        let mut tail = self.broker.tail_results(&job_id);
        let empty_map = OutputMap::new();
        let mut last_status = String::from("UNKNOWN");

        loop {
            let frames = tail.poll().map_err(TransportError::from)?;
            for env in frames {
                match env {
                    ResultEnvelope::Started { .. } => {}
                    ResultEnvelope::Item { value } => {
                        if let serde_json::Value::Object(map) = value {
                            if let Some(item) = OutputItem::from_map(&map, &empty_map) {
                                if tx.send(item).await.is_err() {
                                    // Receiver dropped; signal revoke and exit.
                                    let _ = self.broker.publish_control(&job_id, wire::ControlMsg::Revoke);
                                    return Ok(last_status);
                                }
                            }
                        }
                    }
                    ResultEnvelope::Finished { status, .. } => {
                        last_status = status;
                        return Ok(last_status);
                    }
                    ResultEnvelope::WorkerError { message, .. } => {
                        return Err(TransportError::Worker(message));
                    }
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Subdomain, Url};
    use secator_options::{FileMode, InputWiring, SingleMode};
    use secator_runner::{empty_output_maps, HookRegistry, ItemLoader, ValidatorRegistry};

    static FAKE_SUBFINDER: TaskSpec = TaskSpec {
        name: "fake-subfinder",
        description: "",
        cmd: r#"echo '{"host":"a.example.com","domain":"example.com"}'; echo '{"host":"b.example.com","domain":"example.com"}'"#,
        input_types: &["host"], output_types: &["subdomain"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Arg },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: secator_runner::empty_schema,
        install: secator_runner::InstallSpec::EMPTY,
        proxy_caps: secator_runner::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };
    /// Task that sleeps 200ms before emitting one subdomain — used by the
    /// Group-parallelism regression test to prove `_group` branches actually
    /// overlap (4× FAKE_SLEEP in sequence ≈ 800ms; in parallel ≈ 200ms).
    static FAKE_SLEEP: TaskSpec = TaskSpec {
        name: "fake-sleep",
        description: "",
        cmd: r#"sleep 0.2 && echo '{"host":"slept.example.com","domain":"example.com"}'"#,
        input_types: &["host"], output_types: &["subdomain"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Arg },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: secator_runner::empty_schema,
        install: secator_runner::InstallSpec::EMPTY,
        proxy_caps: secator_runner::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };
    static FAKE_HTTPX: TaskSpec = TaskSpec {
        name: "fake-httpx",
        description: "",
        // Read each input line and emit a Url JSON containing it. With FileMode::Arg
        // the runner appends the inputs file path → `sed '...' <file>`.
        cmd: r#"sed 's|.*|{"url":"https://&","status_code":200,"title":"x"}|'"#,
        input_types: &["host"], output_types: &["url"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Arg },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: secator_runner::empty_schema,
        install: secator_runner::InstallSpec::EMPTY,
        proxy_caps: secator_runner::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    fn lookup() -> Arc<dyn TaskLookup> {
        Arc::new(StaticLookup::new(vec![&FAKE_SUBFINDER, &FAKE_HTTPX, &FAKE_SLEEP]))
    }

    #[tokio::test]
    async fn single_task_plan_executes() {
        let plan = Plan::Task(TaskPlan {
            class: "fake-subfinder".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.fake-subfinder".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let local = LocalTransport::new(lookup());
        let (tx, mut rx) = mpsc::channel(16);
        let results = local.execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx).await;
        drop(rx.close());
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], OutputItem::Subdomain(_)));
    }

    #[tokio::test]
    async fn chain_forwards_results_via_extractor() {
        // subfinder -> httpx with targets_: subdomain.host
        let subfinder = Plan::Task(TaskPlan {
            class: "fake-subfinder".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.fake-subfinder".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let httpx = Plan::Task(TaskPlan {
            class: "fake-httpx".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.fake-httpx".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![secator_dag::Extractor {
                kind: "subdomain".into(),
                field: "host".into(),
                condition: None,
                group_by: None,
            }],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let plan = Plan::Chain(vec![subfinder, httpx]);
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(64);
        let results = local.execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx).await;
        // We expect 2 Subdomains + 2 Urls.
        let subs: Vec<&Subdomain> = results.iter().filter_map(|i| if let OutputItem::Subdomain(s) = i { Some(s) } else { None }).collect();
        let urls: Vec<&Url> = results.iter().filter_map(|i| if let OutputItem::Url(u) = i { Some(u) } else { None }).collect();
        assert_eq!(subs.len(), 2, "expected 2 subdomains, got {results:?}");
        assert_eq!(urls.len(), 2, "expected 2 URLs, got {results:?}");
        // URLs should contain the extracted subdomain hosts.
        let url_set: std::collections::HashSet<&str> = urls.iter().map(|u| u.url.as_str()).collect();
        assert!(url_set.contains("https://a.example.com"));
        assert!(url_set.contains("https://b.example.com"));
    }

    /// End-to-end FileTransport check: a tokio task plays the role of a worker (claims
    /// a unit, appends a Started + 2 Items + Finished envelope), while the client tails
    /// and forwards typed items onto its mpsc. Proves the wire format + broker primitives
    /// + client tail all fit together.
    #[tokio::test]
    async fn file_transport_streams_results_from_fake_worker() {
        use crate::broker::FileBroker;
        use crate::wire::ResultEnvelope;
        use crate::FileTransport;

        let base = std::env::temp_dir().join(format!("secator-ft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ft = FileTransport::open(base.clone()).unwrap();

        // Fake worker: poll the tasks dir, claim, then publish a few envelopes.
        let broker = FileBroker::new(base.clone()).unwrap();
        let worker_handle = tokio::spawn(async move {
            // Wait for a task to appear.
            let unit_path = loop {
                let pending = broker.list_pending().unwrap();
                if let Some(p) = pending.into_iter().next() {
                    break p;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            };
            let (claimed, unit) = broker.claim(&unit_path, "fake-worker").unwrap().unwrap();
            broker.append_result(&unit.job_id, &ResultEnvelope::Started {
                worker_id: "fake-worker".into(),
            }).unwrap();
            broker.append_result(&unit.job_id, &ResultEnvelope::Item {
                value: serde_json::json!({"_type": "subdomain", "host": "a.example.com", "domain": "example.com"}),
            }).unwrap();
            broker.append_result(&unit.job_id, &ResultEnvelope::Item {
                value: serde_json::json!({"_type": "subdomain", "host": "b.example.com", "domain": "example.com"}),
            }).unwrap();
            broker.append_result(&unit.job_id, &ResultEnvelope::Finished {
                worker_id: "fake-worker".into(),
                status: "SUCCESS".into(),
                findings: 2,
                errors: 0,
                elapsed_seconds: 0.1,
            }).unwrap();
            broker.ack(&claimed).unwrap();
        });

        // Client side: submit + tail.
        let (tx, mut rx) = mpsc::channel::<OutputItem>(16);
        let status = ft
            .execute_task("subfinder", vec!["example.com".into()], BTreeMap::new(), None, tx)
            .await
            .unwrap();
        assert_eq!(status, "SUCCESS");

        // Collect items.
        let mut got: Vec<OutputItem> = Vec::new();
        while let Ok(Some(item)) = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
            got.push(item);
        }
        assert_eq!(got.len(), 2, "expected 2 Subdomain items, got {got:?}");
        let hosts: Vec<&str> = got.iter().filter_map(|i| match i {
            OutputItem::Subdomain(s) => Some(s.host.as_str()),
            _ => None,
        }).collect();
        assert!(hosts.contains(&"a.example.com"));
        assert!(hosts.contains(&"b.example.com"));

        worker_handle.await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Build a Group plan with N fake-sleep branches and run it. Returns
    /// (elapsed_ms, total_items_emitted).
    async fn run_sleep_group(n: usize) -> (u128, usize) {
        let mut branches = Vec::with_capacity(n);
        for i in 0..n {
            branches.push(Plan::Task(TaskPlan {
                class: "fake-sleep".into(),
                ancestor_defaults: std::collections::BTreeMap::new(),
                id: format!("wf._group.fake-sleep-{i}"),
                opts: BTreeMap::new(),
                target_extractors: vec![],
                opt_extractors: BTreeMap::new(),
                condition: None,
                ancestor_id: Some("wf".into()),
                description: None,
            }));
        }
        let plan = Plan::Group(branches);
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(64);
        let start = std::time::Instant::now();
        let results = local
            .execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx)
            .await;
        (start.elapsed().as_millis(), results.len())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn group_branches_run_in_parallel() {
        // 4 branches × 200ms each = ~800ms if sequential (subprocess spawn +
        // sleep + wait), ~200ms if parallel. We compare against a 2× sequential
        // run rather than a hard wall-clock cap because `cargo test --workspace`
        // runs many test binaries concurrently and contention can stretch
        // both axes proportionally; the parallel ratio survives the noise.
        let (parallel_elapsed, n_items) = run_sleep_group(4).await;
        assert_eq!(n_items, 4, "expected one subdomain per branch");
        // Sequential baseline for the same number of branches running ONE at a
        // time (single-branch group hits the fast path and runs the sole task
        // four times in sequence — see `run_sleep_serial_baseline`).
        let serial_elapsed = run_sleep_serial_baseline(4).await;
        // Parallel must be meaningfully faster than serial. 0.6× is generous
        // — true parallelism on a 4-core box typically clocks in at ~0.25×.
        assert!(
            parallel_elapsed * 100 < serial_elapsed * 60,
            "group ran in {parallel_elapsed}ms; serial baseline {serial_elapsed}ms — \
             expected parallel < 0.6× serial. The branches likely ran sequentially."
        );
    }

    /// Run N sleep tasks one after another (no Group) — establishes the
    /// "serial wall clock" baseline `group_branches_run_in_parallel` compares
    /// against. Same host, same subprocess overhead, just no concurrency.
    async fn run_sleep_serial_baseline(n: usize) -> u128 {
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(64);
        let start = std::time::Instant::now();
        for i in 0..n {
            let plan = Plan::Task(TaskPlan {
                class: "fake-sleep".into(),
                ancestor_defaults: std::collections::BTreeMap::new(),
                id: format!("wf.serial-{i}"),
                opts: BTreeMap::new(),
                target_extractors: vec![],
                opt_extractors: BTreeMap::new(),
                condition: None,
                ancestor_id: Some("wf".into()),
                description: None,
            });
            let _ = local
                .execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx.clone())
                .await;
        }
        start.elapsed().as_millis()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn group_branches_all_emit_results() {
        // Sanity check: every branch's items end up in the final results vec
        // (the merge step after join_all). Three branches → three subdomains.
        let (_elapsed, n_items) = run_sleep_group(3).await;
        assert_eq!(n_items, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_item_group_still_runs() {
        // Edge case: groups with ≤1 branch take the fast path, no join_all.
        let (_elapsed, n_items) = run_sleep_group(1).await;
        assert_eq!(n_items, 1);
    }

    /// Plan::Group fan-out via FileTransport must enqueue + complete EVERY
    /// branch, not just `worker_concurrency` of them. Shape: N parallel
    /// siblings → FileTransport.execute_task per branch → fake worker (with
    /// 4 concurrent claim loops, matching the production default) drains the
    /// queue → all N branches produce their items in the final result set.
    ///
    /// This was originally written to repro a suspected dispatch-drop bug
    /// observed against `~/.secator/celery/data/` — turned out the live broker
    /// dir was shared with a Python Celery worker that was stealing claims.
    /// The synthetic test pins the Rust dispatch path as correct.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn plan_group_remote_dispatches_every_branch() {
        use crate::broker::FileBroker;
        use crate::wire::ResultEnvelope;
        use crate::FileTransport;

        const N_BRANCHES: usize = 7;

        let base = std::env::temp_dir()
            .join(format!("secator-pg-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&base);
        let ft = FileTransport::open(base.clone()).unwrap();

        // Fake worker with 4 poll loops (matches the real worker's
        // `concurrency=4` default). Each loop sleeps briefly to mimic real
        // subprocess wall time so we exercise the in-flight contention path.
        let worker_broker = FileBroker::new(base.clone()).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut worker_loops: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        const WORKER_CONCURRENCY: usize = 4;
        for slot in 0..WORKER_CONCURRENCY {
            let wb = worker_broker.clone();
            let stop_l = stop.clone();
            let handled_l = handled.clone();
            worker_loops.push(tokio::spawn(async move {
                while !stop_l.load(std::sync::atomic::Ordering::Relaxed) {
                    let pending = wb.list_pending().unwrap_or_default();
                    let mut claimed_any = false;
                    for path in pending {
                        if let Ok(Some((claimed, unit))) = wb.claim(&path, "fake-worker") {
                            claimed_any = true;
                            let id = handled_l
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                + 1;
                            let _ = wb.append_result(
                                &unit.job_id,
                                &ResultEnvelope::Started {
                                    worker_id: format!("fake-worker-{slot}"),
                                },
                            );
                            // Simulate subprocess wall time — matches the
                            // ~350 ms real-gf takes and forces siblings to
                            // contend on the 4 worker slots.
                            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                            let _ = wb.append_result(
                                &unit.job_id,
                                &ResultEnvelope::Item {
                                    value: serde_json::json!({
                                        "_type": "subdomain",
                                        "host": format!("branch-{}.example.com", id),
                                        "domain": "example.com",
                                    }),
                                },
                            );
                            let _ = wb.append_result(
                                &unit.job_id,
                                &ResultEnvelope::Finished {
                                    worker_id: format!("fake-worker-{slot}"),
                                    status: "SUCCESS".into(),
                                    findings: 1,
                                    errors: 0,
                                    elapsed_seconds: 0.08,
                                },
                            );
                            let _ = wb.ack(&claimed);
                            break;
                        }
                    }
                    if !claimed_any {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                }
            }));
        }

        // Build the actual production shape: `Chain(Group(N))`. This is what
        // `compile()` produces for a workflow whose top-level YAML contains
        // `_group/foo:` (see `secator-dag/src/lib.rs` and `url_vuln.yaml`).
        // Each branch has a distinct opt to match the real `gf/<pattern>`
        // shape (the YAML's `pattern: xss`, `pattern: lfi`, ...).
        let patterns = ["xss", "lfi", "ssrf", "rce", "interest", "idor", "debug"];
        assert_eq!(patterns.len(), N_BRANCHES);
        let branches: Vec<Plan> = (0..N_BRANCHES)
            .map(|i| {
                let mut opts = BTreeMap::new();
                opts.insert("pattern".into(), ExprValue::Str(patterns[i].into()));
                Plan::Task(TaskPlan {
                    class: "fake-subfinder".into(),
                    ancestor_defaults: std::collections::BTreeMap::new(),
                    id: format!("wf._group.fake-subfinder/{}", patterns[i]),
                    opts,
                    target_extractors: vec![],
                    opt_extractors: BTreeMap::new(),
                    condition: None,
                    ancestor_id: Some("wf".into()),
                    description: None,
                })
            })
            .collect();
        let plan = Plan::Chain(vec![Plan::Group(branches)]);

        let local = LocalTransport::new(lookup()).with_remote(ft);
        let (tx, mut rx) = mpsc::channel::<OutputItem>(64);
        let collector = tokio::spawn(async move {
            let mut got = Vec::new();
            while let Some(item) = rx.recv().await {
                got.push(item);
            }
            got
        });
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            local.execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx),
        )
        .await
        .expect("plan must complete");

        // Stop the worker and collect.
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in worker_loops {
            let _ = h.await;
        }
        let handled_n = handled.load(std::sync::atomic::Ordering::Relaxed);
        let collected = collector.await.unwrap();
        let _ = std::fs::remove_dir_all(&base);

        let subs: Vec<_> = collected
            .iter()
            .filter(|i| matches!(i, OutputItem::Subdomain(_)))
            .collect();
        assert_eq!(
            handled_n, N_BRANCHES,
            "fake worker should have handled all {N_BRANCHES} branches, got {handled_n}"
        );
        assert_eq!(
            subs.len(),
            N_BRANCHES,
            "client should have received one Subdomain per branch ({N_BRANCHES}), got {}",
            subs.len()
        );
    }

    /// Helper: pull the `state` value out of an OutputItem::State, or None.
    fn state_of(item: &OutputItem) -> Option<&str> {
        if let OutputItem::State(s) = item { Some(&s.state) } else { None }
    }

    /// B1: a task gated by an `if:` that evaluates false must emit Info + State
    /// items so drivers (Mongo/API) can record the SKIPPED status. Before this,
    /// gated tasks vanished silently and Python's per-task SKIPPED row had no
    /// Rust equivalent.
    #[tokio::test]
    async fn condition_false_emits_skipped_state() {
        let plan = Plan::Task(TaskPlan {
            class: "fake-subfinder".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.fake-subfinder".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: BTreeMap::new(),
            condition: Some("not opts.passive".into()),
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let local = LocalTransport::new(lookup());
        let (tx, mut rx) = mpsc::channel(16);
        let mut opts = BTreeMap::new();
        opts.insert("passive".into(), ExprValue::Bool(true));
        let results = local.execute(&plan, vec!["example.com".into()], opts, tx).await;

        // No findings (Subdomain/Url/...) — task was gated out.
        assert!(
            !results.iter().any(|i| i.is_finding()),
            "gated task must not emit findings, got {results:?}"
        );
        // Exactly one SKIPPED state item.
        let skipped: Vec<_> = results.iter().filter(|i| state_of(i) == Some("SKIPPED")).collect();
        assert_eq!(skipped.len(), 1, "expected one SKIPPED state, got {skipped:?}");
        // Info + State must also flow to the live tx (drivers consume the stream).
        let mut streamed = Vec::new();
        while let Ok(Some(item)) = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await {
            streamed.push(item);
        }
        assert!(
            streamed.iter().any(|i| state_of(i) == Some("SKIPPED")),
            "SKIPPED state must reach the live tx channel, streamed: {streamed:?}"
        );
    }

    /// B1: same shape for the empty-resolved-inputs gate — a task whose
    /// extractor produces zero targets and that doesn't accept zero inputs
    /// must still emit a SKIPPED record.
    #[tokio::test]
    async fn empty_inputs_emits_skipped_state() {
        // `fake-httpx` has input_types=&["host","url"] (declared in the test
        // fixtures above) so it does NOT accept zero inputs. We feed it a
        // `targets_: subdomain.host` extractor against an empty `results`
        // — no upstream subdomain emitted yet, so resolved_inputs is empty.
        let plan = Plan::Task(TaskPlan {
            class: "fake-httpx".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.fake-httpx".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![secator_dag::Extractor {
                kind: "subdomain".into(),
                field: "host".into(),
                condition: None,
                group_by: None,
            }],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(16);
        let results = local.execute(&plan, vec![], BTreeMap::new(), tx).await;
        let skipped: Vec<_> = results.iter().filter(|i| state_of(i) == Some("SKIPPED")).collect();
        assert_eq!(
            skipped.len(),
            1,
            "expected one SKIPPED state for the empty-inputs task, got {results:?}"
        );
    }

    /// B1: unknown task class — already emitted an Info before this fix; now
    /// it also emits the SKIPPED state so drivers don't have to special-case
    /// the message format.
    #[tokio::test]
    async fn unknown_class_emits_skipped_state() {
        let plan = Plan::Task(TaskPlan {
            class: "does-not-exist".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "wf.does-not-exist".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: Some("wf".into()),
            description: None,
        });
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(16);
        let results = local.execute(&plan, vec!["example.com".into()], BTreeMap::new(), tx).await;
        let skipped: Vec<_> = results.iter().filter(|i| state_of(i) == Some("SKIPPED")).collect();
        assert_eq!(skipped.len(), 1, "expected one SKIPPED state, got {results:?}");
    }

    /// #167 B-WF-PASSIVE: a TaskPlan's `ancestor_defaults` (e.g. a workflow's
    /// `options.passive.default: false`) must NOT clobber the runtime parent
    /// opt set via CLI / profile (`passive: true`). The merge priority is
    /// `ancestor_defaults < parent_opts < tp.opts`.
    #[tokio::test]
    async fn ancestor_defaults_lose_to_parent_runtime_opts() {
        // Build a Plan::Task whose ancestor_defaults set `passive=false`
        // (mimicking a workflow with `options.passive.default: false`) and
        // whose condition is `not opts.passive`. The runtime parent opts
        // pass `passive=true` (mimicking `--pf passive`). The condition
        // must evaluate to false → task is skipped.
        let mut ancestor_defaults = BTreeMap::new();
        ancestor_defaults.insert("passive".to_string(), ExprValue::Bool(false));
        let tp = TaskPlan {
            class: "fake-subfinder".into(),
            id: "wf.fake-subfinder".into(),
            ancestor_defaults,
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: BTreeMap::new(),
            condition: Some("not opts.passive".into()),
            ancestor_id: Some("wf".into()),
            description: None,
        };
        let plan = Plan::Task(tp);
        let local = LocalTransport::new(lookup());
        let (tx, _rx) = mpsc::channel(16);
        let mut runtime_opts = BTreeMap::new();
        runtime_opts.insert("passive".into(), ExprValue::Bool(true));
        let results = local
            .execute(&plan, vec!["example.com".into()], runtime_opts, tx)
            .await;
        // Runtime passive=true beat ancestor_defaults' passive=false →
        // condition `not opts.passive` is false → task was skipped.
        let skipped: Vec<_> = results
            .iter()
            .filter(|i| state_of(i) == Some("SKIPPED"))
            .collect();
        assert_eq!(
            skipped.len(),
            1,
            "runtime passive=true must override ancestor passive=false; got {results:?}"
        );
    }
}
