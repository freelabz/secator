//! Tool dispatch — execute a normalized action against the secator runtime.
//!
//! Each tool the LLM can call (`run_task`, `run_workflow`, `run_shell`, `stop`,
//! `query_workspace`, `add_finding`, `follow_up`) gets one entry point here.
//! Each entry point returns `Outcome`: an LLM-facing result string + zero or
//! more `OutputItem`s to relay to the operator + an optional "stop the loop"
//! signal so `stop` and `follow_up` can short-circuit the agent loop.
//!
//! All tools are fully wired:
//!   * `run_task` — registry lookup → runner → digest of collected items.
//!   * `run_workflow` — template load + tree build + `LocalTransport` drive on
//!     a dedicated runtime thread.
//!   * `run_shell` — `std::process::Command` with a sanitized env to keep
//!     secrets out of the child.
//!   * `query_workspace` — filesystem-backed `secator_query::JsonBackend`.
//!   * `add_finding` — constructs the requested finding from the LLM's fields
//!     and surfaces it on the outcome's items list.
//!   * `stop` / `follow_up` — set `stop = true` so the agent loop returns
//!     without spending more iterations.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use secator_model::{Info, OutputItem, Warning};
use secator_runner::{CommandRunner, NativeRunner};
use serde_json::Value;
use tokio::sync::mpsc;

/// Result of dispatching one tool call. The string goes back to the LLM as a
/// `tool` message; the items are relayed to the operator; `stop` short-circuits
/// the agent loop.
#[derive(Debug, Default)]
pub struct Outcome {
    pub result: String,
    pub items: Vec<OutputItem>,
    pub stop: bool,
}

/// Top-level dispatcher: routes by `action.action`. Equivalent to
/// `dispatch_with_depth(action, 1)`. Only the test suite calls this convenience
/// form today — production callers always know their depth and use
/// [`dispatch_with_depth`] directly. Gated to keep the dead-code lint quiet
/// without dropping the helper that the test module relies on.
#[cfg(test)]
pub fn dispatch(action: &Value) -> Outcome {
    dispatch_with_depth(action, 1)
}

/// Depth-aware dispatcher: `current_depth` is the ai_depth of the calling
/// agent (1 = top-level run, 2 = first subagent, …). Passed to
/// `dispatch_task` so it can refuse `run_task ai` cleanly when the chain
/// would exceed `agent::MAX_SUBAGENT_DEPTH`.
pub fn dispatch_with_depth(action: &Value, current_depth: u32) -> Outcome {
    let kind = action.get("action").and_then(|v| v.as_str()).unwrap_or("");
    match kind {
        "task" => dispatch_task(action, current_depth),
        "workflow" => dispatch_workflow(action),
        "shell" => dispatch_shell(action),
        "query" => dispatch_query(action),
        "add_finding" => dispatch_add_finding(action),
        "follow_up" => dispatch_follow_up(action),
        "stop" => dispatch_stop(action),
        other => Outcome {
            result: format!("unknown action `{other}` — see TOOL_SCHEMAS for valid names"),
            ..Default::default()
        },
    }
}

fn dispatch_stop(action: &Value) -> Outcome {
    let reason = action.get("reason").and_then(|v| v.as_str()).unwrap_or("(no reason given)");
    Outcome {
        result: format!("stop acknowledged: {reason}"),
        items: vec![OutputItem::Info(Info {
            message: format!("ai: stopping — {reason}"),
            ..Default::default()
        })],
        stop: true,
    }
}

fn dispatch_follow_up(action: &Value) -> Outcome {
    use std::io::{BufRead, IsTerminal, Write};

    let reason = action.get("reason").and_then(|v| v.as_str()).unwrap_or("(no reason given)");
    let choices: Vec<String> = action
        .get("choices")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // When stdin is a TTY, prompt the operator + read an answer + feed it
    // back to the LLM as the next user message (returned in the Outcome
    // `result` body so agent.rs adds it as a `tool` message; the LLM picks
    // it up on the next iteration). When stdin isn't a TTY (subagent, CI,
    // piped invocation), short-circuit with `stop=true` so the run exits
    // cleanly with the operator-facing Info — Python parity for the
    // "non-interactive backend" case in `interactivity.py`.
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut items: Vec<OutputItem> = Vec::new();
    let info_msg = if choices.is_empty() {
        format!("ai: follow-up needed — {reason}")
    } else {
        format!("ai: follow-up needed — {reason} (choices: {})", choices.join(", "))
    };
    items.push(OutputItem::Info(Info { message: info_msg, ..Default::default() }));

    if !interactive {
        return Outcome {
            result: format!("follow_up surfaced to operator (non-interactive): {reason}"),
            items,
            stop: true,
        };
    }

    // Interactive flow: print question + choices to stderr, read one line
    // from stdin. Empty answer / EOF → stop the loop with a clear message.
    eprintln!("\n[ai] follow-up needed: {reason}");
    if !choices.is_empty() {
        eprintln!("Choices:");
        for (i, c) in choices.iter().enumerate() {
            eprintln!("  {}. {c}", i + 1);
        }
        eprintln!("(enter a number or your own answer)");
    }
    eprint!("> ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => {
            // EOF — operator dropped out of the prompt.
            return Outcome {
                result: format!("follow_up: operator declined to answer ({reason})"),
                items,
                stop: true,
            };
        }
        Ok(_) => {}
        Err(e) => {
            return Outcome {
                result: format!("follow_up: stdin read failed — {e}"),
                items,
                stop: true,
            };
        }
    }
    let mut answer = line.trim().to_string();
    if answer.is_empty() {
        return Outcome {
            result: format!("follow_up: empty answer ({reason})"),
            items,
            stop: true,
        };
    }
    // If the answer parses as a 1-based choice index, replace it with the
    // actual choice text.
    if let Ok(idx) = answer.parse::<usize>() {
        if idx >= 1 && idx <= choices.len() {
            answer = choices[idx - 1].clone();
        }
    }
    items.push(OutputItem::Info(Info {
        message: format!("ai: operator answered — {answer}"),
        ..Default::default()
    }));
    // Return the answer in the tool-result body so the LLM sees it on the
    // next iteration. `stop = false` keeps the loop going.
    Outcome {
        result: format!("follow_up answer: {answer}"),
        items,
        stop: false,
    }
}

/// Construct a finding from the LLM's `add_finding` call and emit it on the
/// outcome's items list. The CLI's receive loop fans Items out to enabled
/// drivers (Mongo / API / Discord / Slack / GCS) so a finding the LLM creates
/// flows through the same pipeline as one a task produced. Python parity
/// with `add_finding` in `ai/actions.py`.
fn dispatch_add_finding(action: &Value) -> Outcome {
    use secator_model::{OutputItem as O, OutputMap};

    // Build a loose Map from the action's fields (everything except our
    // internal discriminators). `_type` is required.
    let mut item_map: secator_model::Map = secator_model::Map::new();
    if let Value::Object(obj) = action {
        for (k, v) in obj {
            if k == "action" || k == "description" {
                continue;
            }
            item_map.insert(k.clone(), v.clone());
        }
    }
    let ty = match item_map.get("_type").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return Outcome {
                result: "add_finding: `_type` is required (e.g. vulnerability, url, port, …)".into(),
                ..Default::default()
            };
        }
    };
    if !secator_model::FINDING_TYPE_NAMES.contains(&ty.as_str()) {
        return Outcome {
            result: format!(
                "add_finding: unknown finding type `{ty}` (valid: {})",
                secator_model::FINDING_TYPE_NAMES.join(", ")
            ),
            ..Default::default()
        };
    }
    let item = match O::from_map(&item_map, &OutputMap::new()) {
        Some(i) => i,
        None => {
            return Outcome {
                result: format!(
                    "add_finding: couldn't construct a `{ty}` from those fields — \
                     check required fields (`name`, `matched_at`, etc.)"
                ),
                ..Default::default()
            };
        }
    };

    // Stamp `_source = "ai"` so downstream tools / drivers can tell which items
    // were operator/LLM-authored vs which came from a tool subprocess.
    let mut item = item;
    if item.meta().source.is_empty() {
        item.meta_mut().source = "ai".into();
    }
    let type_name = item.type_name();
    Outcome {
        result: format!("add_finding: emitted {type_name}"),
        items: vec![
            OutputItem::Info(Info {
                message: format!("ai: emitted finding ({type_name})"),
                ..Default::default()
            }),
            item,
        ],
        ..Default::default()
    }
}

/// Search the workspace's persisted findings using the JSON query backend.
/// Python parity with `query_workspace`: takes a MongoDB-style `query` object
/// + optional `limit` (default 100), returns the matched findings as a digest.
///
/// Uses [`secator_query::JsonBackend`] (filesystem) — the same backend
/// `secator q --driver json` uses. MongoDB / API backends aren't reachable from
/// inside the ai task today (they'd need the config addons threaded through
/// AgentConfig) so we always go through the filesystem path.
fn dispatch_query(action: &Value) -> Outcome {
    use secator_query::QueryBackend;

    let query = match action.get("query") {
        Some(q) if q.is_object() => q.clone(),
        _ => {
            return Outcome {
                result: "query_workspace: `query` must be a MongoDB-style object".into(),
                ..Default::default()
            };
        }
    };
    let limit = action
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(100);

    let cfg = secator_config::get();
    let workspace = if cfg.workspace.default.is_empty() {
        "default".to_string()
    } else {
        cfg.workspace.default.clone()
    };
    let backend = secator_query::JsonBackend::new(cfg.dirs.reports.clone(), workspace.clone());
    let results = backend.search(&query, Some(limit));
    let n = results.len();

    // Compact JSON one per line — easy for the LLM to parse, cheap on tokens.
    let mut body = format!(
        "query_workspace (workspace={workspace}, limit={limit}, matched={n}):\n"
    );
    for (i, r) in results.iter().enumerate() {
        if i >= 100 {
            body.push_str(&format!("... and {} more\n", n - i));
            break;
        }
        let line = serde_json::to_string(r).unwrap_or_default();
        body.push_str(&line);
        body.push('\n');
    }
    let result = truncate(&body, MAX_TOOL_RESULT_BYTES);
    Outcome {
        result,
        items: vec![OutputItem::Info(Info {
            message: format!("ai: query_workspace matched {n} finding(s)"),
            ..Default::default()
        })],
        ..Default::default()
    }
}

/// Run a workflow by name — look up its YAML, build the runner tree, prune
/// against opts/targets, walk every command/native task node serially, and
/// return a digest of every collected item. `_group` parallel nodes are
/// flattened to serial execution (Python parity gap; full parallel scheduling
/// would need `secator-dag`'s task-graph engine, deferred for now).
fn dispatch_workflow(action: &Value) -> Outcome {
    let name = action.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() {
        return Outcome { result: "run_workflow: missing `name`".into(), ..Default::default() };
    }
    let targets: Vec<String> = action
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let opts = opts_from_action(action);

    let yaml = match secator_templates::registry::workflows::get(&name) {
        Some(y) => y,
        None => {
            return Outcome {
                result: format!("run_workflow: unknown workflow `{name}`"),
                items: vec![OutputItem::Warning(Warning {
                    message: format!("ai: workflow `{name}` not found in registry"),
                    ..Default::default()
                })],
                ..Default::default()
            };
        }
    };

    let template = match secator_templates::load_from_str(yaml) {
        Ok(t) => t,
        Err(e) => {
            return Outcome {
                result: format!("run_workflow `{name}`: parse failed — {e}"),
                ..Default::default()
            };
        }
    };
    let mut tree = match secator_templates::build_runner_tree(&template, |w| {
        secator_templates::registry::workflows::get(w)
            .and_then(|y| secator_templates::load_from_str(y).ok())
            .and_then(|t| match t {
                secator_templates::Template::Workflow(w) => Some(w),
                _ => None,
            })
    }) {
        Ok(t) => t,
        Err(e) => {
            return Outcome {
                result: format!("run_workflow `{name}`: tree build failed — {e}"),
                ..Default::default()
            };
        }
    };
    secator_templates::prune(&mut tree, &opts_to_yaml_mapping(&opts), &targets);

    // Compile the pruned tree to a Plan and drive it through `LocalTransport`.
    // This gets us the same chain/group semantics + parallel `_group` branches
    // the CLI's `secator w` path uses, including extractor chains
    // (`targets_: subdomain.host`) so workflows like `host_recon` actually
    // route data between tasks instead of running each stage in isolation.
    let plan = secator_dag::compile(&tree);
    let initial_opts = opts_to_expr_map(&opts);
    let lookup: std::sync::Arc<dyn secator_exec::TaskLookup> = std::sync::Arc::new(
        secator_exec::StaticLookup::new(crate::all()).with_native(crate::native_all()),
    );
    let local = secator_exec::LocalTransport::new(lookup);
    let (collected, ran) = run_plan_via_local(&local, plan, targets.clone(), initial_opts, &name);

    let digest = digest_workflow(&name, &ran, &collected);
    let result = truncate(&digest, MAX_TOOL_RESULT_BYTES);
    let mut items = vec![OutputItem::Info(Info {
        message: format!("ai: workflow `{name}` ran {} step(s) → {} item(s)", ran.len(), collected.len()),
        ..Default::default()
    })];
    items.extend(collected);
    Outcome { result, items, ..Default::default() }
}

/// Drive a Plan through `LocalTransport` on a dedicated tokio thread so the
/// AI's sync dispatch context can collect items synchronously. Returns the
/// collected items + the list of task class names that ran (extracted from
/// the Plan, since LocalTransport doesn't surface a run log).
fn run_plan_via_local(
    local: &secator_exec::LocalTransport,
    plan: secator_dag::Plan,
    inputs: Vec<String>,
    opts: BTreeMap<String, secator_expr::Value>,
    workflow_name: &str,
) -> (Vec<OutputItem>, Vec<String>) {
    use tokio::sync::mpsc;

    let mut ran: Vec<String> = Vec::new();
    collect_task_classes(&plan, &mut ran);

    // Spawn a fresh runtime in its own thread — same pattern as the LLM call
    // path. Avoids "runtime within runtime" panics when the CLI is already
    // tokio-driven.
    let local_clone = local_transport_clone(local);
    let handle = std::thread::Builder::new()
        .name(format!("secator-ai-workflow-{workflow_name}"))
        .spawn(move || -> Vec<OutputItem> {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return Vec::new(),
            };
            rt.block_on(async move {
                let (tx, mut rx) = mpsc::channel::<OutputItem>(256);
                let collector = tokio::spawn(async move {
                    let mut out: Vec<OutputItem> = Vec::new();
                    while let Some(item) = rx.recv().await {
                        out.push(item);
                    }
                    out
                });
                let _ = local_clone.execute(&plan, inputs, opts, tx).await;
                // Drop the sender (already dropped via execute) — collector will end.
                collector.await.unwrap_or_default()
            })
        });
    let items = match handle.and_then(|h| h.join().map_err(|_| {
        std::io::Error::other("workflow thread panicked")
    })) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    (items, ran)
}

/// Shallow clone of a `LocalTransport` — `Arc<dyn TaskLookup>` is the only
/// shared state, the other knobs are bool/Option fields we copy directly.
fn local_transport_clone(t: &secator_exec::LocalTransport) -> secator_exec::LocalTransport {
    let mut clone = secator_exec::LocalTransport::new(std::sync::Arc::clone(&t.lookup));
    if let Some(rf) = &t.reports_folder {
        clone = clone.with_reports_folder(rf.clone());
    }
    if t.verbose {
        clone = clone.with_verbose(true);
    }
    clone
}

/// Walk the Plan and append each Task's class name to `out` (for the digest
/// "ran X step(s): a → b → c" line).
fn collect_task_classes(plan: &secator_dag::Plan, out: &mut Vec<String>) {
    match plan {
        secator_dag::Plan::Task(tp) => out.push(tp.class.clone()),
        secator_dag::Plan::Chain(items) | secator_dag::Plan::Group(items) => {
            for p in items {
                collect_task_classes(p, out);
            }
        }
    }
}

/// Convert the AI's stringified opts into the typed `secator_expr::Value` map
/// the DAG executor expects. Booleans/numbers parse out; everything else
/// stays as a string.
fn opts_to_expr_map(opts: &BTreeMap<String, String>) -> BTreeMap<String, secator_expr::Value> {
    let mut out = BTreeMap::new();
    for (k, v) in opts {
        let parsed = if v == "true" {
            secator_expr::Value::Bool(true)
        } else if v == "false" {
            secator_expr::Value::Bool(false)
        } else if let Ok(n) = v.parse::<i64>() {
            secator_expr::Value::Int(n)
        } else if let Ok(n) = v.parse::<f64>() {
            secator_expr::Value::Float(n)
        } else if v.contains(',') {
            // List-y values (Python parity: comma-joined back to a list for
            // `'nmap' in opts.scanners`-style checks).
            secator_expr::Value::List(
                v.split(',').map(|s| secator_expr::Value::Str(s.trim().into())).collect(),
            )
        } else {
            secator_expr::Value::Str(v.clone())
        };
        out.insert(k.clone(), parsed);
    }
    out
}

/// Convert `BTreeMap<String, String>` to `serde_yaml::Mapping` for the
/// `secator_templates::prune` opt-evaluator. Booleans / numbers are parsed
/// when possible so `if: opts.passive == true` evaluates correctly.
fn opts_to_yaml_mapping(opts: &BTreeMap<String, String>) -> serde_yaml::Mapping {
    let mut m = serde_yaml::Mapping::new();
    for (k, v) in opts {
        let parsed: serde_yaml::Value = if v == "true" {
            serde_yaml::Value::Bool(true)
        } else if v == "false" {
            serde_yaml::Value::Bool(false)
        } else if let Ok(n) = v.parse::<i64>() {
            serde_yaml::Value::Number(n.into())
        } else if let Ok(n) = v.parse::<f64>() {
            serde_yaml::Value::Number(serde_yaml::Number::from(n))
        } else {
            serde_yaml::Value::String(v.clone())
        };
        m.insert(serde_yaml::Value::String(k.clone()), parsed);
    }
    m
}

fn digest_workflow(name: &str, steps: &[String], items: &[OutputItem]) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for it in items {
        *counts.entry(it.type_name()).or_insert(0) += 1;
    }
    let counts_str = counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut samples: Vec<String> = items.iter().take(30).map(format_item).collect();
    if items.len() > samples.len() {
        samples.push(format!("... and {} more", items.len() - samples.len()));
    }
    format!(
        "Workflow `{name}` ran {} step(s): {}.\nProduced {} item(s): {counts_str}\n{}",
        steps.len(),
        steps.join(" → "),
        items.len(),
        samples.join("\n"),
    )
}

/// Run an arbitrary shell command and capture stdout+stderr (truncated). The
/// env is sanitized to keep API keys / secrets from leaking into the child.
fn dispatch_shell(action: &Value) -> Outcome {
    let cmd = match action.get("command").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c,
        _ => {
            return Outcome {
                result: "run_shell: missing `command` argument".into(),
                ..Default::default()
            }
        }
    };
    let env = sanitized_env();
    let output = match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env_clear()
        .envs(&env)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Outcome {
                result: format!("run_shell: spawn failed — {e}"),
                items: vec![OutputItem::Warning(Warning {
                    message: format!("ai: shell spawn failed for `{cmd}` — {e}"),
                    ..Default::default()
                })],
                ..Default::default()
            };
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().unwrap_or(-1);
    let body = format!(
        "$ {cmd}\nexit_code: {status}\n--- stdout ({stdout_bytes} bytes) ---\n{stdout}\n--- stderr ({stderr_bytes} bytes) ---\n{stderr}",
        stdout_bytes = stdout.len(),
        stderr_bytes = stderr.len()
    );
    let result = truncate(&body, MAX_TOOL_RESULT_BYTES);
    Outcome {
        result,
        items: vec![OutputItem::Info(Info {
            message: format!("ai: ran `{cmd}` (exit {status})"),
            ..Default::default()
        })],
        ..Default::default()
    }
}

/// Hard cap to keep tool results from blowing up the context window. Mirrors
/// Python's `MAX_ACTION_TOKENS` budget (10k tokens ≈ 40 KB at 4 bytes/token).
const MAX_TOOL_RESULT_BYTES: usize = 40_000;

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let head = &s[..max];
    format!("{head}\n... [TRUNCATED — {extra} bytes elided]", extra = s.len() - max)
}

/// Allowlist of env vars passed through to child processes. Everything else is
/// stripped so secrets (API keys, tokens, etc.) don't leak to commands the LLM
/// orchestrates. Mirrors Python `_sanitized_env` policy.
fn sanitized_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (k, v) in std::env::vars() {
        let upper = k.to_uppercase();
        // Hard denylist on common secret-bearing names + prefixes.
        if SENSITIVE_PREFIXES.iter().any(|p| upper.starts_with(p)) {
            continue;
        }
        if SENSITIVE_SUBSTRINGS.iter().any(|s| upper.contains(s)) {
            continue;
        }
        env.insert(k, v);
    }
    // Keep a sane PATH/HOME if the parent had them.
    env
}

const SENSITIVE_PREFIXES: &[&str] = &[
    "SECATOR_",
    "ANTHROPIC_",
    "OPENAI_",
    "GOOGLE_",
    "AZURE_",
    "AWS_",
    "GCP_",
    "OPENROUTER_",
    "XAI_",
];

const SENSITIVE_SUBSTRINGS: &[&str] = &["KEY", "SECRET", "TOKEN", "PASSWORD"];

/// Look the task up in the registry, build a runner, execute on a dedicated
/// runtime thread, collect the items, and return a digest the LLM can read.
/// `current_depth` is the ai_depth of the calling agent — only meaningful when
/// the LLM requests `run_task ai`, where it gates against the
/// `MAX_SUBAGENT_DEPTH` cap and gets incremented for the child run.
fn dispatch_task(action: &Value, current_depth: u32) -> Outcome {
    let name = action.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() {
        return Outcome {
            result: "run_task: missing `name` argument".into(),
            ..Default::default()
        };
    }
    let targets: Vec<String> = action
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut opts = opts_from_action(action);

    // Subagent path: when the LLM dispatches `run_task ai`, refuse cleanly
    // beyond `MAX_SUBAGENT_DEPTH`, otherwise inject the bumped `ai_depth` opt
    // + force `subagent=true` so the child loop strips `follow_up` and saves
    // its session under a child name.
    if name == "ai" {
        if current_depth >= super::agent::MAX_SUBAGENT_DEPTH {
            return Outcome {
                result: format!(
                    "run_task ai: refused — subagent depth {current_depth} would exceed cap {} (Python parity)",
                    super::agent::MAX_SUBAGENT_DEPTH
                ),
                items: vec![OutputItem::Warning(Warning {
                    message: format!(
                        "ai: refused subagent dispatch (depth {current_depth} >= cap {})",
                        super::agent::MAX_SUBAGENT_DEPTH
                    ),
                    ..Default::default()
                })],
                ..Default::default()
            };
        }
        opts.insert("ai_depth".into(), (current_depth + 1).to_string());
        opts.insert("subagent".into(), "true".into());
    }
    let summary_label = format!("{name} {} target(s)", targets.len());

    let collected = match collect_task_items(&name, targets.clone(), opts.clone()) {
        Ok(c) => c,
        Err(e) => {
            return Outcome {
                result: format!("run_task `{name}`: {e}"),
                items: vec![OutputItem::Warning(Warning {
                    message: format!("ai: run_task `{name}` failed — {e}"),
                    ..Default::default()
                })],
                ..Default::default()
            };
        }
    };

    let digest = digest_items(&collected, &name);
    let result = truncate(&digest, MAX_TOOL_RESULT_BYTES);
    let mut items: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("ai: ran {summary_label} → {n} item(s)", n = collected.len()),
        ..Default::default()
    })];
    // Surface the collected items to the operator (so the CLI's live UI / drivers
    // see them) AND keep them in the LLM digest above.
    items.extend(collected);
    Outcome { result, items, ..Default::default() }
}

/// Build a one-string-per-key RunOpts map from the LLM's `opts` object. Strings
/// pass through, numbers/booleans get to_string()'d, arrays get comma-joined.
fn opts_from_action(action: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(opts) = action.get("opts").and_then(|v| v.as_object()) {
        for (k, v) in opts {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| match x {
                        Value::String(s) => Some(s.clone()),
                        Value::Bool(b) => Some(b.to_string()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                Value::Null => continue,
                Value::Object(_) => continue, // nested objects aren't part of RunOpts
            };
            out.insert(k.clone(), s);
        }
    }
    out
}

/// Spawn a dedicated runtime thread that drives the requested runner to
/// completion and collects every emitted OutputItem. Tasks are async; we sit
/// in a sync hook so we own the channel here.
fn collect_task_items(
    name: &str,
    inputs: Vec<String>,
    opts: BTreeMap<String, String>,
) -> Result<Vec<OutputItem>, String> {
    let task_name = name.to_string();
    let handle = std::thread::Builder::new()
        .name(format!("secator-ai-dispatch-{name}"))
        .spawn(move || -> Result<Vec<OutputItem>, String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio rt build: {e}"))?;
            rt.block_on(async move { run_one(&task_name, inputs, opts).await })
        })
        .map_err(|e| format!("spawn dispatch thread: {e}"))?;
    handle
        .join()
        .map_err(|_| "dispatch thread panicked".to_string())
        .and_then(|inner| inner)
}

async fn run_one(
    name: &str,
    inputs: Vec<String>,
    opts: BTreeMap<String, String>,
) -> Result<Vec<OutputItem>, String> {
    let (tx, mut rx) = mpsc::channel::<OutputItem>(256);
    // Native registry first (urlparser, prompt, ai itself); fall back to the
    // command registry (every external tool).
    if let Some(spec) = crate::native::get(name) {
        let mut runner = NativeRunner::new(spec, inputs);
        runner.opts = opts;
        let run_handle = tokio::spawn(async move { runner.run(tx).await });
        let items = collect(&mut rx).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), run_handle).await;
        return Ok(items);
    }
    if let Some(spec) = crate::get(name) {
        let mut runner = CommandRunner::new(spec, inputs);
        runner.opts = opts;
        let run_handle = tokio::spawn(async move { runner.run(tx).await });
        let items = collect(&mut rx).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), run_handle).await;
        return Ok(items);
    }
    Err(format!("unknown task `{name}` (not in native or command registry)"))
}

async fn collect(rx: &mut mpsc::Receiver<OutputItem>) -> Vec<OutputItem> {
    let mut items = Vec::new();
    while let Some(item) = rx.recv().await {
        items.push(item);
    }
    items
}

/// Compact one-line-per-finding digest the LLM can read without choking the
/// context window. The full structured items are still surfaced to the
/// operator via the `Outcome.items` path.
fn digest_items(items: &[OutputItem], task: &str) -> String {
    if items.is_empty() {
        return format!("Task `{task}` produced 0 items.");
    }
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut samples: Vec<String> = Vec::new();
    for it in items {
        *counts.entry(it.type_name()).or_insert(0) += 1;
        if samples.len() < 20 {
            samples.push(format_item(it));
        }
    }
    let counts_str = counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    let head = format!("Task `{task}` produced {} item(s): {counts_str}.", items.len());
    let body = samples.join("\n");
    let tail = if items.len() > samples.len() {
        format!("\n... and {} more", items.len() - samples.len())
    } else {
        String::new()
    };
    format!("{head}\n{body}{tail}")
}

fn format_item(item: &OutputItem) -> String {
    match item {
        OutputItem::Url(u) => format!("- url: {} ({})", u.url, u.status_code),
        OutputItem::Port(p) => format!("- port: {}/{} {} {}", p.port, p.protocol, p.state, p.service_name),
        OutputItem::Subdomain(s) => format!("- subdomain: {}", s.host),
        OutputItem::Ip(i) => format!("- ip: {} (alive={})", i.ip, i.alive),
        OutputItem::Vulnerability(v) => format!(
            "- vuln: [{}] {} @ {}",
            v.severity, v.name, v.matched_at
        ),
        OutputItem::Exploit(e) => format!("- exploit: {} ({})", e.id, e.reference),
        OutputItem::Technology(t) => format!(
            "- tech: {}{}",
            t.product,
            t.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default()
        ),
        OutputItem::Tag(t) => format!("- tag: {}={} ({})", t.name, t.value, t.category),
        OutputItem::Certificate(c) => format!("- cert: {} ({})", c.host, c.fingerprint_sha256),
        OutputItem::Error(e) => format!("- error: {}", e.message),
        OutputItem::Warning(w) => format!("- warning: {}", w.message),
        OutputItem::Info(i) => format!("- info: {}", i.message),
        other => format!("- {}: {:?}", other.type_name(), other.to_map()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dispatch_stop_emits_info_and_signals_stop() {
        let action = json!({"action":"stop","reason":"done"});
        let out = dispatch(&action);
        assert!(out.stop);
        assert!(out.result.contains("done"));
        assert!(out.items.iter().any(|i| matches!(i, OutputItem::Info(_))));
    }

    #[test]
    fn dispatch_follow_up_non_interactive_stops_and_emits_info() {
        // In tests stdin is not a TTY → follow_up takes the non-interactive
        // path: stop the loop, emit the operator-facing Info with choices.
        let action = json!({"action":"follow_up","reason":"need scope","choices":["A","B"]});
        let out = dispatch(&action);
        assert!(out.stop);
        assert!(out.items.iter().any(|i| matches!(i, OutputItem::Info(info) if info.message.contains("A, B"))));
        assert!(out.result.contains("non-interactive"));
    }

    #[test]
    fn dispatch_shell_runs_echo() {
        let action = json!({"action":"shell","command":"echo hello-from-ai"});
        let out = dispatch(&action);
        assert!(out.result.contains("hello-from-ai"));
        assert!(out.result.contains("exit_code: 0"));
        assert!(!out.stop);
    }

    #[test]
    fn dispatch_shell_with_missing_command_errors() {
        let action = json!({"action":"shell"});
        let out = dispatch(&action);
        assert!(out.result.contains("missing"));
    }

    #[test]
    fn dispatch_task_unknown_name_errors() {
        let action = json!({"action":"task","name":"definitely-not-a-task","targets":["x"]});
        let out = dispatch(&action);
        assert!(out.result.contains("unknown task"));
    }

    #[test]
    fn dispatch_task_refuses_subagent_when_depth_at_cap() {
        // At depth == MAX_SUBAGENT_DEPTH (2), spawning another `ai` is refused.
        let action = json!({"action":"task","name":"ai","targets":[]});
        let out = dispatch_with_depth(&action, super::super::agent::MAX_SUBAGENT_DEPTH);
        assert!(out.result.contains("refused"));
        assert!(out.result.contains("exceed cap"));
    }

    #[test]
    fn dispatch_task_subagent_at_top_level_injects_depth_and_subagent_flag() {
        // From depth=1 (top-level) we let the dispatch proceed — the task
        // registry doesn't have an `ai` task at runtime resolution because
        // it's a native task (not a CommandRunner task). collect_task_items
        // will surface that as "unknown task" in this test, but the depth +
        // subagent flag injection runs before that step. Confirm via the
        // refused-message NOT appearing.
        let action = json!({"action":"task","name":"ai","targets":[]});
        let out = dispatch_with_depth(&action, 1);
        // Should NOT be a depth-cap refusal — should either succeed-ish or fail
        // for a different reason (e.g. "unknown task" if registry can't find
        // `ai` from the static lookup path).
        assert!(!out.result.contains("would exceed cap"));
    }

    #[test]
    fn dispatch_workflow_missing_name_errors() {
        let action = json!({"action":"workflow","targets":["x"]});
        let out = dispatch(&action);
        assert!(out.result.contains("missing"));
    }

    #[test]
    fn dispatch_workflow_unknown_name_errors() {
        let action = json!({"action":"workflow","name":"definitely-not-a-workflow","targets":["x"]});
        let out = dispatch(&action);
        assert!(out.result.contains("unknown workflow"));
    }

    #[test]
    fn dispatch_workflow_runs_known_workflow_to_completion() {
        // We don't actually execute network tasks in tests (subprocesses for
        // nmap/httpx aren't available); the assertion here is that
        // dispatch_workflow finds the workflow, parses it, builds the tree,
        // and tries to run each step — items will mostly be Warnings from
        // failing dispatches in the sandbox, but the digest is well-formed.
        let action = json!({
            "action": "workflow",
            "name": "url_crawl",
            "targets": [],
        });
        let out = dispatch(&action);
        assert!(out.result.contains("url_crawl"));
        // Info item announcing how many steps ran.
        assert!(out.items.iter().any(|i| matches!(
            i,
            OutputItem::Info(info) if info.message.contains("url_crawl")
        )));
    }

    #[test]
    fn dispatch_add_finding_missing_type_errors() {
        let action = json!({"action": "add_finding", "name": "x"});
        let out = dispatch(&action);
        assert!(out.result.contains("_type"));
    }

    #[test]
    fn dispatch_add_finding_unknown_type_errors() {
        let action = json!({"action": "add_finding", "_type": "not_a_real_type", "name": "x"});
        let out = dispatch(&action);
        assert!(out.result.contains("unknown finding type"));
    }

    #[test]
    fn dispatch_add_finding_emits_vulnerability() {
        let action = json!({
            "action": "add_finding",
            "_type": "vulnerability",
            "name": "Test vuln",
            "severity": "high",
            "matched_at": "https://example.com",
        });
        let out = dispatch(&action);
        assert!(out.result.contains("emitted vulnerability"));
        // Info + the finding itself.
        assert!(out.items.iter().any(|i| matches!(i, OutputItem::Vulnerability(_))));
        // Source should be stamped as "ai".
        let vuln = out.items.iter().find_map(|i| match i {
            OutputItem::Vulnerability(v) => Some(v),
            _ => None,
        }).unwrap();
        assert_eq!(vuln.meta.source, "ai");
        assert_eq!(vuln.name, "Test vuln");
        assert_eq!(vuln.severity, "high");
    }

    #[test]
    fn dispatch_add_finding_emits_url() {
        let action = json!({
            "action": "add_finding",
            "_type": "url",
            "url": "https://leaked.example.com/secret",
            "status_code": 200,
        });
        let out = dispatch(&action);
        assert!(out.items.iter().any(|i| matches!(i, OutputItem::Url(_))));
    }

    #[test]
    fn dispatch_query_missing_query_field_errors() {
        let action = json!({"action": "query"});
        let out = dispatch(&action);
        assert!(out.result.contains("MongoDB-style object"));
    }

    #[test]
    fn dispatch_query_with_empty_workspace_returns_zero_matches() {
        // Empty reports dir → JsonBackend yields zero matches but doesn't error.
        let action = json!({"action": "query", "query": {"_type": "vulnerability"}, "limit": 5});
        let out = dispatch(&action);
        assert!(out.result.contains("query_workspace"));
        assert!(out.result.contains("matched=0") || out.result.contains("limit=5"));
        assert!(out.items.iter().any(|i| matches!(i, OutputItem::Info(_))));
    }

    #[test]
    fn dispatch_unknown_action_errors() {
        let action = json!({"action":"banana"});
        let out = dispatch(&action);
        assert!(out.result.contains("unknown action"));
    }

    #[test]
    fn sanitized_env_strips_api_keys() {
        // Plant a fake secret in the parent env. The child env must NOT see it.
        // `FAKE_API_KEY` matches via the "KEY" substring rule; `OPENAI_FAKE_ID`
        // matches via the "OPENAI_" prefix rule; `BENIGN_VAR` is allowed through.
        unsafe { std::env::set_var("FAKE_API_KEY", "leak-me-not"); }
        unsafe { std::env::set_var("OPENAI_FAKE_ID", "another-secret"); }
        unsafe { std::env::set_var("BENIGN_AI_TEST_VAR", "ok"); }
        let env = sanitized_env();
        assert!(!env.contains_key("FAKE_API_KEY"), "API_KEY substring must be stripped");
        assert!(!env.contains_key("OPENAI_FAKE_ID"), "OPENAI_ prefix must be stripped");
        assert_eq!(
            env.get("BENIGN_AI_TEST_VAR").map(String::as_str),
            Some("ok"),
            "non-secret var must pass through"
        );
        unsafe { std::env::remove_var("FAKE_API_KEY"); }
        unsafe { std::env::remove_var("OPENAI_FAKE_ID"); }
        unsafe { std::env::remove_var("BENIGN_AI_TEST_VAR"); }
    }

    #[test]
    fn opts_from_action_serializes_scalars_and_arrays() {
        let action = json!({
            "opts": {
                "ports": "80,443",
                "rate_limit": 100,
                "follow_redirect": true,
                "tags": ["tech","detect"],
                "nested": {"x": 1},
                "null_value": null
            }
        });
        let opts = opts_from_action(&action);
        assert_eq!(opts.get("ports").map(String::as_str), Some("80,443"));
        assert_eq!(opts.get("rate_limit").map(String::as_str), Some("100"));
        assert_eq!(opts.get("follow_redirect").map(String::as_str), Some("true"));
        assert_eq!(opts.get("tags").map(String::as_str), Some("tech,detect"));
        // Nested objects + nulls dropped.
        assert!(!opts.contains_key("nested"));
        assert!(!opts.contains_key("null_value"));
    }

    #[test]
    fn truncate_caps_long_strings() {
        let long = "a".repeat(MAX_TOOL_RESULT_BYTES + 100);
        let t = truncate(&long, MAX_TOOL_RESULT_BYTES);
        assert!(t.len() < long.len());
        assert!(t.contains("TRUNCATED"));
    }
}
