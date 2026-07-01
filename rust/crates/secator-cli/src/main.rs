//! secator binary.
//!
//! Usage: `secator x <task> <target> ...` / `secator w <workflow>` / `secator s <scan>`.
//!
//! Single binary that ships every subcommand: task / workflow / scan / worker /
//! beat / install / config / workspace / profiles / aliases / reports / health /
//! cheatsheet / update / utils / query / addons / schedule. Per-task option
//! flags are generated dynamically from each task's `OptSchema` at startup,
//! reports persist to `<reports>/<workspace>/{tasks,workflows,scans}/<id>/`,
//! and findings fan out to enabled drivers + exporters.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Arg, ArgAction, ArgMatches, Command};
use secator_expr::Value as ExprValue;
use secator_model::OutputItem;
use secator_options::{KeyMap, OptSchema, OptSpec, OptType};
use secator_runner::CommandRunner;
use secator_ui::{err, info, raw, render, target_line, Style};
use serde_yaml::{Mapping, Value as Yaml};
use tokio::sync::mpsc;

mod cli_groups;
mod plugins;
mod profiles;
mod scans;
mod workflows;

/// Resolve a task class name to its option schema regardless of whether it's
/// backed by a `TaskSpec` (subprocess) or a `NativeSpec` (in-process). Used by
/// the workflow / scan flag aggregation and the `--help` renderer so native
/// tasks expose their opts at the CLI just like command tasks.
fn schema_for_class(class: &str) -> Option<OptSchema> {
    if let Some(spec) = secator_tasks::get(class) {
        return Some((spec.schema)());
    }
    if let Some(spec) = secator_tasks::get_native(class) {
        return Some((spec.schema)());
    }
    None
}


#[tokio::main]
async fn main() -> ExitCode {
    // Install the process-wide config BEFORE building the CLI: task schemas read it
    // when computing their defaults (header, threads, response-size limits, etc.).
    if let Ok(cfg) = secator_config::Config::load() {
        secator_config::set(cfg);
    }
    // Seed the debug filter from the top-level `debug:` config key. Falls back
    // to `SECATOR_DEBUG` env if the config field is empty.
    secator_debug::init(&secator_config::get().debug);
    // Discover user-supplied workflow / scan / profile templates from
    // `<dirs.templates>/*.yaml`. Python parity with `loader.find_templates()`.
    secator_templates::registry::init_user_templates(&secator_config::get().dirs.templates);
    // Discover compiled `.rs` plugin crates (tasks / drivers / exporters)
    // under `<dirs.templates>/target/release/`. `secator template build`
    // produces these; the loader silently no-ops when the dir doesn't exist.
    let user_plugins = plugins::load_user_plugins(&secator_config::get().dirs.templates);
    secator_tasks::register_plugin_tasks(user_plugins.tasks);

    let cli = build_cli();
    let matches = cli.get_matches();
    match matches.subcommand() {
        Some((cmd, sub)) if matches!(cmd, "task" | "x" | "t" | "tasks") => {
            run_task_subcommand(sub).await
        }
        Some((cmd, sub)) if matches!(cmd, "workflow" | "w" | "workflows") => {
            run_workflow_subcommand(sub).await
        }
        Some((cmd, sub)) if matches!(cmd, "scan" | "s" | "scans") => {
            run_scan_subcommand(sub).await
        }
        Some((cmd, sub)) if matches!(cmd, "worker" | "wk") => {
            run_worker_subcommand(sub).await
        }
        Some((cmd, sub)) if matches!(cmd, "profile" | "p" | "profiles") => {
            run_profile_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "workspace" | "ws" | "workspaces") => {
            run_workspace_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "health" | "h") => {
            cli_groups::run_health_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "cheatsheet" | "ch") => {
            cli_groups::run_cheatsheet_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "install" | "i") => {
            cli_groups::run_install_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "reports" | "report" | "r") => {
            cli_groups::run_reports_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "config" | "c") => {
            cli_groups::run_config_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "query" | "q") => {
            cli_groups::run_query_subcommand(sub)
        }
        Some((cmd, sub)) if matches!(cmd, "addons" | "a") => {
            cli_groups::run_addons_subcommand(sub)
        }
        Some(("alias", sub)) => cli_groups::run_alias_subcommand(sub),
        Some(("update", sub)) => cli_groups::run_update_subcommand(sub),
        Some((cmd, sub)) if matches!(cmd, "utils" | "u") => {
            // Pass the live Command tree so the `completion` subcommand can
            // emit clap_complete output for the whole CLI surface.
            cli_groups::run_utils_subcommand(sub, &mut build_cli())
        }
        Some(("beat", sub)) => cli_groups::run_beat_subcommand(sub).await,
        Some(("schedule", sub)) => cli_groups::run_schedule_subcommand(sub),
        Some(("vuln", sub)) => cli_groups::run_vuln_subcommand(sub).await,
        Some(("diff", sub)) => cli_groups::run_diff_subcommand(sub),
        Some(("template", sub)) | Some(("templates", sub)) => run_template_subcommand(sub),
        _ => {
            eprintln!("see --help");
            ExitCode::from(2)
        }
    }
}

/// `--verbose` resolution: CLI flag wins; otherwise fall back to
/// `CONFIG.cli.show_command_output` (Python parity — the operator sets the
/// default once in `~/.secator/config.yml` instead of typing `-v` every run).
fn resolve_verbose(args: &clap::ArgMatches) -> bool {
    args.get_flag("verbose") || secator_config::get().cli.show_command_output
}

/// Convert Python's "i64, negative-or-zero = unlimited" knobs into an
/// `Option<Duration>` (seconds). Used for transport timeouts.
fn positive_duration(seconds: i64) -> Option<std::time::Duration> {
    (seconds > 0).then(|| std::time::Duration::from_secs(seconds as u64))
}

/// Same shape as [`positive_duration`] but for the count-like knobs
/// (`worker_max_tasks_per_child`, `task_memory_limit_mb`).
fn positive_u64(n: i64) -> Option<u64> {
    (n > 0).then_some(n as u64)
}

/// `secator template build|list|path` — manages plugin crates dropped under
/// `<dirs.templates>/`. `build` shells out to `cargo build --release` against
/// that dir; `list` shows the compiled dylibs the loader would pick up at
/// startup; `path` prints the templates dir so operators can `cd` to it.
fn run_template_subcommand(args: &ArgMatches) -> ExitCode {
    let templates_dir = secator_config::get().dirs.templates.clone();
    match args.subcommand() {
        Some(("scaffold", sub)) => {
            let name = sub
                .get_one::<String>("name")
                .expect("required arg")
                .clone();
            match plugins::scaffold_plugin(&templates_dir, &name) {
                Ok(path) => {
                    eprintln!(
                        "[INF] Scaffolded plugin crate at {}",
                        path.display()
                    );
                    eprintln!("      Edit src/lib.rs, then run `secator template build`.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("template scaffold failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some(("build", _)) => match plugins::build_user_templates(&templates_dir) {
            Ok(paths) if paths.is_empty() => {
                eprintln!("Built — but no cdylib artifacts produced. Make sure your plugin crate sets `crate-type = [\"cdylib\"]` in Cargo.toml.");
                ExitCode::SUCCESS
            }
            Ok(paths) => {
                eprintln!("Built {} plugin artifact(s):", paths.len());
                for p in paths {
                    eprintln!("  {}", p.display());
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("template build failed: {e}");
                ExitCode::from(1)
            }
        },
        Some(("list", _)) => {
            let loaded = plugins::load_user_plugins(&templates_dir);
            println!(
                "tasks={} drivers={} exporters={}",
                loaded.tasks.len(),
                loaded.drivers.len(),
                loaded.exporters.len(),
            );
            for spec in &loaded.tasks {
                println!("  task     {}", spec.name);
            }
            for (name, _) in &loaded.drivers {
                println!("  driver   {name}");
            }
            for (name, _) in &loaded.exporters {
                println!("  exporter {name}");
            }
            ExitCode::SUCCESS
        }
        Some(("path", _)) => {
            println!("{}", templates_dir.display());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("see --help");
            ExitCode::from(2)
        }
    }
}

fn build_template_subcommand() -> Command {
    Command::new("template")
        .visible_alias("templates")
        .about("Manage .rs plugin crates dropped under ~/.secator/templates/")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("scaffold")
                .about("Generate a starter plugin crate under ~/.secator/templates/<name>/")
                .arg(
                    Arg::new("name")
                        .help("Plugin crate name (kebab-case recommended)")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("build")
                .about("Compile plugin crates via `cargo build --release` against ~/.secator/templates/"),
        )
        .subcommand(
            Command::new("list")
                .about("List tasks/drivers/exporters the loaded plugins contribute"),
        )
        .subcommand(
            Command::new("path")
                .about("Print the path to the templates directory (dirs.templates)"),
        )
}

// -------------------------------------------------------------------- CLI shape

fn build_cli() -> Command {
    Command::new("secator-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .about("secator (Rust rewrite) — the pentester's swiss knife")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(build_task_subcommand())
        .subcommand(build_workflow_subcommand())
        .subcommand(build_scan_subcommand())
        .subcommand(build_worker_subcommand())
        .subcommand(build_profile_subcommand())
        .subcommand(build_workspace_subcommand())
        .subcommand(cli_groups::build_health_subcommand())
        .subcommand(cli_groups::build_cheatsheet_subcommand())
        .subcommand(cli_groups::build_install_subcommand())
        .subcommand(cli_groups::build_reports_subcommand())
        .subcommand(cli_groups::build_config_subcommand())
        .subcommand(cli_groups::build_query_subcommand())
        .subcommand(cli_groups::build_addons_subcommand())
        .subcommand(cli_groups::build_alias_subcommand())
        .subcommand(cli_groups::build_update_subcommand())
        .subcommand(cli_groups::build_utils_subcommand())
        .subcommand(cli_groups::build_beat_subcommand())
        .subcommand(cli_groups::build_schedule_subcommand())
        .subcommand(cli_groups::build_vuln_subcommand())
        .subcommand(cli_groups::build_diff_subcommand())
        .subcommand(build_template_subcommand())
}

// ----------------------------------------------------------------- Profile CLI

fn build_profile_subcommand() -> Command {
    Command::new("profile")
        .visible_alias("p")
        .visible_alias("profiles")
        .about("Manage profiles (preset option bundles)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("List available profiles"))
}

/// `secator p list` — Python parity for `secator profiles list`. Prints a tidy
/// summary of every built-in profile + the opts it sets.
fn run_profile_subcommand(matches: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    match matches.subcommand() {
        Some(("list", _)) => {
            eprintln!("{}", info("Available profiles:", style));
            for name in profiles::names() {
                let p = match profiles::load(name) {
                    Some(p) => p,
                    None => continue,
                };
                let desc = p.description.unwrap_or_default();
                let opts: Vec<String> = p
                    .opts
                    .iter()
                    .filter_map(|(k, v)| {
                        let k = k.as_str()?;
                        let v = yaml_to_display(v);
                        Some(format!("{k}={v}"))
                    })
                    .collect();
                let enforced = if p.enforce { " [enforced]" } else { "" };
                eprintln!("  {:<14} {}{}", name, desc, enforced);
                if !opts.is_empty() {
                    eprintln!("                 {}", opts.join(", "));
                }
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: secator p list");
            ExitCode::from(2)
        }
    }
}

fn yaml_to_display(v: &Yaml) -> String {
    match v {
        Yaml::Bool(b) => b.to_string(),
        Yaml::Number(n) => n.to_string(),
        Yaml::String(s) => s.clone(),
        _ => serde_yaml::to_string(v).unwrap_or_default().trim().to_string(),
    }
}

// ----------------------------------------------------------------- Workspace CLI

/// `secator ws` (aliases: workspace, workspaces). Maps 1:1 to Python's
/// `cli.py` workspace group: `list`, `use`, `current`, `rm`. Workspaces are
/// just directories under `CONFIG.dirs.reports/<name>/{tasks,workflows,scans}/`.
fn build_workspace_subcommand() -> Command {
    Command::new("workspace")
        .visible_alias("ws")
        .visible_alias("workspaces")
        .about("Manage workspaces (report-folder namespaces)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("List workspaces and their run counts"))
        .subcommand(
            Command::new("use")
                .visible_alias("create")
                .about("Set the default workspace (persists to ~/.secator/config.yml)")
                .arg(Arg::new("name").required(true).value_name("NAME")),
        )
        .subcommand(Command::new("current").about("Show the current default workspace"))
        .subcommand(
            Command::new("rm")
                .visible_alias("remove")
                .visible_alias("delete")
                .about("Delete a workspace and all its reports")
                .arg(Arg::new("name").required(true).value_name("NAME"))
                .arg(
                    Arg::new("yes")
                        .short('y')
                        .long("yes")
                        .help("Skip confirmation prompt")
                        .action(ArgAction::SetTrue),
                ),
        )
}

fn run_workspace_subcommand(matches: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    match matches.subcommand() {
        Some(("list", _)) => workspace_list(style),
        Some(("use", sub)) => {
            let name = sub.get_one::<String>("name").map(String::as_str).unwrap_or("");
            workspace_use(name, style)
        }
        Some(("current", _)) => workspace_current(style),
        Some(("rm", sub)) => {
            let name = sub.get_one::<String>("name").map(String::as_str).unwrap_or("");
            let yes = sub.get_flag("yes");
            workspace_rm(name, yes, style)
        }
        _ => {
            eprintln!("usage: secator ws list|use|current|rm");
            ExitCode::from(2)
        }
    }
}

/// Discover workspaces: every directory under `reports_dir` is a workspace,
/// counted by `report.json` files found below it. Mirrors Python's walk in
/// `cli.py::workspace_list`.
fn workspace_list(style: Style) -> ExitCode {
    use std::collections::BTreeMap;
    let config = secator_config::get();
    let reports_dir = &config.dirs.reports;
    let mut counts: BTreeMap<String, (usize, std::path::PathBuf)> = BTreeMap::new();

    // Seed with every direct child directory (including empty ones).
    if let Ok(entries) = std::fs::read_dir(reports_dir) {
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = e.file_name().to_str() {
                    counts.entry(name.to_string()).or_insert((0, e.path()));
                }
            }
        }
    }

    // Walk and count report.json files. Each is at
    // <reports>/<ws>/<runner_type>/<id>/report.json — bump the ws's count.
    fn walk(
        path: &std::path::Path,
        reports_root: &std::path::Path,
        counts: &mut BTreeMap<String, (usize, std::path::PathBuf)>,
    ) {
        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return,
        };
        for e in entries.flatten() {
            let p = e.path();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                walk(&p, reports_root, counts);
            } else if p.file_name().and_then(|n| n.to_str()) == Some("report.json") {
                // Derive workspace name from path relative to reports_root.
                if let Ok(rel) = p.strip_prefix(reports_root) {
                    if let Some(first) = rel.components().next() {
                        if let Some(s) = first.as_os_str().to_str() {
                            let entry = counts
                                .entry(s.to_string())
                                .or_insert((0, reports_root.join(s)));
                            entry.0 += 1;
                        }
                    }
                }
            }
        }
    }
    walk(reports_dir, reports_dir, &mut counts);

    if counts.is_empty() {
        eprintln!(
            "{}",
            info(&format!("No workspaces found under {}", reports_dir.display()), style)
        );
        return ExitCode::SUCCESS;
    }
    eprintln!("{}", info("Workspaces:", style));
    eprintln!("  {:<24} {:>10}  {}", "NAME", "RUN COUNT", "PATH");
    for (name, (count, path)) in &counts {
        eprintln!("  {:<24} {:>10}  {}", name, count, path.display());
    }
    ExitCode::SUCCESS
}

/// `secator ws use <name>`: persist `workspace.default = <name>` to
/// `~/.secator/config.yml`. Same shape as Python's `CONFIG.set + CONFIG.save`,
/// but we splice into the YAML directly so we don't clobber unrelated keys.
fn workspace_use(name: &str, style: Style) -> ExitCode {
    let name = name.trim();
    if name.is_empty() {
        eprintln!("{}", err("workspace name is empty", style));
        return ExitCode::from(2);
    }
    // Python parity: persist the literal name. Disk-path sanitization happens
    // at run time via `secator_report::sanitize_folder_name` when allocating
    // each run's reports folder.
    let path = secator_config::user_config_path();
    // Load the existing user-config YAML (if any), splice `workspace.default`,
    // and rewrite. We work at the raw-YAML level so we only touch this one key.
    let mut root: serde_yaml::Value = if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(t) => serde_yaml::from_str(&t).unwrap_or(serde_yaml::Value::Mapping(Default::default())),
            Err(e) => {
                eprintln!("{}", err(&format!("read {}: {e}", path.display()), style));
                return ExitCode::from(1);
            }
        }
    } else {
        serde_yaml::Value::Mapping(Default::default())
    };
    {
        let m = root
            .as_mapping_mut()
            .expect("root is constructed as a mapping");
        let ws_key = serde_yaml::Value::String("workspace".into());
        let ws_node = m
            .entry(ws_key)
            .or_insert(serde_yaml::Value::Mapping(Default::default()));
        if let Some(ws_map) = ws_node.as_mapping_mut() {
            ws_map.insert(
                serde_yaml::Value::String("default".into()),
                serde_yaml::Value::String(name.to_string()),
            );
        }
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("{}", err(&format!("mkdir {}: {e}", parent.display()), style));
            return ExitCode::from(1);
        }
    }
    let text = match serde_yaml::to_string(&root) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", err(&format!("serialize config: {e}"), style));
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("{}", err(&format!("write {}: {e}", path.display()), style));
        return ExitCode::from(1);
    }
    eprintln!(
        "{}",
        info(&format!("Now using workspace: {name} (saved to {})", path.display()), style)
    );
    ExitCode::SUCCESS
}

fn workspace_current(style: Style) -> ExitCode {
    let config = secator_config::get();
    let current = if config.workspace.default.is_empty() {
        "default".to_string()
    } else {
        config.workspace.default.clone()
    };
    eprintln!("{}", info(&format!("Current workspace: {current}"), style));
    ExitCode::SUCCESS
}

fn workspace_rm(name: &str, yes: bool, style: Style) -> ExitCode {
    let name = name.trim();
    if name.is_empty() {
        eprintln!("{}", err("workspace name is empty", style));
        return ExitCode::from(2);
    }
    let config = secator_config::get();
    let folder = config
        .dirs
        .reports
        .join(secator_report::sanitize_folder_name(name));
    if !folder.exists() {
        eprintln!(
            "{}",
            err(&format!("Workspace folder not found: {}", folder.display()), style)
        );
        return ExitCode::from(2);
    }
    eprintln!("{}", info("The following actions will be performed:", style));
    eprintln!("  - Remove workspace folder: {}", folder.display());
    if !yes {
        // Read y/N from stdin. Default-no on EOF or any non-y/Y answer.
        use std::io::{BufRead, Write};
        eprint!("\nAre you sure you want to delete workspace {name:?}? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            eprintln!("{}", info("Aborted.", style));
            return ExitCode::from(1);
        }
    }
    if let Err(e) = std::fs::remove_dir_all(&folder) {
        eprintln!(
            "{}",
            err(&format!("remove {}: {e}", folder.display()), style)
        );
        return ExitCode::from(1);
    }
    eprintln!(
        "{}",
        info(&format!("Removed workspace folder: {}", folder.display()), style)
    );
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------- Workflow CLI

fn build_workflow_subcommand() -> Command {
    let mut grp = Command::new("workflow")
        .visible_alias("w")
        .visible_alias("workflows")
        .about("Run a workflow (a composed set of tasks)")
        .subcommand_required(true)
        .arg_required_else_help(true);
    for name in workflows::names() {
        if let Some(yaml) = workflows::get(name) {
            grp = grp.subcommand(build_workflow_cmd(name, yaml));
        }
    }
    grp
}

/// Build `secator scan` — same shape as the workflow subcommand. Each scan
/// references one or more workflows; `build_workflow_cmd` is reused as-is so
/// the scan picks up its declared inputs + (any) options block. Per-task opts
/// from the nested workflows are NOT propagated to the scan's clap surface yet
/// — pass them via `secator w <workflow>` if you need that level of control.
fn build_scan_subcommand() -> Command {
    let mut grp = Command::new("scan")
        .visible_alias("s")
        .visible_alias("scans")
        .about("Run a scan (composes one or more workflows)")
        .subcommand_required(true)
        .arg_required_else_help(true);
    for name in scans::names() {
        if let Some(yaml) = scans::get(name) {
            grp = grp.subcommand(build_workflow_cmd(name, yaml));
        }
    }
    grp
}

fn build_workflow_cmd(name: &'static str, yaml: &'static str) -> Command {
    // Parse YAML once at startup to harvest description/options/input_types.
    let parsed: Yaml = serde_yaml::from_str(yaml).unwrap_or(Yaml::Null);
    let mapping = parsed.as_mapping().cloned().unwrap_or_default();
    let description = mapping
        .get(Yaml::String("description".into()))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input_types: Vec<String> = mapping
        .get(Yaml::String("input_types".into()))
        .and_then(|v| v.as_sequence())
        .map(|s| s.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| vec!["target".into()]);
    let metavar: &'static str = Box::leak(input_types.join("|").into_boxed_str());

    let mut cmd = Command::new(name)
        .about(Box::leak(description.to_string().into_boxed_str()) as &str)
        .arg(
            // Optional at the clap layer: stdin / piped input is read by
            // `expand_inputs` when no positionals are passed. Empties are
            // rejected there with a clear error message.
            Arg::new("inputs")
                .help("Target(s) — positional, comma-separated list, file path, or stdin")
                .value_name(metavar)
                .num_args(0..),
        )
        .arg(global_flag("json", "Print items as JSON lines on stdout"))
        .arg(global_flag("raw", "Print only the primary field of each item on stdout"))
        .arg(
            // Default: hide subprocess stderr so the operator only sees Secator's
            // own lines (`⚡`, `[INF] Task ...`, parsed items). `--verbose` flips
            // it back on for debugging.
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Show the underlying tool's stderr output (banners, logs)")
                .action(ArgAction::SetTrue),
        )
        .arg(global_flag("no_color", "Disable ANSI colors"))
        // Inspection flags — print + exit, no tasks executed (Python parity).
        .arg(
            Arg::new("tree")
                .long("tree")
                .help("Print the pruned runner tree and exit (no tasks run)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("yaml")
                .long("yaml")
                .help("Print the resolved workflow YAML and exit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Print the tree and the cmds that would run; do not spawn subprocesses")
                .action(ArgAction::SetTrue),
        )
        // Worker / sync routing flags — same semantics as for the `x` subcommand.
        .arg(
            Arg::new("worker")
                .long("worker")
                .help("Force remote execution via the file broker (every task)")
                .action(ArgAction::SetTrue)
                .conflicts_with("sync"),
        )
        .arg(
            Arg::new("sync")
                .long("sync")
                .help("Force local (in-process) execution for every task")
                .action(ArgAction::SetTrue),
        )
        // Profile + workspace flags (Python parity: --pf/--ws long aliases —
        // Click's single-dash multi-char `-pf` / `-ws` shorts can't be modeled
        // in clap without colliding with task short flags like naabu's `-p`).
        .arg(
            Arg::new("profiles")
                .long("profiles")
                .visible_alias("pf")
                .value_name("LIST")
                .help("Comma-separated profile names to apply (see `secator p list`)"),
        )
        .arg(
            Arg::new("workspace")
                .long("workspace")
                .visible_alias("ws")
                .value_name("NAME")
                .help("Override the workspace name for this run's reports folder"),
        );

    // Workflow-level "common opts" that propagate to every task (Python parity:
    // threads/rate_limit/header/timeout/proxy/delay propagate down). Skip names that
    // the workflow YAML already exposes via its own `options:` block.
    let yaml_options = mapping
        .get(Yaml::String("options".into()))
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    let already_declared = |k: &str| yaml_options.get(Yaml::String(k.into())).is_some();
    for (opt_name, ty, help) in [
        ("threads", "int", "Number of threads (propagated to all tasks)"),
        ("rate_limit", "int", "Max requests per second (propagated)"),
        ("timeout", "int", "Request timeout in seconds (propagated)"),
        ("delay", "float", "Delay between requests in seconds (propagated)"),
        ("header", "str", "Custom HTTP header propagated to HTTP tasks"),
        ("proxy", "str", "HTTP(s)/SOCKS5 proxy URL (propagated)"),
    ] {
        if already_declared(opt_name) {
            continue;
        }
        let long_str: &'static str = Box::leak(opt_name.replace('_', "-").into_boxed_str());
        let mut arg = Arg::new(opt_name).long(long_str).help(help);
        match ty {
            "int" => arg = arg.value_parser(clap::value_parser!(i64)),
            "float" => arg = arg.value_parser(clap::value_parser!(f64)),
            _ => {}
        }
        cmd = cmd.arg(arg);
    }

    // Add per-task option groups: walk every task class referenced in `tasks:` and
    // expose its task-specific opts under `help_heading("Task <name> options")`.
    // Dedup both long and short flag names so a flag shared across two tasks
    // (e.g. `--ports` on nmap + naabu, or `-s` for nuclei's `severity` vs
    // searchsploit's `strict`) is only registered once — first task wins. Tasks
    // that lose the conflict still get their value at runtime because the
    // surviving task's parsed value propagates to every workflow task via
    // `initial_opts`.
    {
        use std::collections::HashSet;
        let mut seen_long: HashSet<String> = HashSet::new();
        let mut seen_short: HashSet<char> = HashSet::new();
        for class in collect_task_classes(&mapping) {
            let schema = match schema_for_class(&class) {
                Some(s) => s,
                None => continue,
            };
            let heading: &'static str =
                Box::leak(format!("Task {class} options").into_boxed_str());
            for opt in schema.opts.iter() {
                if opt.internal {
                    continue;
                }
                let long = opt.name.replace('_', "-");
                if !seen_long.insert(long.clone()) {
                    continue;
                }
                // If the opt has a single-char short and that char is already
                // taken, drop it (we keep the long form). Multi-char "shorts"
                // (clap can't model them) are ignored anyway in build_arg_from_spec.
                let mut arg = build_arg_from_spec(opt).help_heading(heading);
                if let Some(s) = opt.short {
                    let chars: Vec<char> = s.chars().collect();
                    if chars.len() == 1 {
                        if !seen_short.insert(chars[0]) {
                            // Strip the short to avoid the clap-time panic.
                            arg = arg.short(None);
                        }
                    }
                }
                cmd = cmd.arg(arg);
            }
        }
    }

    // Add an Arg per workflow option. For lists, accept a comma-separated string and
    // split downstream. is_flag → SetTrue.
    if let Some(opts) = mapping.get(Yaml::String("options".into())).and_then(|v| v.as_mapping()) {
        for (k, v) in opts {
            let opt_name = match k.as_str() {
                Some(s) => s,
                None => continue,
            };
            let opt_conf = v.as_mapping().cloned().unwrap_or_default();
            let is_flag = opt_conf
                .get(Yaml::String("is_flag".into()))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let help: &'static str = Box::leak(
                opt_conf
                    .get(Yaml::String("help".into()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
                    .into_boxed_str(),
            );
            let long_str: &'static str =
                Box::leak(opt_name.replace('_', "-").into_boxed_str());
            let mut arg = Arg::new(Box::leak(opt_name.to_string().into_boxed_str()) as &str)
                .long(long_str)
                .help(help);
            if is_flag {
                arg = arg.action(ArgAction::SetTrue);
            } else if let Some(def) = opt_conf.get(Yaml::String("default".into())) {
                // Lists → join with comma for the default display.
                let default_str = match def {
                    Yaml::Sequence(s) => {
                        let parts: Vec<String> =
                            s.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
                        parts.join(",")
                    }
                    Yaml::String(s) => s.clone(),
                    Yaml::Bool(b) => b.to_string(),
                    Yaml::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                if !default_str.is_empty() {
                    arg = arg.default_value(Box::leak(default_str.into_boxed_str()) as &str);
                }
            }
            cmd = cmd.arg(arg);
        }
    }
    cmd
}

async fn run_workflow_subcommand(matches: &ArgMatches) -> ExitCode {
    let (wf_name, args) = match matches.subcommand() {
        Some(s) => s,
        None => {
            eprintln!("usage: secator-cli w <workflow> <target>...");
            return ExitCode::from(2);
        }
    };
    let yaml = match workflows::get(wf_name) {
        Some(y) => y,
        None => {
            eprintln!("unknown workflow: {wf_name}");
            return ExitCode::from(2);
        }
    };
    run_template(wf_name, yaml, TemplateKind::Workflow, args).await
}

/// Same flow as `run_workflow_subcommand` but resolves the scan's nested
/// `workflows:` block via `workflows::get`. Routed here from `secator s <name>`.
async fn run_scan_subcommand(matches: &ArgMatches) -> ExitCode {
    let (scan_name, args) = match matches.subcommand() {
        Some(s) => s,
        None => {
            eprintln!("usage: secator-cli s <scan> <target>...");
            return ExitCode::from(2);
        }
    };
    let yaml = match scans::get(scan_name) {
        Some(y) => y,
        None => {
            eprintln!("unknown scan: {scan_name}");
            return ExitCode::from(2);
        }
    };
    run_template(scan_name, yaml, TemplateKind::Scan, args).await
}

#[derive(Copy, Clone, PartialEq)]
enum TemplateKind {
    Workflow,
    Scan,
}
impl TemplateKind {
    fn label(self) -> &'static str {
        match self { Self::Workflow => "workflow", Self::Scan => "scan" }
    }
}

async fn run_template(
    name: &str,
    yaml: &'static str,
    kind: TemplateKind,
    args: &ArgMatches,
) -> ExitCode {

    let raw_inputs: Vec<String> = args
        .get_many::<String>("inputs")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let want_json = args.get_flag("json");
    let want_raw = args.get_flag("raw");
    let force_no_color = args.get_flag("no_color");
    let mut style = Style::detect_stderr();
    if force_no_color {
        style.color = false;
    }
    let stdout_tty = std::io::stdout().is_terminal();
    let raw_mode = want_raw || (!want_json && !stdout_tty);

    // Parse template + extract the option/input shape regardless of kind.
    let template = match secator_templates::load_from_str(yaml) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", err(&format!("{} parse: {e}", kind.label()), style));
            return ExitCode::from(1);
        }
    };
    let (options_yaml, input_types, description, tasks_yaml, default_inputs) = match &template {
        secator_templates::Template::Workflow(w) => (
            w.options.clone(),
            w.input_types.clone(),
            w.description.clone(),
            Some(w.tasks.clone()),
            w.default_inputs.clone(),
        ),
        secator_templates::Template::Scan(s) => (
            s.options.clone(),
            s.input_types.clone(),
            s.description.clone(),
            None,
            s.default_inputs.clone(),
        ),
        secator_templates::Template::Profile(_) => {
            eprintln!("{}", err("profiles can't be run", style));
            return ExitCode::from(1);
        }
    };
    let mut initial_opts = collect_workflow_opts_from_matches(&options_yaml, args);
    if let Some(tasks) = &tasks_yaml {
        collect_task_opts_from_matches(tasks, args, &mut initial_opts);
    }

    // Apply --profiles / -pf (+ CONFIG.profiles_defaults) to initial_opts.
    // Non-enforced profiles fill gaps left by the user; enforced override.
    apply_profile_opts(args.get_one::<String>("profiles").map(String::as_str), &mut initial_opts, style);

    // Expand raw CLI inputs: file → lines, `a,b,c` → split, stdin if piped.
    let input_types_str: Vec<&str> = input_types.iter().map(|s| s.as_str()).collect();
    let inputs = expand_inputs(raw_inputs, &input_types_str);
    // Python `default_inputs: ''` means "OK to run with no targets" — workflows
    // like `cidr_recon` use it because their first stage (netdetect) synthesises
    // its own state. Absent or non-empty default → require at least one input.
    if inputs.is_empty() && default_inputs.is_none() {
        eprintln!("{}", err("no targets — pass positional args, a comma list, a file, or pipe via stdin", style));
        return ExitCode::from(2);
    }

    // Lifecycle header.
    let target_word = if inputs.len() == 1 { "target" } else { "targets" };
    eprintln!(
        "{}",
        info(&format!("Loaded {} {target_word} for {} {}", inputs.len(), kind.label(), name), style)
    );
    for t in &inputs {
        let kt = secator_model::autodetect_type(t);
        eprintln!("{}", target_line(t, &kt, style));
    }
    if let Some(desc) = description.as_deref() {
        let title = match kind { TemplateKind::Workflow => "Workflow", TemplateKind::Scan => "Scan" };
        eprintln!(
            "{}",
            info(&format!("{title} {name} ({desc}) started"), style),
        );
    }

    // Build the runner tree. Scans resolve their `workflows:` block via the
    // built-in workflow registry; workflows just pass `|_| None`.
    let find_workflow = |wf_name: &str| -> Option<secator_templates::WorkflowDef> {
        let wf_yaml = workflows::get(wf_name)?;
        match secator_templates::load_from_str(wf_yaml).ok()? {
            secator_templates::Template::Workflow(w) => Some(w),
            _ => None,
        }
    };
    let mut tree = match secator_templates::build_runner_tree(&template, find_workflow) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", err(&format!("tree build: {e}"), style));
            return ExitCode::from(1);
        }
    };
    let opts_for_prune = opts_to_yaml_mapping(&initial_opts);
    secator_templates::prune(&mut tree, &opts_for_prune, &inputs);

    // Print a compact summary of the pruned tree (Python parity: "Workflow built: ...").
    eprintln!("      {}", tree.render().replace('\n', "\n      "));

    // Inspection-only flags: print the requested view and exit before any
    // subprocess is spawned. `--tree` is satisfied by the line above; this
    // handles `--yaml` and `--dry-run`.
    let want_tree = args.get_flag("tree");
    let want_yaml = args.get_flag("yaml");
    let want_dry = args.get_flag("dry_run");
    if want_yaml {
        // Re-emit the workflow YAML with the resolved `initial_opts` merged into
        // the `options:` block (lossy but useful for inspection / piping).
        let parsed: Yaml = serde_yaml::from_str(yaml).unwrap_or(Yaml::Null);
        let mut display = parsed.as_mapping().cloned().unwrap_or_default();
        let mut applied = display
            .get(Yaml::String("options".into()))
            .and_then(|v| v.as_mapping())
            .cloned()
            .unwrap_or_default();
        for (k, v) in &initial_opts {
            applied.insert(Yaml::String(k.clone()), expr_to_yaml(v));
        }
        display.insert(Yaml::String("options".into()), Yaml::Mapping(applied));
        println!("{}", serde_yaml::to_string(&Yaml::Mapping(display)).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    if want_dry {
        // Build the plan and print each task's resolved cmd; do NOT spawn anything.
        let plan = secator_dag::compile(&tree);
        print_dry_run(&plan, &inputs, &initial_opts, style);
        return ExitCode::SUCCESS;
    }
    if want_tree {
        return ExitCode::SUCCESS;
    }

    // Decide local vs per-task remote routing for this workflow run.
    let want_worker = args.get_flag("worker");
    let want_sync = args.get_flag("sync");
    let broker_root = secator_config::get().dirs.celery_data.clone();
    let worker_alive = secator_exec::broker::FileBroker::new(&broker_root)
        .map(|b| b.worker_alive())
        .unwrap_or(false);
    let use_remote = if want_sync {
        false
    } else if want_worker {
        if !worker_alive {
            eprintln!(
                "{}",
                err(
                    "No worker is alive — start one with `secator worker` or omit --worker.",
                    style,
                )
            );
            return ExitCode::from(2);
        }
        true
    } else {
        worker_alive
    };

    if use_remote {
        eprintln!(
            "{}",
            info(
                "Worker available, routing every task to the file broker",
                style,
            )
        );
    } else if !want_sync {
        eprintln!("{}", info("No worker available, running every task locally", style));
    }

    // Allocate this run's reports folder UP FRONT so every child task can write
    // its output files into `<reports>/.outputs/` instead of falling back to
    // `/tmp`. Python parity: the outer runner owns the folder; child tasks
    // inherit it via `self.reports_folder`.
    let config = secator_config::get();
    let workspace = resolve_workspace(args, &config);
    let reports_folder =
        secator_report::next_reports_folder(&config.dirs.reports, &workspace, kind.label()).ok();
    if let Some(rf) = &reports_folder {
        eprintln!("{}", info(&format!("Outputs folder: {}", rf.display()), style));
    }

    // Compile + execute via LocalTransport (with optional remote attachment).
    let plan = secator_dag::compile(&tree);
    let lookup: Arc<dyn secator_exec::TaskLookup> =
        Arc::new(
            secator_exec::StaticLookup::new(secator_tasks::all())
                .with_native(secator_tasks::native_all()),
        );
    let mut transport = secator_exec::LocalTransport::new(lookup)
        .with_verbose(resolve_verbose(args));
    if let Some(rf) = &reports_folder {
        transport = transport.with_reports_folder(rf.clone());
    }
    if use_remote {
        match secator_exec::FileTransport::open(broker_root) {
            Ok(ft) => transport = transport.with_remote(ft),
            Err(e) => {
                eprintln!("{}", err(&format!("broker open failed: {e}"), style));
                return ExitCode::from(1);
            }
        }
    }

    // Capture resolved opts as String map before consuming `initial_opts` so
    // `finalize_run_with_timing` can round-trip them into `info.run_opts`
    // (Python parity, B-INFO-OPTS / #165).
    let captured_opts = opts_to_run_opts(&initial_opts);
    let start_time = unix_time();

    let (tx, mut rx) = mpsc::channel::<OutputItem>(128);
    let inputs_for_run = inputs.clone();
    let exec_handle = tokio::spawn(async move {
        transport.execute(&plan, inputs_for_run, initial_opts, tx).await
    });

    // Stream rendering + collection (same shape as the task path).
    let mut collected: Vec<OutputItem> = Vec::new();
    let mut findings = 0u32;
    let mut errors = 0u32;
    // Emit a Target per CLI input — Python parity (#168). Workflow leaf tasks
    // get tag_meta from `secator-exec::tag_meta`, but the run-level Target
    // anchor isn't synthesised by any of them, so it has to come from here.
    for input in &inputs {
        let mut t = OutputItem::Target(secator_model::Target {
            name: input.clone(),
            ..Default::default()
        });
        stamp_task_meta(&mut t, name);
        collected.push(t);
    }
    while let Some(item) = rx.recv().await {
        if matches!(item, OutputItem::Error(_)) { errors += 1; }
        if item.is_finding() { findings += 1; }
        if want_json {
            let json = serde_json::to_string(&item.to_map()).unwrap_or_default();
            println!("{json}");
        } else if raw_mode {
            if let Some(r) = raw(&item) {
                println!("{r}");
            }
            if let Some(line) = render(&item, style) {
                eprintln!("{line}");
            }
        } else if let Some(line) = render(&item, style) {
            eprintln!("{line}");
        }
        collected.push(item);
    }
    let _ = exec_handle.await;

    finalize_run_with_timing(
        name,
        description.as_deref().unwrap_or(""),
        kind.label(),
        inputs.clone(),
        workspace,
        reports_folder,
        collected,
        findings,
        errors,
        style,
        start_time,
        unix_time(),
        captured_opts,
    )
}

/// Read workflow option values from clap matches, converting list-typed options into
/// `ExprValue::List` (so `'x' in opts.scanners` is true membership, not substring).
/// Also harvests the workflow-level common opts (threads/rate_limit/header/...).
/// Convert a `serde_yaml::Value` (an option's declared `default`) into the
/// typed `ExprValue` the runtime expression scope wants. Used by
/// [`collect_workflow_opts_from_matches`] when the operator didn't pass a
/// CLI flag for an `internal: True` workflow option.
fn yaml_to_expr_value(value: &Yaml, ty: &str) -> Option<ExprValue> {
    match value {
        Yaml::Bool(b) => Some(ExprValue::Bool(*b)),
        Yaml::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Some(ExprValue::Int(i));
            }
            if let Some(f) = n.as_f64() {
                return Some(ExprValue::Float(f));
            }
            None
        }
        Yaml::String(s) => {
            if ty == "list" {
                // String-shaped list default like `"a,b,c"` — split it.
                Some(ExprValue::List(
                    s.split(',')
                        .filter(|p| !p.is_empty())
                        .map(|p| ExprValue::Str(p.trim().to_string()))
                        .collect(),
                ))
            } else {
                Some(ExprValue::Str(s.clone()))
            }
        }
        Yaml::Sequence(items) => Some(ExprValue::List(
            items
                .iter()
                .filter_map(|v| match v {
                    Yaml::String(s) => Some(ExprValue::Str(s.clone())),
                    Yaml::Bool(b) => Some(ExprValue::Bool(*b)),
                    Yaml::Number(n) => n.as_i64().map(ExprValue::Int).or_else(|| n.as_f64().map(ExprValue::Float)),
                    _ => None,
                })
                .collect(),
        )),
        _ => None,
    }
}

fn collect_workflow_opts_from_matches(
    options_yaml: &Mapping,
    args: &ArgMatches,
) -> BTreeMap<String, ExprValue> {
    let mut out: BTreeMap<String, ExprValue> = BTreeMap::new();
    for (k, v) in options_yaml {
        let name = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        let conf = v.as_mapping().cloned().unwrap_or_default();
        let is_flag = conf
            .get(Yaml::String("is_flag".into()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ty = conf
            .get(Yaml::String("type".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("str");
        if is_flag {
            out.insert(name.into(), ExprValue::Bool(args.get_flag(name)));
        } else if let Some(s) = args.get_one::<String>(name) {
            let v = if ty == "list" {
                ExprValue::List(
                    s.split(',').filter(|p| !p.is_empty()).map(|p| ExprValue::Str(p.to_string())).collect(),
                )
            } else if ty == "int" {
                s.parse::<i64>().map(ExprValue::Int).unwrap_or(ExprValue::Str(s.clone()))
            } else {
                ExprValue::Str(s.clone())
            };
            out.insert(name.into(), v);
        } else if let Some(default) = conf.get(Yaml::String("default".into())) {
            // No CLI value supplied — pull the workflow's YAML default into
            // the runtime opts so leaf-task conditions like
            // `'xurlfind3r' in opts.crawlers and opts.passive` evaluate
            // against the real default list, not against an undefined value.
            // Python parity: `internal: True` options never reach the CLI
            // surface but their defaults still propagate to children.
            if let Some(v) = yaml_to_expr_value(default, ty) {
                out.insert(name.into(), v);
            }
        }
    }
    // Common opts that propagate to all tasks. `get_one` returns None when the user
    // didn't pass the flag (we don't set default_value() for these), so unset opts
    // don't override per-task schema defaults.
    for name in ["threads", "rate_limit", "timeout"] {
        if let Some(v) = args.get_one::<i64>(name) {
            out.insert(name.into(), ExprValue::Int(*v));
        }
    }
    if let Some(v) = args.get_one::<f64>("delay") {
        out.insert("delay".into(), ExprValue::Float(*v));
    }
    for name in ["header", "proxy"] {
        if let Some(v) = args.get_one::<String>(name) {
            out.insert(name.into(), ExprValue::Str(v.clone()));
        }
    }
    out
}

/// Read each unique task class's task-specific opts from `args` and merge them into
/// `out`. Per-task opts in the workflow flow through `initial_opts` (Python parity:
/// a workflow-level `--scan-type c` propagates to every task whose schema has
/// `scan_type`; tasks without it ignore the unknown key thanks to `key_map`).
fn collect_task_opts_from_matches(
    tasks: &Mapping,
    args: &ArgMatches,
    out: &mut BTreeMap<String, ExprValue>,
) {
    // Build a wrapper mapping so we can reuse `collect_task_classes`.
    let mut wrapper = Mapping::new();
    wrapper.insert(Yaml::String("tasks".into()), Yaml::Mapping(tasks.clone()));
    let classes = collect_task_classes(&wrapper);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for class in classes {
        let schema = match schema_for_class(&class) {
            Some(s) => s,
            None => continue,
        };
        for opt in schema.opts.iter() {
            if opt.internal || !seen.insert(opt.name.to_string()) {
                continue;
            }
            // The arg id matches `opt.name` (see `build_arg_from_spec`).
            let value: Option<ExprValue> =
                if opt.is_flag || matches!(opt.ty, secator_options::OptType::Bool) {
                    if args.try_get_one::<bool>(opt.name).unwrap_or(None).copied().unwrap_or(false) {
                        Some(ExprValue::Bool(true))
                    } else {
                        None
                    }
                } else {
                    match &opt.ty {
                        secator_options::OptType::Int => args
                            .try_get_one::<i64>(opt.name)
                            .unwrap_or(None)
                            .copied()
                            .map(ExprValue::Int),
                        secator_options::OptType::Float => args
                            .try_get_one::<f64>(opt.name)
                            .unwrap_or(None)
                            .copied()
                            .map(ExprValue::Float),
                        _ => args
                            .try_get_one::<String>(opt.name)
                            .unwrap_or(None)
                            .cloned()
                            .map(ExprValue::Str),
                    }
                };
            if let Some(v) = value {
                out.insert(opt.name.to_string(), v);
            }
        }
    }
}

/// Convert `BTreeMap<String, ExprValue>` to a `serde_yaml::Mapping` for `prune`.
fn opts_to_yaml_mapping(opts: &BTreeMap<String, ExprValue>) -> Mapping {
    let mut m = Mapping::new();
    for (k, v) in opts {
        m.insert(Yaml::String(k.clone()), expr_to_yaml(v));
    }
    m
}

/// Resolve the workspace name to use for this run's reports folder:
///   1. `--workspace`/`--ws` CLI flag (highest)
///   2. `workspace.default` from config
///   3. literal `"default"` (Python parity — never empty on disk)
fn resolve_workspace(args: &ArgMatches, config: &secator_config::Config) -> String {
    if let Some(name) = args.get_one::<String>("workspace") {
        if !name.trim().is_empty() {
            return name.trim().to_string();
        }
    }
    if !config.workspace.default.is_empty() {
        return config.workspace.default.clone();
    }
    "default".into()
}

/// Task-path variant of `apply_profile_opts`: splices profile opts into a
/// task's `BTreeMap<String, String>` runner opts (strings, not ExprValue).
/// Non-enforced fills gaps; enforced overrides.
fn apply_profile_opts_to_runner_opts(
    profile_names_csv: Option<&str>,
    runner_opts: &mut BTreeMap<String, String>,
    style: Style,
) {
    let config = secator_config::get();
    let mut want: Vec<String> = Vec::new();
    if let Some(csv) = profile_names_csv {
        for p in csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            want.push(p.to_string());
        }
    }
    for p in &config.profiles.defaults {
        if !want.iter().any(|x| x == p) {
            want.push(p.clone());
        }
    }
    if want.is_empty() {
        return;
    }
    let mut loaded: Vec<secator_templates::ProfileDef> = Vec::new();
    for name in &want {
        match profiles::load(name) {
            Some(p) => loaded.push(p),
            None => eprintln!(
                "{}",
                err(
                    &format!("Profile {name:?} was not found. Run `secator p list`."),
                    style,
                )
            ),
        }
    }
    let mut ordered: Vec<secator_templates::ProfileDef> = Vec::new();
    ordered.extend(loaded.iter().filter(|p| !p.enforce).cloned());
    ordered.extend(loaded.iter().filter(|p| p.enforce).cloned());
    for profile in &ordered {
        let opts_str: Vec<String> = profile
            .opts
            .iter()
            .filter_map(|(k, v)| Some(format!("{}={}", k.as_str()?, yaml_to_display(v))))
            .collect();
        let label = if profile.enforce { " (enforced)" } else { "" };
        eprintln!(
            "{}",
            info(
                &format!(
                    "Loaded profile {}{}: {} [{}]",
                    profile.name,
                    label,
                    profile.description.as_deref().unwrap_or(""),
                    opts_str.join(", "),
                ),
                style,
            )
        );
        for (k, v) in &profile.opts {
            let key = match k.as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let val = yaml_to_display(v);
            if profile.enforce {
                runner_opts.insert(key, val);
            } else {
                runner_opts.entry(key).or_insert(val);
            }
        }
    }
}

/// Convert a YAML value into an `ExprValue` for `initial_opts`. Mirrors
/// `expr_to_yaml` but in the opposite direction. Used by `apply_profile_opts`
/// to splice profile values into the runner's `initial_opts`.
fn yaml_to_expr(v: &Yaml) -> ExprValue {
    match v {
        Yaml::Bool(b) => ExprValue::Bool(*b),
        Yaml::Number(n) => {
            if let Some(i) = n.as_i64() {
                ExprValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                ExprValue::Float(f)
            } else {
                ExprValue::Str(n.to_string())
            }
        }
        Yaml::String(s) => ExprValue::Str(s.clone()),
        Yaml::Sequence(items) => ExprValue::List(items.iter().map(yaml_to_expr).collect()),
        Yaml::Mapping(m) => {
            let mut out: BTreeMap<String, ExprValue> = BTreeMap::new();
            for (k, v) in m {
                if let Some(k) = k.as_str() {
                    out.insert(k.to_string(), yaml_to_expr(v));
                }
            }
            ExprValue::Map(out)
        }
        Yaml::Null => ExprValue::Null,
        Yaml::Tagged(t) => yaml_to_expr(&t.value),
    }
}

/// Resolve a comma-separated profile list into loaded `ProfileDef`s, splice
/// their opts into `initial_opts`, and print loaded-profile lines on stderr.
///
/// Mirrors Python's `Runner.resolve_profiles`:
///   * defaults from `profiles_defaults` are appended (deduplicated)
///   * non-enforced profiles supply a value only if the user didn't set one
///   * enforced profiles always win — they're applied last
fn apply_profile_opts(
    profile_names_csv: Option<&str>,
    initial_opts: &mut BTreeMap<String, ExprValue>,
    style: Style,
) {
    let config = secator_config::get();
    // Build the dedup'd resolution list: user-supplied first, then defaults.
    let mut want: Vec<String> = Vec::new();
    if let Some(csv) = profile_names_csv {
        for p in csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            want.push(p.to_string());
        }
    }
    for p in &config.profiles.defaults {
        if !want.iter().any(|x| x == p) {
            want.push(p.clone());
        }
    }
    if want.is_empty() {
        return;
    }
    // Load each; warn for unknowns (Python parity).
    let mut loaded: Vec<secator_templates::ProfileDef> = Vec::new();
    for name in &want {
        match profiles::load(name) {
            Some(p) => loaded.push(p),
            None => eprintln!(
                "{}",
                err(
                    &format!("Profile {name:?} was not found. Run `secator p list` to see available profiles."),
                    style,
                )
            ),
        }
    }
    if loaded.is_empty() {
        return;
    }
    // Sort: non-enforced first, enforced last (so enforced.update() wins).
    let mut ordered: Vec<secator_templates::ProfileDef> = Vec::new();
    ordered.extend(loaded.iter().filter(|p| !p.enforce).cloned());
    ordered.extend(loaded.iter().filter(|p| p.enforce).cloned());
    for profile in &ordered {
        let label = if profile.enforce { " (enforced)" } else { "" };
        let opts_str: Vec<String> = profile
            .opts
            .iter()
            .filter_map(|(k, v)| Some(format!("{}={}", k.as_str()?, yaml_to_display(v))))
            .collect();
        let desc = profile.description.as_deref().unwrap_or("");
        eprintln!(
            "{}",
            info(
                &format!(
                    "Loaded profile {}{}: {} [{}]",
                    profile.name,
                    label,
                    desc,
                    opts_str.join(", "),
                ),
                style,
            )
        );
        for (k, v) in &profile.opts {
            let k = match k.as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            if profile.enforce {
                // Enforced: always overwrite.
                initial_opts.insert(k, yaml_to_expr(v));
            } else {
                // Non-enforced: only fill if the user didn't already set it.
                initial_opts.entry(k).or_insert_with(|| yaml_to_expr(v));
            }
        }
    }
}

fn expr_to_yaml(v: &ExprValue) -> Yaml {
    match v {
        ExprValue::Bool(b) => Yaml::Bool(*b),
        ExprValue::Int(i) => Yaml::Number((*i).into()),
        ExprValue::Float(f) => {
            serde_yaml::from_str(&f.to_string()).unwrap_or(Yaml::String(f.to_string()))
        }
        ExprValue::Str(s) => Yaml::String(s.clone()),
        ExprValue::List(items) => Yaml::Sequence(items.iter().map(expr_to_yaml).collect()),
        ExprValue::Map(m) => {
            let mut map = Mapping::new();
            for (k, v) in m {
                map.insert(Yaml::String(k.clone()), expr_to_yaml(v));
            }
            Yaml::Mapping(map)
        }
        ExprValue::Null => Yaml::Null,
    }
}

fn build_worker_subcommand() -> Command {
    Command::new("worker")
        .visible_alias("wk")
        .about("Start a worker daemon that pulls jobs from the file broker")
        .arg(
            Arg::new("concurrency")
                .long("concurrency")
                .short('c')
                .help("Number of parallel claim/process slots")
                .value_parser(clap::value_parser!(usize))
                .default_value("4"),
        )
        .arg(
            Arg::new("id")
                .long("id")
                .help("Worker id (defaults to worker-<random>)")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("no_color")
                .long("no-color")
                .help("Disable ANSI colors")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("redis")
                .long("redis")
                .value_name("URL")
                .help("Pull jobs from a Redis Stream instead of the filesystem broker. \
                       Falls back to config.transport.broker_url when omitted."),
        )
        .arg(
            Arg::new("metrics_addr")
                .long("metrics-addr")
                .value_name("HOST:PORT")
                .help("Expose Prometheus metrics on this address (e.g. 0.0.0.0:9100). \
                       Serves a single `GET /metrics` endpoint."),
        )
}

async fn run_worker_subcommand(args: &ArgMatches) -> ExitCode {
    let concurrency = *args.get_one::<usize>("concurrency").unwrap();
    let id = args.get_one::<String>("id").cloned().unwrap_or_else(|| {
        format!("worker-{}", uuid::Uuid::new_v4().simple())
    });

    let mut style = Style::detect_stderr();
    if args.get_flag("no_color") {
        style.color = false;
    }

    let config = secator_config::get();

    // Optional Prometheus metrics endpoint (`--metrics-addr 0.0.0.0:9100`).
    // Built BEFORE either worker branch so both Redis + FileBroker paths can
    // tick the same counters. The HTTP listener stays up for the lifetime of
    // the process; the JoinHandle is aborted on shutdown.
    let metrics_addr = args.get_one::<String>("metrics_addr").cloned();
    let (metrics, metrics_handle) = match metrics_addr {
        Some(addr) => {
            let m = secator_metrics::Metrics::new();
            match secator_metrics::spawn_server(&addr, Arc::clone(&m)).await {
                Ok((bound, handle)) => {
                    eprintln!(
                        "{}",
                        info(&format!("Metrics server listening on http://{bound}/metrics"), style)
                    );
                    (Some(m), Some(handle))
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        err(&format!("metrics server bind to {addr} failed: {e}"), style)
                    );
                    return ExitCode::from(1);
                }
            }
        }
        None => (None, None),
    };

    // ----- Redis Streams worker path.
    // Picked when `--redis <url>` is passed OR config.transport.broker_url is redis://.
    let redis_url = args.get_one::<String>("redis").cloned().or_else(|| {
        let url = &config.transport.broker_url;
        (url.starts_with("redis://") || url.starts_with("rediss://")).then(|| url.clone())
    });
    if let Some(url) = redis_url {
        let exit = run_redis_worker(&id, &url, concurrency, style, metrics).await;
        if let Some(h) = metrics_handle {
            h.abort();
        }
        return exit;
    }

    let broker_root = &config.dirs.celery_data;
    let broker = match secator_exec::broker::FileBroker::new(broker_root) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", err(&format!("failed to open broker dir {}: {e}", broker_root.display()), style));
            return ExitCode::from(1);
        }
    };
    let lookup: Arc<dyn secator_exec::TaskLookup> =
        Arc::new(
            secator_exec::StaticLookup::new(secator_tasks::all())
                .with_native(secator_tasks::native_all()),
        );

    eprintln!(
        "{}",
        info(
            &format!(
                "Worker {} starting (broker: {}, concurrency: {})",
                id,
                broker_root.display(),
                concurrency,
            ),
            style,
        )
    );
    eprintln!(
        "{}",
        info(&format!("Registered tasks: {}", secator_tasks::registry().join(", ")), style)
    );
    eprintln!("{}", info("Press Ctrl+C to stop.", style));

    let cfg = secator_worker::WorkerConfig {
        id: id.clone(),
        concurrency,
        task_max_timeout: positive_duration(config.transport.task_max_timeout),
        worker_max_tasks_per_child: positive_u64(config.transport.worker_max_tasks_per_child),
        worker_kill_after_idle: positive_duration(config.transport.worker_kill_after_idle_seconds),
        task_memory_limit_mb: positive_u64(config.transport.task_memory_limit_mb),
        worker_kill_after_task: config.transport.worker_kill_after_task,
        ..Default::default()
    };
    let worker = secator_worker::Worker::new(broker, lookup, cfg);
    let worker = match metrics {
        Some(m) => worker.with_metrics(m),
        None => worker,
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let result = worker.run(shutdown).await;
    if let Some(h) = metrics_handle {
        h.abort();
    }

    eprintln!("{}", info(&format!("Worker {id} stopped"), style));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

/// Redis Streams worker: pull WorkUnits via `XREADGROUP`, run them through the
/// in-process `CommandRunner`/`NativeRunner`, emit ResultEnvelope frames back on
/// `secator:results:<job_id>`. Same wire format as `FileBroker` so the client
/// side is transport-agnostic.
async fn run_redis_worker(
    id: &str,
    url: &str,
    concurrency: usize,
    style: Style,
    metrics: Option<Arc<secator_metrics::Metrics>>,
) -> ExitCode {
    let worker = match secator_redis::RedisWorker::new(url, id.to_string()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}", err(&format!("redis worker open failed: {e}"), style));
            return ExitCode::from(1);
        }
    };
    if let Err(e) = worker.ensure_group().await {
        eprintln!("{}", err(&format!("ensure_group failed: {e}"), style));
        return ExitCode::from(1);
    }
    eprintln!(
        "{}",
        info(
            &format!("Worker {id} starting (redis: {url}, concurrency: {concurrency})"),
            style,
        )
    );
    eprintln!(
        "{}",
        info(&format!("Registered tasks: {}", secator_tasks::registry().join(", ")), style)
    );
    eprintln!("{}", info("Press Ctrl+C to stop.", style));

    let worker = std::sync::Arc::new(worker);
    // Semaphore bounds concurrent unit execution. We `acquire_owned()` BEFORE
    // calling `pull()` so that when all slots are busy this worker stops pulling
    // — letting another worker in the consumer group pick up the next unit
    // (proper backpressure, just like Celery's prefetch_count).
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop2 = stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop2.notify_one();
    });

    loop {
        // Wait for a free slot OR a shutdown signal. The permit is held by the
        // spawned task and dropped when the unit finishes.
        let permit = tokio::select! {
            _ = stop.notified() => break,
            p = sem.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break, // semaphore closed → shutdown
            },
        };
        // Race the next pull against shutdown.
        let next = tokio::select! {
            _ = stop.notified() => break,
            r = worker.pull() => r,
        };
        let (entry_id, unit) = match next {
            Ok(Some(p)) => p,
            Ok(None) => {
                // Nothing pulled (block_ms timeout). Release the permit + loop.
                drop(permit);
                continue;
            }
            Err(e) => {
                eprintln!("{}", err(&format!("redis pull failed: {e}"), style));
                drop(permit);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        secator_debug::debug!(
            "redis.worker",
            "{id} processing unit_id={} class={} permits_left={}",
            unit.unit_id,
            unit.task_class,
            sem.available_permits()
        );
        let w = worker.clone();
        let worker_id = id.to_string();
        let m = metrics.clone();
        tokio::spawn(async move {
            run_redis_unit(w, &worker_id, unit, entry_id, m).await;
            drop(permit); // releases the slot for the next pull
        });
    }

    // Wait for in-flight units to drain before exiting (best-effort, 30s cap).
    let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while sem.available_permits() < concurrency.max(1)
        && std::time::Instant::now() < drain_deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    eprintln!("{}", info(&format!("Worker {id} stopped"), style));
    ExitCode::SUCCESS
}

/// Execute one WorkUnit and stream its results back to the per-job stream.
async fn run_redis_unit(
    worker: std::sync::Arc<secator_redis::RedisWorker>,
    worker_id: &str,
    unit: secator_exec::wire::WorkUnit,
    entry_id: String,
    metrics: Option<Arc<secator_metrics::Metrics>>,
) {
    use secator_exec::wire::ResultEnvelope;
    let job_id = unit.job_id.clone();
    let started = std::time::Instant::now();
    let _ = worker
        .emit(&job_id, &ResultEnvelope::Started { worker_id: worker_id.into() })
        .await;

    // Resolve task spec.
    let spec_ref = if let Some(s) = secator_tasks::get(&unit.task_class) {
        Some(s)
    } else {
        None
    };
    let Some(spec) = spec_ref else {
        let _ = worker
            .emit(
                &job_id,
                &ResultEnvelope::WorkerError {
                    worker_id: worker_id.into(),
                    message: format!("unknown task class: {}", unit.task_class),
                },
            )
            .await;
        let _ = worker.ack(&entry_id).await;
        return;
    };

    let mut runner = CommandRunner::new(spec, unit.inputs.clone());
    runner.opts = unit.opts.clone();
    if let Some(rf) = unit.reports_folder.as_ref() {
        runner.reports_folder = Some(std::path::PathBuf::from(rf));
    }

    // Bridge runner items → Redis frames.
    let (tx, mut rx) = mpsc::channel::<OutputItem>(64);
    let run = tokio::spawn(async move { runner.run(tx).await });
    let mut findings = 0u32;
    let mut errors = 0u32;
    while let Some(item) = rx.recv().await {
        if matches!(item, OutputItem::Error(_)) {
            errors += 1;
        }
        if item.is_finding() {
            findings += 1;
            if let Some(m) = &metrics {
                m.inc_finding(item.type_name());
            }
        }
        let map = item.to_map();
        let _ = worker
            .emit(
                &job_id,
                &ResultEnvelope::Item { value: serde_json::Value::Object(map) },
            )
            .await;
    }
    let result = run.await;
    let status = match result {
        Ok(Ok(())) => "SUCCESS".to_string(),
        Ok(Err(e)) => {
            let _ = worker
                .emit(
                    &job_id,
                    &ResultEnvelope::WorkerError {
                        worker_id: worker_id.into(),
                        message: e.to_string(),
                    },
                )
                .await;
            "FAILURE".to_string()
        }
        Err(e) => {
            let _ = worker
                .emit(
                    &job_id,
                    &ResultEnvelope::WorkerError {
                        worker_id: worker_id.into(),
                        message: format!("join: {e}"),
                    },
                )
                .await;
            "FAILURE".to_string()
        }
    };
    let elapsed = started.elapsed().as_secs_f64();
    if let Some(m) = &metrics {
        m.inc_task(&unit.task_class, &status);
        m.observe_task_seconds(&unit.task_class, elapsed);
        m.inc_errors(errors as u64);
    }
    let _ = worker
        .emit(
            &job_id,
            &ResultEnvelope::Finished {
                worker_id: worker_id.into(),
                status,
                findings,
                errors,
                elapsed_seconds: elapsed,
            },
        )
        .await;
    let _ = worker.ack(&entry_id).await;
    secator_debug::debug!("redis.worker", "{worker_id} finished unit_id={} in {elapsed:.2}s", unit.unit_id);
}

fn build_task_subcommand() -> Command {
    let mut grp = Command::new("task")
        .about("Run a single task")
        .visible_alias("x")
        .visible_alias("t")
        .visible_alias("tasks")
        .subcommand_required(true)
        .arg_required_else_help(true);
    for spec in secator_tasks::all() {
        grp = grp.subcommand(build_task_cmd(spec));
    }
    for nspec in secator_tasks::native_all() {
        grp = grp.subcommand(build_native_task_cmd(nspec));
    }
    grp
}

fn build_task_cmd(spec: &'static secator_runner::TaskSpec) -> Command {
    let metavar: &'static str = if spec.input_types.is_empty() {
        "TARGET"
    } else {
        Box::leak(spec.input_types.join("|").into_boxed_str())
    };
    let mut cmd = Command::new(spec.name)
        .about(spec.description)
        .arg(
            // Optional at the clap layer: `expand_inputs` reads stdin when no
            // positionals are passed, and emits a clear error if it ends up empty.
            Arg::new("inputs")
                .help("Target(s) — positional, comma-separated list, file path, or stdin")
                .value_name(metavar)
                .num_args(0..),
        )
        // CLI-global flags (separate namespace from per-task opts).
        .arg(global_flag("json", "Print items as JSON lines on stdout"))
        .arg(global_flag("raw", "Print only the primary field of each item on stdout (for piping)"))
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Show the underlying tool's stderr output (banners, logs)")
                .action(ArgAction::SetTrue),
        )
        .arg(global_flag("no_color", "Disable ANSI colors"))
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Print the cmd that would run; do not spawn a subprocess")
                .action(ArgAction::SetTrue),
        )
        // Worker / sync routing flags. By default the CLI auto-detects: if a worker is
        // heartbeating on the broker dir, route the task there; otherwise run locally.
        .arg(
            Arg::new("worker")
                .long("worker")
                .help("Force remote execution via the file broker (fails if no worker alive)")
                .action(ArgAction::SetTrue)
                .conflicts_with("sync"),
        )
        .arg(
            Arg::new("sync")
                .long("sync")
                .help("Force local (in-process) execution, even if a worker is available")
                .action(ArgAction::SetTrue),
        )
        // Profile + workspace flags — same shape as the workflow/scan path.
        .arg(
            Arg::new("profiles")
                .long("profiles")
                .visible_alias("pf")
                .value_name("LIST")
                .help("Comma-separated profile names to apply (see `secator p list`)"),
        )
        .arg(
            Arg::new("workspace")
                .long("workspace")
                .visible_alias("ws")
                .value_name("NAME")
                .help("Override the workspace name for this run's reports folder"),
        );

    // Per-task options from the schema. Meta-opts (shared HTTP/recon set) come first
    // for stable help ordering, then task-specific opts (mirrors Python's grouping).
    // `KeyMap::NotSupported` hides an opt from the CLI only when it's a META opt — task
    // own opts may still need to be CLI-visible because hooks read them from
    // `runner.opts` directly (Python's "internal pattern": `gf`'s positional `pattern`,
    // `dirsearch`'s `output_path`, `msfconsole`'s `execute_command`, …).
    let schema = (spec.schema)();
    // Dedup: a task opt with the same name as a meta opt overrides the meta opt
    // entirely (ffuf's `data` with short `-d` wins over the canonical `data`
    // meta). Also track shorts so meta opts that collide with task-claimed
    // letters silently drop their short.
    let task_opt_names: std::collections::BTreeSet<&str> =
        schema.opts.iter().map(|o| o.name).collect();
    let mut taken_shorts: std::collections::BTreeSet<char> =
        ["v", "h"].iter().filter_map(|s| s.chars().next()).collect();
    for opt in schema.opts.iter() {
        if let Some(s) = opt.short {
            if s.chars().count() == 1 {
                if let Some(c) = s.chars().next() {
                    taken_shorts.insert(c);
                }
            }
        }
    }
    for opt in schema.meta_opts.iter() {
        if matches!(schema.key_map.get(opt.name), Some(KeyMap::NotSupported)) {
            continue;
        }
        if opt.internal {
            continue;
        }
        if task_opt_names.contains(opt.name) {
            // Task's own opt will register it — skip the meta version.
            continue;
        }
        cmd = cmd.arg(build_arg_from_spec_taken(opt, &mut taken_shorts));
    }
    for opt in schema.opts.iter() {
        if opt.internal {
            continue;
        }
        cmd = cmd.arg(build_arg_from_spec_taken(opt, &mut taken_shorts));
    }
    cmd
}

/// Like `build_task_cmd` but for in-process native tasks. The CLI surface is
/// the same shape (positional `inputs` + global flags + per-task opts) — the
/// only differences are the lack of `--worker` (native tasks always run
/// in-process) and the schema source. Kept as a parallel function rather than
/// generic-over-spec for clarity.
fn build_native_task_cmd(spec: &'static secator_runner::NativeSpec) -> Command {
    let metavar: &'static str = if spec.input_types.is_empty() {
        "TARGET"
    } else {
        Box::leak(spec.input_types.join("|").into_boxed_str())
    };
    let mut cmd = Command::new(spec.name)
        .about(spec.description)
        .arg(
            Arg::new("inputs")
                .help("Target(s) — positional, comma-separated list, file path, or stdin")
                .value_name(metavar)
                .num_args(0..),
        )
        .arg(global_flag("json", "Print items as JSON lines on stdout"))
        .arg(global_flag("raw", "Print only the primary field of each item on stdout (for piping)"))
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Show extra detail in stderr output")
                .action(ArgAction::SetTrue),
        )
        .arg(global_flag("no_color", "Disable ANSI colors"))
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Print the resolved inputs/opts; do not run the native task")
                .action(ArgAction::SetTrue),
        )
        // `--worker` / `--sync` are meaningless for native (in-process) tasks
        // but the flags are accepted so operators can pass them uniformly
        // across native + command tasks — the run path always executes locally
        // regardless of what's set here.
        .arg(
            Arg::new("worker")
                .long("worker")
                .help("Force remote execution via the file broker (ignored for native tasks — always local)")
                .action(ArgAction::SetTrue)
                .conflicts_with("sync"),
        )
        .arg(
            Arg::new("sync")
                .long("sync")
                .help("Force local (in-process) execution (default for native tasks)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("profiles")
                .long("profiles")
                .visible_alias("pf")
                .value_name("LIST")
                .help("Comma-separated profile names to apply (see `secator p list`)"),
        )
        .arg(
            Arg::new("workspace")
                .long("workspace")
                .visible_alias("ws")
                .value_name("NAME")
                .help("Override the workspace name for this run's reports folder"),
        );
    let schema = (spec.schema)();
    let task_opt_names: std::collections::BTreeSet<&str> =
        schema.opts.iter().map(|o| o.name).collect();
    let mut taken_shorts: std::collections::BTreeSet<char> =
        ["v", "h"].iter().filter_map(|s| s.chars().next()).collect();
    for opt in schema.opts.iter() {
        if let Some(s) = opt.short {
            if s.chars().count() == 1 {
                if let Some(c) = s.chars().next() {
                    taken_shorts.insert(c);
                }
            }
        }
    }
    for opt in schema.meta_opts.iter() {
        if matches!(schema.key_map.get(opt.name), Some(KeyMap::NotSupported)) {
            continue;
        }
        if opt.internal {
            continue;
        }
        if task_opt_names.contains(opt.name) {
            continue;
        }
        cmd = cmd.arg(build_arg_from_spec_taken(opt, &mut taken_shorts));
    }
    for opt in schema.opts.iter() {
        if opt.internal {
            continue;
        }
        cmd = cmd.arg(build_arg_from_spec_taken(opt, &mut taken_shorts));
    }
    cmd
}

/// Expand raw CLI-provided targets into the runner's input list. Mirrors Python
/// `utils.expand_input`:
/// * file path positional → split by lines (unless the task takes `path`-typed inputs);
/// * comma-separated single arg → split into multiple targets;
/// * `-` shorthand → read stdin (common Unix convention; Python doesn't expose this
///   but it's a low-cost convenience);
/// * empty positionals + piped stdin → auto-read stdin lines (Python `piped_input`);
/// * whitespace-only / empty entries are dropped (matches Python's `.strip()` chain).
///
/// Stdin reads honor a configurable timeout (`SECATOR_CLI_STDIN_TIMEOUT` env, default
/// 1.0s) so a hung upstream doesn't block forever — Python's
/// `select.select(..., stdin_timeout)` behaviour.
fn expand_inputs(raw: Vec<String>, input_types: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let take_path_as_is = input_types.contains(&"path");
    let push = |s: &str, out: &mut Vec<String>| {
        let t = s.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    };
    let read_stdin_into = |out: &mut Vec<String>| {
        let lines = read_stdin_with_timeout(stdin_timeout_secs());
        for line in lines {
            push(&line, out);
        }
    };
    let process_one = |item: &str, out: &mut Vec<String>| {
        // `-` is "read stdin" (Unix convention, Python omits but we accept).
        if item == "-" {
            read_stdin_into(out);
            return;
        }
        if !take_path_as_is && std::path::Path::new(item).is_file() {
            // File path → read each non-empty line as a separate target.
            if let Ok(contents) = std::fs::read_to_string(item) {
                for line in contents.lines() {
                    push(line, out);
                }
                return;
            }
        }
        if item.contains(',') {
            for part in item.split(',') {
                push(part, out);
            }
        } else {
            push(item, out);
        }
    };
    for r in &raw {
        process_one(r, &mut out);
    }
    // Auto-read stdin when no positional targets were given and stdin is piped.
    if raw.is_empty() && !std::io::stdin().is_terminal() {
        read_stdin_into(&mut out);
    }
    out
}

/// Read stdin until EOF, but give up after `timeout_secs` of inactivity. We poll
/// every 100ms with a non-blocking lock-and-fill on the kernel pipe to mirror
/// Python's `select.select([stdin], [], [], timeout)` behaviour. On Windows the
/// timeout is best-effort — we fall back to a blocking read.
fn read_stdin_with_timeout(timeout_secs: f64) -> Vec<String> {
    use std::io::BufRead;
    let mut out = Vec::new();
    let stdin = std::io::stdin();

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = stdin.as_raw_fd();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(timeout_secs);
        // Probe with poll() to see if data is ready; bail when the deadline expires
        // with nothing produced (Python's "No input passed on stdin" path).
        let mut handle = stdin.lock();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() && out.is_empty() {
                return out;
            }
            let ms: i32 = remaining
                .as_millis()
                .min(100)
                .try_into()
                .unwrap_or(100);
            let mut pfd = libc_poll_fd(fd);
            // SAFETY: `poll` is a stable syscall taking a pointer to one pollfd and an
            // event count + timeout. We pass exactly one fd.
            let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, ms) };
            if rc < 0 {
                return out;
            }
            if rc == 0 && out.is_empty() {
                // Still nothing on the pipe and we haven't read any line yet — loop again
                // unless the overall deadline elapsed.
                if std::time::Instant::now() >= deadline {
                    return out;
                }
                continue;
            }
            // Either data ready (rc>0) OR we already have output and the upstream
            // closed (rc==0 + POLLHUP). Read whatever's available.
            let mut line = String::new();
            match handle.read_line(&mut line) {
                Ok(0) => return out, // EOF
                Ok(_) => out.push(line.trim_end_matches(['\n', '\r']).to_string()),
                Err(_) => return out,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = timeout_secs;
        for line in stdin.lock().lines().map_while(|r| r.ok()) {
            out.push(line);
        }
        out
    }
}

#[cfg(unix)]
fn libc_poll_fd(fd: std::os::fd::RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    }
}

fn stdin_timeout_secs() -> f64 {
    std::env::var("SECATOR_CLI_STDIN_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0)
}

/// Print a `--dry-run` view of a compiled plan: for each task node, show its id,
/// description, the resolved `if:` condition (when present), and the cmd that
/// **would** be assembled with the static opts. Runtime extractors over prior
/// results can't be resolved at dry-run time (there are no results yet), so we
/// show the static cmd template — the same one the operator sees at `⚡` time
/// for first-stage tasks.
fn print_dry_run(
    plan: &secator_dag::Plan,
    inputs: &[String],
    opts: &BTreeMap<String, ExprValue>,
    _style: Style,
) {
    fn walk(node: &secator_dag::Plan, inputs: &[String], opts: &BTreeMap<String, ExprValue>) {
        match node {
            secator_dag::Plan::Chain(items) | secator_dag::Plan::Group(items) => {
                for item in items {
                    walk(item, inputs, opts);
                }
            }
            secator_dag::Plan::Task(tp) => {
                if let Some(spec) = secator_tasks::get(&tp.class) {
                    let desc = tp.description.as_deref().unwrap_or(spec.description);
                    eprintln!("[dry-run] {} ({desc})", tp.id);
                    if let Some(c) = &tp.condition {
                        eprintln!("           if: {c}");
                    }
                    let resolved_inputs = if tp.target_extractors.is_empty() {
                        inputs.to_vec()
                    } else {
                        Vec::new()
                    };
                    let mut merged: BTreeMap<String, ExprValue> = opts.clone();
                    for (k, v) in &tp.opts {
                        merged.insert(k.clone(), v.clone());
                    }
                    let mut runner = secator_runner::CommandRunner::new(spec, resolved_inputs.clone());
                    runner.opts = opts_to_run_opts(&merged);
                    runner.aliases = vec![tp.class.clone()];
                    if resolved_inputs.is_empty() {
                        eprintln!("           inputs: <from extractors>");
                    } else {
                        let _ = runner.prepare();
                        eprintln!("           cmd: {}", runner.build_cmd_with_hooks());
                    }
                } else if let Some(nspec) = secator_tasks::get_native(&tp.class) {
                    let desc = tp.description.as_deref().unwrap_or(nspec.description);
                    eprintln!("[dry-run] {} ({desc}) [native]", tp.id);
                    if let Some(c) = &tp.condition {
                        eprintln!("           if: {c}");
                    }
                } else {
                    eprintln!("[dry-run] {} — unknown task class", tp.id);
                }
            }
        }
    }
    walk(plan, inputs, opts);
}

/// Convert `BTreeMap<String, ExprValue>` to `BTreeMap<String, String>` for
/// `CommandRunner.opts` — same logic as `secator-exec::opts_to_run_opts` (lifted
/// here so the CLI can build dry-run cmds without depending on the exec crate's
/// internals).
fn opts_to_run_opts(opts: &BTreeMap<String, ExprValue>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in opts {
        let s = match v {
            ExprValue::Str(s) => s.clone(),
            ExprValue::Bool(b) => b.to_string(),
            ExprValue::Int(i) => i.to_string(),
            ExprValue::Float(f) => f.to_string(),
            ExprValue::List(items) => items
                .iter()
                .map(|x| match x {
                    ExprValue::Str(s) => s.clone(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(","),
            ExprValue::Map(_) | ExprValue::Null => continue,
        };
        out.insert(k.clone(), s);
    }
    out
}

/// Walk a workflow YAML mapping and return the unique task class names it references.
/// `tasks:` is a map of `<node_id>:<config>` where the node id may carry a `/profile`
/// suffix (e.g. `nmap/light`) and `_group` keys group siblings. We strip the suffix to
/// land on the class (`nmap`) and skip the `_group` containers themselves.
fn collect_task_classes(mapping: &Mapping) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let push = |raw: &str, out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
        let class = raw.split('/').next().unwrap_or(raw).to_string();
        if class.starts_with('_') || class.is_empty() {
            return;
        }
        if seen.insert(class.clone()) {
            out.push(class);
        }
    };
    let tasks = match mapping.get(Yaml::String("tasks".into())).and_then(|v| v.as_mapping()) {
        Some(t) => t,
        None => return out,
    };
    for (k, v) in tasks {
        let key = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        if key.starts_with('_') {
            // _group containers — recurse one level.
            if let Some(inner) = v.as_mapping() {
                for (ik, _) in inner {
                    if let Some(s) = ik.as_str() {
                        push(s, &mut out, &mut seen);
                    }
                }
            }
        } else {
            push(key, &mut out, &mut seen);
        }
    }
    out
}

fn global_flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name.replace('_', "-").leak() as &str)
        .help(help)
        .action(ArgAction::SetTrue)
}

/// Same as [`build_arg_from_spec`] but drops the short flag when it'd collide
/// with an already-claimed letter. Used by the per-task builders so meta opts
/// can't shadow a task's own short flag (e.g. ffuf's `-d` for `data`).
fn build_arg_from_spec_taken(
    opt: &OptSpec,
    taken: &mut std::collections::BTreeSet<char>,
) -> Arg {
    let arg = build_arg_from_spec(opt);
    if let Some(s) = opt.short {
        if s.chars().count() == 1 {
            if let Some(c) = s.chars().next() {
                // First-come-first-served: caller seeded with task opts already,
                // so meta opts arriving with a colliding short land here and
                // we drop their short by re-emitting the arg without `.short()`.
                // If this opt is the FIRST to claim the letter, leave the arg
                // alone and mark the letter taken for everyone after it.
                if taken.contains(&c) && opt_short_already_emitted_for_other(opt) {
                    // Rebuild without the short.
                    return strip_short(opt);
                } else {
                    taken.insert(c);
                }
            }
        }
    }
    arg
}

/// True when this opt's short letter was pre-claimed by another opt during the
/// build_task_cmd seed pass — i.e. a task opt has the same short. We treat that
/// as "task opt wins". For native tasks (which only have one opts set) this
/// returns false because there's no competing opt.
fn opt_short_already_emitted_for_other(_opt: &OptSpec) -> bool {
    // The seed loop in build_task_cmd / build_native_task_cmd populates
    // `taken_shorts` with task opts BEFORE meta opts are processed, so by the
    // time we get here for a meta opt, its conflict has already been recorded.
    // The check happens at the call site (`if taken.contains(&c)`) — this
    // function exists so callers can override per-opt logic if needed; default
    // returns true so meta opts always yield to the task's claim.
    true
}

/// Rebuild a clap `Arg` from `opt` but force no short flag. Used to resolve
/// collisions detected in [`build_arg_from_spec_taken`].
fn strip_short(opt: &OptSpec) -> Arg {
    let long_str: &'static str = Box::leak(opt.name.replace('_', "-").into_boxed_str());
    let mut arg = Arg::new(opt.name).long(long_str).help(opt.help);
    if opt.is_flag || matches!(opt.ty, OptType::Bool) {
        arg = arg.action(ArgAction::SetTrue);
    } else {
        match &opt.ty {
            OptType::Int => arg = arg.value_parser(clap::value_parser!(i64)),
            OptType::Float => arg = arg.value_parser(clap::value_parser!(f64)),
            _ => {}
        }
        if let Some(d) = opt.default {
            arg = arg.default_value(d);
        }
    }
    arg
}

/// Translate an `OptSpec` into a clap `Arg`. Canonical name stays underscored (the key
/// `runner.opts` will use); the long form is kebab-case.
fn build_arg_from_spec(opt: &OptSpec) -> Arg {
    let long_str: &'static str = Box::leak(opt.name.replace('_', "-").into_boxed_str());
    let mut arg = Arg::new(opt.name).long(long_str).help(opt.help);

    // Use short only when it's a single character — clap requires `char` for `short`.
    if let Some(s) = opt.short {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() == 1 {
            arg = arg.short(chars[0]);
        }
    }

    if opt.is_flag || matches!(opt.ty, OptType::Bool) {
        arg = arg.action(ArgAction::SetTrue);
    } else {
        // Typed value.
        match &opt.ty {
            OptType::Int => arg = arg.value_parser(clap::value_parser!(i64)),
            OptType::Float => arg = arg.value_parser(clap::value_parser!(f64)),
            OptType::Choice(_) => {
                // TODO: leak the choice list to `&'static str` when a task actually
                // uses `OptType::Choice` (no MVP task does today).
            }
            _ => {}
        }
        if let Some(d) = opt.default {
            arg = arg.default_value(d);
        }
    }
    arg
}

/// Walk every per-task arg in the parsed matches and populate `runner.opts` with the
/// stringified value. Booleans only enter the map when set true (so `is_flag` opts that
/// the user didn't pass stay absent, mirroring the Python "falsy → skip" rule).
fn collect_opts_into_runner(
    spec: &'static secator_runner::TaskSpec,
    args: &ArgMatches,
    runner: &mut CommandRunner,
) {
    let schema = (spec.schema)();
    // Same rule as `build_task_cmd`: meta opts honor `KeyMap::NotSupported`, task
    // opts ignore it (they may still need to reach `runner.opts` for hooks).
    let collect = |opt: &OptSpec, runner: &mut CommandRunner| {
        let value: Option<String> = if opt.is_flag || matches!(opt.ty, OptType::Bool) {
            if args.get_flag(opt.name) { Some("true".into()) } else { None }
        } else {
            match &opt.ty {
                OptType::Int => args.get_one::<i64>(opt.name).map(|v| v.to_string()),
                OptType::Float => args.get_one::<f64>(opt.name).map(|v| v.to_string()),
                _ => args.get_one::<String>(opt.name).cloned(),
            }
        };
        if let Some(v) = value {
            runner.opts.insert(opt.name.to_string(), v);
        }
    };
    for opt in schema.meta_opts.iter() {
        if matches!(schema.key_map.get(opt.name), Some(KeyMap::NotSupported)) || opt.internal {
            continue;
        }
        collect(opt, runner);
    }
    for opt in schema.opts.iter() {
        if opt.internal {
            continue;
        }
        collect(opt, runner);
    }
}

/// Native counterpart of [`collect_opts_into_runner`]. Identical option-handling
/// logic; only the receiver type differs (`NativeRunner.opts` is a `BTreeMap` too).
fn collect_opts_into_native_runner(
    spec: &'static secator_runner::NativeSpec,
    args: &ArgMatches,
    runner: &mut secator_runner::NativeRunner,
) {
    let schema = (spec.schema)();
    let collect = |opt: &OptSpec, runner: &mut secator_runner::NativeRunner| {
        let value: Option<String> = if opt.is_flag || matches!(opt.ty, OptType::Bool) {
            if args.get_flag(opt.name) { Some("true".into()) } else { None }
        } else {
            match &opt.ty {
                OptType::Int => args.get_one::<i64>(opt.name).map(|v| v.to_string()),
                OptType::Float => args.get_one::<f64>(opt.name).map(|v| v.to_string()),
                _ => args.get_one::<String>(opt.name).cloned(),
            }
        };
        if let Some(v) = value {
            runner.opts.insert(opt.name.to_string(), v);
        }
    };
    for opt in schema.meta_opts.iter() {
        if matches!(schema.key_map.get(opt.name), Some(KeyMap::NotSupported)) || opt.internal {
            continue;
        }
        collect(opt, runner);
    }
    for opt in schema.opts.iter() {
        if opt.internal {
            continue;
        }
        collect(opt, runner);
    }
}

// ------------------------------------------------------------------ Execution

async fn run_task_subcommand(matches: &ArgMatches) -> ExitCode {
    let (task_name, args) = match matches.subcommand() {
        Some(s) => s,
        None => {
            eprintln!("usage: secator-cli x <task> <target> [<target>...]");
            return ExitCode::from(2);
        }
    };
    let raw_inputs: Vec<String> = args
        .get_many::<String>("inputs")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let want_json = args.get_flag("json");
    let want_raw = args.get_flag("raw");
    let force_no_color = args.get_flag("no_color");

    // Resolve to either a command spec (subprocess) or a native spec (in-proc).
    enum SpecRef {
        Cmd(&'static secator_runner::TaskSpec),
        Native(&'static secator_runner::NativeSpec),
    }
    let spec_ref = if let Some(s) = secator_tasks::get(task_name) {
        SpecRef::Cmd(s)
    } else if let Some(s) = secator_tasks::get_native(task_name) {
        SpecRef::Native(s)
    } else {
        eprintln!("unknown task: {task_name}");
        return ExitCode::from(2);
    };
    let (spec_name, spec_desc, spec_input_types, spec_default_inputs):
        (&str, &str, &[&str], Option<&str>) = match &spec_ref {
        SpecRef::Cmd(s) => (s.name, s.description, s.input_types, s.default_inputs),
        SpecRef::Native(s) => (s.name, s.description, s.input_types, s.default_inputs),
    };

    // Expand inputs: file → lines, `a,b,c` → split, stdin auto-read if piped.
    // Python semantics (`_validate_input_nonempty`): a task with
    // `default_inputs` set (to any value, including `""`) tolerates an
    // empty input list — it synthesises its own state (arp reads local
    // ARP cache, netdetect scans interfaces, ai/prompt read from opts).
    // `input_types: &[]` is orthogonal: it means "accept any type", NOT
    // "no input required" (Python `input_types = None` semantics).
    let inputs = expand_inputs(raw_inputs, spec_input_types);
    let allow_empty_inputs = spec_default_inputs.is_some();
    if inputs.is_empty() && !allow_empty_inputs {
        eprintln!("no targets — pass positional args, a comma list, a file, or pipe via stdin");
        return ExitCode::from(2);
    }

    // Style: stderr coloring, with --no-color override and NO_COLOR detection.
    let mut style = Style::detect_stderr();
    if force_no_color {
        style.color = false;
    }
    let stdout_tty = std::io::stdout().is_terminal();
    let raw_mode = want_raw || (!want_json && !stdout_tty);

    // Lifecycle: loaded N target(s).
    let label = if inputs.len() == 1 { "target" } else { "targets" };
    if !inputs.is_empty() {
        eprintln!(
            "{}",
            info(&format!("Loaded {} {label} for {}", inputs.len(), spec_name), style)
        );
        for t in &inputs {
            let kind = secator_model::autodetect_type(t);
            eprintln!("{}", target_line(t, &kind, style));
        }
    }
    eprintln!(
        "{}",
        info(&format!("Task {spec_name} ({spec_desc}) started"), style)
    );

    // Allocate this task's reports folder BEFORE building the runner so the schema's
    // hooks (e.g. httpx -srd) can read it via HookCtx.state["reports_folder"].
    let config = secator_config::get();
    let workspace = resolve_workspace(args, &config);
    let reports_folder = secator_report::next_reports_folder(&config.dirs.reports, &workspace, "task")
        .ok();

    // Worker / sync routing: native tasks always run locally (no subprocess to
    // ship to a worker), command tasks honor `--worker`/`--sync` + auto.
    let is_native = matches!(&spec_ref, SpecRef::Native(_));
    let want_worker = !is_native && args.get_flag("worker");
    let want_sync = is_native || args.get_flag("sync");
    let broker_root = config.dirs.celery_data.clone();
    let worker_alive = !is_native
        && secator_exec::broker::FileBroker::new(&broker_root)
            .map(|b| b.worker_alive())
            .unwrap_or(false);
    let use_remote = if want_sync {
        false
    } else if want_worker {
        if !worker_alive {
            eprintln!(
                "{}",
                err(
                    "No worker is alive — start one with `secator worker` or omit --worker for auto-detect.",
                    style,
                )
            );
            return ExitCode::from(2);
        }
        true
    } else {
        worker_alive
    };

    if use_remote {
        eprintln!("{}", info("Worker available, running remotely", style));
    } else if !want_sync && !is_native {
        eprintln!("{}", info("No worker available, running locally", style));
    }

    // Dry-run: build the runner, apply profile + before_init mutations, print the
    // resolved cmd / inputs / opts, then return without spawning. We do this
    // before the channel so no items are queued / no broker submission happens.
    if args.get_flag("dry_run") {
        match spec_ref {
            SpecRef::Cmd(spec) => {
                let mut runner = CommandRunner::new(spec, inputs.clone());
                runner.reports_folder = reports_folder.clone();
                runner.verbose = resolve_verbose(args);
                collect_opts_into_runner(spec, args, &mut runner);
                apply_profile_opts_to_runner_opts(
                    args.get_one::<String>("profiles").map(String::as_str),
                    &mut runner.opts,
                    style,
                );
                // Run `before_init` hooks so dynamic cmd_suffix (ffuf FUZZ, dirsearch -o,
                // msfconsole -x, ...) lands in the dry-run echo.
                let mut ctx = secator_runner::HookCtx { task_name: spec.name, ..Default::default() };
                if let Some(rf) = &runner.reports_folder {
                    ctx.state.insert("reports_folder".into(), rf.to_string_lossy().into());
                }
                for h in spec.hooks.before_init { h(&mut ctx, &mut runner); }
                // Run proxy resolution so the dry-run echo reflects what would
                // actually be executed (proxychains prefix, resolved socks5 URL,
                // dropped opt for unsupported tasks).
                secator_runner::configure_proxy(&mut runner);
                // For multi-input runs, synthesize a placeholder file path so the
                // dry-run echo shows what the file-flag would resolve to without
                // actually touching disk (`prepare()` writes a real file).
                if runner.inputs.len() > 1 && runner.input_file.is_none() {
                    runner.input_file = Some(format!(
                        "<inputs:{}-targets>", runner.inputs.len()
                    ));
                }
                let cmd = runner.build_cmd_with_hooks();
                eprintln!("[dry-run] {cmd}");
                if !runner.opts.is_empty() {
                    let mut kv: Vec<_> = runner.opts.iter().collect();
                    kv.sort();
                    eprintln!("[dry-run] resolved opts:");
                    for (k, v) in kv {
                        eprintln!("           {k} = {v}");
                    }
                }
                if !ctx.extra_results.is_empty() {
                    eprintln!("[dry-run] before_init queued {} item(s)", ctx.extra_results.len());
                }
            }
            SpecRef::Native(spec) => {
                let mut runner = secator_runner::NativeRunner::new(spec, inputs.clone());
                collect_opts_into_native_runner(spec, args, &mut runner);
                apply_profile_opts_to_runner_opts(
                    args.get_one::<String>("profiles").map(String::as_str),
                    &mut runner.opts,
                    style,
                );
                eprintln!("[dry-run] native task {} (no shell cmd)", spec.name);
                eprintln!("[dry-run] inputs: {:?}", runner.inputs);
                if !runner.opts.is_empty() {
                    let mut kv: Vec<_> = runner.opts.iter().collect();
                    kv.sort();
                    eprintln!("[dry-run] resolved opts:");
                    for (k, v) in kv {
                        eprintln!("           {k} = {v}");
                    }
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    // Drivers (MongoDB / API / future Slack/Discord) — instantiated once per run
    // from `config.addons`. Empty when no addon is enabled. `on_run_start` fires
    // BEFORE the runner spawns so the runner doc is present even if the run dies.
    let drivers = enabled_drivers(&config);
    let driver_info_for_start = secator_report::ReportInfo {
        name: spec_name.to_string(),
        task_name: spec_name.to_string(),
        status: "RUNNING".into(),
        targets: inputs.clone(),
        workspace: workspace.clone(),
        title: spec_desc.to_string(),
        ..Default::default()
    };
    let mut driver_ids: Vec<(String, Option<String>)> = Vec::new();
    for d in &drivers {
        match d.on_run_start(&driver_info_for_start, secator_driver::RunKind::Task).await {
            Ok(id) => driver_ids.push((d.name().to_string(), id)),
            Err(e) => {
                eprintln!("{}", err(&format!("driver {} on_run_start: {e}", d.name()), style));
                driver_ids.push((d.name().to_string(), None));
            }
        }
    }

    // Stream items through a channel; render or pipe as appropriate. Same
    // shape regardless of runner kind.
    let (tx, mut rx) = mpsc::channel::<OutputItem>(64);
    // Capture resolved opts + start time BEFORE spawning so finalize_run can
    // round-trip them into report.info. Python parity (`run_opts`, `start_time`).
    let captured_opts: std::collections::BTreeMap<String, String>;
    let start_time = unix_time();
    let task_handle: tokio::task::JoinHandle<Result<(), String>> = match spec_ref {
        SpecRef::Cmd(spec) => {
            // Auto-install pass — Python parity (`runners.auto_install_commands`,
            // default true). If the task's primary binary isn't on PATH and the
            // operator hasn't disabled the knob, run the install pipeline before
            // spawning. Failures here log a Warning and fall through; the actual
            // subprocess invocation will surface the missing-binary error.
            if config.security.auto_install_commands && !binary_in_path(spec.cmd) {
                eprintln!(
                    "{}",
                    info(
                        &format!(
                            "{} not found on PATH — running auto-install (disable with `secator config set security.auto_install_commands false`)",
                            spec.cmd
                        ),
                        style
                    )
                );
                // Auto-install respects `CONFIG.security.force_source_install` so
                // operators who configure source-only builds get them even on the
                // implicit auto-install path (Python parity with the install CLI).
                let mut opts = secator_install::InstallOptions::default();
                opts.force_source = secator_config::get().security.force_source_install;
                let status = secator_install::install_task(spec, &opts);
                match status {
                    secator_install::InstallStatus::Success
                    | secator_install::InstallStatus::SkippedOk => {
                        eprintln!(
                            "{}",
                            info(&format!("auto-install: {} ready", spec.cmd), style)
                        );
                    }
                    secator_install::InstallStatus::NotSupported => {
                        eprintln!(
                            "{}",
                            err(
                                &format!(
                                    "auto-install: no install metadata for `{}` — please install it manually",
                                    spec.name
                                ),
                                style
                            )
                        );
                    }
                    other => {
                        eprintln!(
                            "{}",
                            err(
                                &format!("auto-install: {} install returned {other:?}", spec.cmd),
                                style
                            )
                        );
                    }
                }
            }
            let mut runner = CommandRunner::new(spec, inputs.clone());
            runner.reports_folder = reports_folder.clone();
            runner.verbose = resolve_verbose(args);
            collect_opts_into_runner(spec, args, &mut runner);
            apply_profile_opts_to_runner_opts(
                args.get_one::<String>("profiles").map(String::as_str),
                &mut runner.opts,
                style,
            );
            captured_opts = runner.opts.clone();
            if use_remote {
                // Pick transport from `config.transport.broker_url`:
                //   `redis://...`     → RedisTransport (real distributed mode)
                //   anything else     → FileTransport (filesystem broker scaffold)
                let task_name = spec.name.to_string();
                let opts = std::mem::take(&mut runner.opts);
                let inputs_copy = runner.inputs.clone();
                let rf = runner.reports_folder.clone();
                let broker_url = config.transport.broker_url.clone();
                if broker_url.starts_with("redis://") || broker_url.starts_with("rediss://") {
                    let rt = match secator_redis::RedisTransport::open(&broker_url) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("{}", err(&format!("redis open failed: {e}"), style));
                            return ExitCode::from(1);
                        }
                    };
                    tokio::spawn(async move {
                        rt.execute_task(&task_name, inputs_copy, opts, rf, tx)
                            .await
                            .map(|_status| ())
                            .map_err(|e| e.to_string())
                    })
                } else {
                    let ft = match secator_exec::FileTransport::open(broker_root.clone()) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("{}", err(&format!("broker open failed: {e}"), style));
                            return ExitCode::from(1);
                        }
                    };
                    tokio::spawn(async move {
                        ft.execute_task(&task_name, inputs_copy, opts, rf, tx)
                            .await
                            .map(|_status| ())
                            .map_err(|e| e.to_string())
                    })
                }
            } else {
                tokio::spawn(async move {
                    runner.run(tx).await.map_err(|e| e.to_string())
                })
            }
        }
        SpecRef::Native(spec) => {
            let mut runner = secator_runner::NativeRunner::new(spec, inputs.clone());
            collect_opts_into_native_runner(spec, args, &mut runner);
            apply_profile_opts_to_runner_opts(
                args.get_one::<String>("profiles").map(String::as_str),
                &mut runner.opts,
                style,
            );
            captured_opts = runner.opts.clone();
            tokio::spawn(async move {
                runner.run(tx).await.map_err(|e| e.to_string())
            })
        }
    };

    // CVE enrichment chain — built once per run. Skipped entirely in offline mode
    // or when `config.runners.skip_cve_search` is set; local cache hits still
    // resolve for free.
    let cve_cache = secator_providers::LocalCache::new(config.dirs.data.clone());
    let cve_providers: Vec<Box<dyn secator_providers::CveProvider>> = build_cve_chain(&config);

    // Exploit enrichment chain — Python parity with `ExploitProvider`. When an
    // `Exploit` item arrives with an `EDB-…` id, we fetch the upstream page and
    // stash a `cached_path` reference into `extra_data` so downstream consumers
    // (operator, ai task) can grep it without re-hitting the network.
    let exploit_cache = secator_providers::ExploitCache::new(config.dirs.data.clone());
    let exploit_providers: Vec<Box<dyn secator_providers::ExploitProvider>> =
        build_exploit_chain(&config);

    // Live UI sink — auto-disabled when piping stderr or in `--json`/`--raw` mode
    // (those redirect stdout but still write item lines to stderr, just not in
    // an in-place way).
    let mut live = secator_ui::LiveSink::new(style);
    if want_json || raw_mode || force_no_color {
        live = live.plain();
    }

    let mut findings = 0u32;
    let mut errors = 0u32;
    let mut collected: Vec<OutputItem> = Vec::new();
    // Emit one `Target` per CLI input — Python parity (#168 B-TARGET-EMIT).
    // Drivers + the report consume these as the run-scoped anchor for the
    // operator's stated targets.
    for input in &inputs {
        let mut t = OutputItem::Target(secator_model::Target {
            name: input.clone(),
            ..Default::default()
        });
        stamp_task_meta(&mut t, &task_name);
        collected.push(t);
    }
    while let Some(mut item) = rx.recv().await {
        // Stamp meta the workflow/scan paths get from `tag_meta` but that
        // the single-task path was missing (#164 B-TASK-META).
        stamp_task_meta(&mut item, &task_name);
        if matches!(item, OutputItem::Error(_)) { errors += 1; }
        if item.is_finding() { findings += 1; }
        // Vulnerability enrichment: when the runner produced a `CVE-...` /
        // `GHSA-...` id, look it up against the cache + remote providers and
        // overlay non-empty fields. Runs BEFORE driver fanout so Mongo / API
        // see the enriched view.
        if let OutputItem::Vulnerability(v) = &mut item {
            if !cve_providers.is_empty() && !v.id.is_empty() {
                let lookup_id = v.id.clone();
                if lookup_id.starts_with("CVE-") || lookup_id.starts_with("GHSA-") {
                    if let Some(enriched) =
                        secator_providers::enrich_one(&lookup_id, &cve_cache, &cve_providers).await
                    {
                        secator_providers::merge_into(v, &enriched);
                    }
                }
            }
        }
        // Exploit enrichment — populates `extra_data.cached_path` so downstream
        // consumers can read the upstream page without another network call.
        if let OutputItem::Exploit(e) = &mut item {
            if !exploit_providers.is_empty() && !e.id.is_empty() {
                let lookup_id = e.id.clone();
                if lookup_id.starts_with("EDB-") {
                    if secator_providers::enrich_one_exploit(
                        &lookup_id,
                        &exploit_cache,
                        &exploit_providers,
                    )
                    .await
                    .is_some()
                    {
                        let cached_path = exploit_cache.dir.join(format!(
                            "{}.html",
                            lookup_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
                        ));
                        e.extra_data.insert(
                            "cached_path".into(),
                            serde_json::Value::String(cached_path.to_string_lossy().into_owned()),
                        );
                    }
                }
            }
        }
        // Fan each item out to enabled drivers (Mongo, API, …) for live persistence.
        // Driver errors are logged but never abort the run — same as Python.
        for d in &drivers {
            if let Err(e) = d.on_finding(&mut item).await {
                eprintln!("{}", err(&format!("driver {} on_finding: {e}", d.name()), style));
            }
        }
        if want_json {
            let json = serde_json::to_string(&item.to_map()).unwrap_or_default();
            println!("{json}");
        } else if raw_mode {
            if let Some(r) = raw(&item) {
                println!("{r}");
            }
            live.emit(&item);
        } else {
            live.emit(&item);
        }
        collected.push(item);
    }
    live.finish();

    // Wait for the subprocess (local) or broker tail (remote) + collect its outcome.
    let runner_result = task_handle.await;
    if let Some(msg) = match runner_result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(e) => Some(format!("join error: {e}")),
    } {
        eprintln!("{}", err(&msg, style));
        errors = errors.saturating_add(1);
    }

    let end_time = unix_time();
    // Drivers `on_run_end` — match each driver to the external_id it returned on
    // run_start, push the final ReportInfo + collected items.
    let elapsed = if end_time > start_time { end_time - start_time } else { 0.0 };
    let final_info = secator_report::ReportInfo {
        name: spec_name.to_string(),
        task_name: spec_name.to_string(),
        status: if errors > 0 { "FAILURE".into() } else { "SUCCESS".into() },
        targets: inputs.clone(),
        workspace: workspace.clone(),
        title: spec_desc.to_string(),
        findings_count: findings as usize,
        errors_count: errors as usize,
        start_time,
        end_time,
        elapsed_seconds: elapsed,
        elapsed_human: secator_report::format_elapsed(elapsed),
        run_opts: captured_opts.clone(),
        context: serde_json::Map::new(),
        errors: collected
            .iter()
            .filter_map(|i| match i {
                OutputItem::Error(e) => Some(e.message.clone()),
                _ => None,
            })
            .collect(),
    };
    for d in &drivers {
        let external = driver_ids
            .iter()
            .find(|(n, _)| n == d.name())
            .and_then(|(_, id)| id.clone());
        if let Err(e) = d
            .on_run_end(
                &final_info,
                &collected,
                secator_driver::RunKind::Task,
                external.as_deref(),
            )
            .await
        {
            eprintln!("{}", err(&format!("driver {} on_run_end: {e}", d.name()), style));
        }
    }
    finalize_run_with_timing(
        spec_name,
        spec_desc,
        "task",
        inputs,
        workspace,
        reports_folder,
        collected,
        findings,
        errors,
        style,
        start_time,
        end_time,
        captured_opts,
    )
}

/// Is `bin` resolvable on the operator's PATH? Used by the auto-install
/// branch to decide whether to run the install pipeline before spawning a
/// task's subprocess. Mirrors `shutil.which(bin) is not None` in Python.
fn binary_in_path(bin: &str) -> bool {
    if bin.is_empty() {
        return false;
    }
    // Handle multi-word `cmd` declarations like `httpx-toolkit -irh` — only
    // the first token is the actual binary name.
    let first = bin.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return false;
    }
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(first);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

/// Current unix time in seconds (Python `time.time()` parity for ReportInfo).
fn unix_time() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Stamp the meta fields the workflow / scan paths get for free from
/// `secator_exec::tag_meta` but that the single-task path was missing:
/// `_source`, `_timestamp`, `_uuid`. Also fills out the run-scoped
/// `_context.workspace_*` keys so drivers see the workspace at emission
/// time (B-TASK-META / #164).
fn stamp_task_meta(item: &mut OutputItem, task_name: &str) {
    let cfg = secator_config::get();
    let workspace = if cfg.workspace.default.is_empty() {
        "default".to_string()
    } else {
        cfg.workspace.default.clone()
    };
    let meta = item.meta_mut();
    if meta.source.is_empty() {
        meta.source = task_name.to_string();
    }
    if meta.timestamp == 0.0 {
        meta.timestamp = unix_time();
    }
    if meta.uuid.is_empty() {
        meta.uuid = uuid::Uuid::new_v4().to_string();
    }
    if !meta.context.contains_key("workspace_name") {
        meta.context.insert(
            "workspace_name".to_string(),
            serde_json::Value::String(workspace.clone()),
        );
        meta.context.insert(
            "workspace_id".to_string(),
            serde_json::Value::String(workspace),
        );
    }
}

/// Instantiate all drivers whose addon is `enabled: true` in config. Drivers fail
/// open: any backend that throws on construction is logged + skipped, so a bad
/// MongoDB URL never blocks the rest of the run.
/// Build the configured CVE provider chain. `circl` first, optional `ghsa` second.
/// Returns an empty vec when offline mode or skip_cve_search is set — short-circuits
/// the enrichment branch in the receive loop.
fn build_cve_chain(
    config: &secator_config::Config,
) -> Vec<Box<dyn secator_providers::CveProvider>> {
    if config.offline_mode || config.runners.skip_cve_search {
        return Vec::new();
    }
    let mut chain: Vec<Box<dyn secator_providers::CveProvider>> = Vec::new();
    match config.providers.cve() {
        "circl" | "" => chain.push(Box::new(secator_providers::CirclProvider::new())),
        "vulners" => chain.push(Box::new(secator_providers::VulnersProvider::from_config(
            config.addons.vulners.clone(),
        ))),
        _ => {}
    }
    match config.providers.ghsa() {
        "ghsa" | "" => chain.push(Box::new(secator_providers::GhsaProvider::new())),
        _ => {}
    }
    // Vulners is also offered as a secondary enricher when its addon is
    // explicitly enabled — operators often pair Circl (free, sometimes thin)
    // with Vulners (paid, deeper) to fill gaps. Skipped unless the addon
    // has both enabled=true and an api_key.
    if config.addons.vulners.enabled
        && !config.addons.vulners.api_key.is_empty()
        && config.providers.cve() != "vulners"
    {
        chain.push(Box::new(secator_providers::VulnersProvider::from_config(
            config.addons.vulners.clone(),
        )));
    }
    chain
}

/// Build the configured exploit provider chain. `exploitdb` is the only
/// built-in today. Returns empty in offline mode or when
/// `runners.skip_exploit_search` is set — short-circuits the enrichment
/// branch in the receive loop.
fn build_exploit_chain(
    config: &secator_config::Config,
) -> Vec<Box<dyn secator_providers::ExploitProvider>> {
    if config.offline_mode || config.runners.skip_exploit_search {
        return Vec::new();
    }
    let mut chain: Vec<Box<dyn secator_providers::ExploitProvider>> = Vec::new();
    match config.providers.exploit() {
        "exploitdb" | "" => chain.push(Box::new(secator_providers::ExploitDbProvider::new())),
        _ => {}
    }
    chain
}

fn enabled_drivers(
    config: &secator_config::Config,
) -> Vec<Box<dyn secator_driver::Driver>> {
    let mut out: Vec<Box<dyn secator_driver::Driver>> = Vec::new();
    if config.addons.mongodb.enabled {
        out.push(Box::new(secator_mongo::MongoDriver::from_config(
            config.addons.mongodb.clone(),
        )));
    }
    if config.addons.api.enabled {
        match secator_api::ApiDriver::from_config(config.addons.api.clone()) {
            Ok(d) => out.push(Box::new(d)),
            Err(e) => eprintln!("api driver disabled — {e}"),
        }
    }
    if config.addons.slack.enabled && !config.addons.slack.webhook_url.is_empty() {
        out.push(Box::new(secator_notify::SlackDriver::from_config(
            config.addons.slack.clone(),
        )));
    }
    if config.addons.discord.enabled && !config.addons.discord.webhook_url.is_empty() {
        out.push(Box::new(secator_notify::DiscordDriver::from_config(
            config.addons.discord.clone(),
        )));
    }
    if config.addons.gcs.enabled && !config.addons.gcs.bucket_name.is_empty() {
        out.push(Box::new(secator_gcs::GcsDriver::from_config(
            config.addons.gcs.clone(),
        )));
    }
    out
}

/// Runner-level finalizer — Python `Runner.mark_completed` equivalent. Called
/// once at the end of every task/workflow/scan run. Flags duplicate findings
/// on the accumulated results (does NOT drop them — Python parity: reports
/// persist all items with `_duplicate: true` on the losers), then prints the
/// summary line and writes the configured exporters.
#[allow(clippy::too_many_arguments)]
fn finalize_run_with_timing(
    name: &str,
    description: &str,
    kind: &'static str,
    inputs: Vec<String>,
    workspace: String,
    reports_folder: Option<std::path::PathBuf>,
    mut collected: Vec<OutputItem>,
    findings: u32,
    errors: u32,
    style: Style,
    start_time: f64,
    end_time: f64,
    run_opts: std::collections::BTreeMap<String, String>,
) -> ExitCode {
    // Universal: flag duplicate items by per-type compare_key.
    secator_model::mark_duplicates(&mut collected);

    let status = if errors > 0 { "FAILURE" } else { "SUCCESS" };
    let kind_label = match kind {
        "task" => "Task",
        "workflow" => "Workflow",
        "scan" => "Scan",
        _ => "Run",
    };
    eprintln!(
        "{}",
        info(
            &format!(
                "{} {} finished with status {} and found {} {}",
                kind_label,
                name,
                status,
                findings,
                if findings == 1 { "finding" } else { "findings" },
            ),
            style,
        )
    );

    if let Some(folder) = reports_folder {
        let elapsed = if end_time > start_time { end_time - start_time } else { 0.0 };
        let errors_msgs: Vec<String> = collected
            .iter()
            .filter_map(|i| match i {
                OutputItem::Error(e) => Some(e.message.clone()),
                _ => None,
            })
            .collect();
        // Populate `info.context` with the run-scoped metadata Python keeps in
        // `data.info.context` (workspace identity, active drivers list). Python
        // also stashes `celery_id` / `worker_name` — Rust uses a different
        // transport so those don't apply, but the workspace + drivers entries
        // are still useful to downstream consumers (B-INFO-CONTEXT, #166).
        let mut context = serde_json::Map::new();
        context.insert(
            "workspace_name".into(),
            serde_json::Value::String(workspace.clone()),
        );
        context.insert(
            "workspace_id".into(),
            serde_json::Value::String(workspace.clone()),
        );
        context.insert(
            "workspace_explicit".into(),
            serde_json::Value::Bool(false),
        );
        let driver_names: Vec<serde_json::Value> = enabled_drivers(secator_config::get())
            .iter()
            .map(|d| serde_json::Value::String(d.name().to_string()))
            .collect();
        context.insert("drivers".into(), serde_json::Value::Array(driver_names));

        let info_struct = secator_report::ReportInfo {
            name: name.to_string(),
            task_name: name.to_string(),
            status: status.to_string(),
            targets: inputs,
            workspace,
            title: description.to_string(),
            findings_count: findings as usize,
            errors_count: errors as usize,
            start_time,
            end_time,
            elapsed_seconds: elapsed,
            elapsed_human: secator_report::format_elapsed(elapsed),
            run_opts,
            context,
            errors: errors_msgs,
        };
        let report = secator_report::Report::build(info_struct, &collected, folder);
        // Always export — Python parity. Even a 0-finding run produces a
        // `report.json` so downstream queries / drivers can rely on the
        // file existing (B-EMPTY-REPORT, #169).
        {
            // Honour `CONFIG.exporters.{tasks,workflows,scans}` so users can
            // opt into Markdown/Table without touching code.
            let exporters = match kind {
                "workflow" => secator_exporters::default_workflow_exporters(),
                "scan" => secator_exporters::default_scan_exporters(),
                _ => secator_exporters::default_task_exporters(),
            };
            eprintln!(
                "{}",
                info(
                    &format!(
                        "Exporting results with exporters: {}",
                        exporters
                            .iter()
                            .map(|e| e.name().to_lowercase())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                    style,
                )
            );
            for exporter in exporters {
                match exporter.send(&report) {
                    Ok(paths) => {
                        if paths.len() == 1 {
                            eprintln!(
                                "{}",
                                info(
                                    &format!(
                                        "Saved {} report to {}",
                                        exporter.name(),
                                        paths[0].display()
                                    ),
                                    style,
                                )
                            );
                        } else if paths.len() > 1 {
                            eprintln!(
                                "{}",
                                info(&format!("Saved {} reports to", exporter.name()), style)
                            );
                            for p in &paths {
                                eprintln!("   • {}", p.display());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{}",
                            err(&format!("{} export failed: {e}", exporter.name()), style)
                        );
                    }
                }
            }
        }
    }

    if status == "SUCCESS" { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

#[allow(dead_code)]
fn write_reports(
    spec: &'static secator_runner::TaskSpec,
    items: &[OutputItem],
    folder: std::path::PathBuf,
    workspace: &str,
    inputs: &[String],
    status: &str,
    findings: u32,
    errors: u32,
    style: Style,
) {
    use secator_exporters::default_task_exporters;
    use secator_report::{Report, ReportInfo};

    let report = Report::build(
        ReportInfo {
            name: spec.name.to_string(),
            task_name: spec.name.to_string(),
            status: status.to_string(),
            targets: inputs.to_vec(),
            workspace: workspace.to_string(),
            title: spec.description.to_string(),
            findings_count: findings as usize,
            errors_count: errors as usize,
            ..ReportInfo::default()
        },
        items,
        folder,
    );
    if report.is_empty() {
        return;
    }
    let exporters = default_task_exporters();
    eprintln!(
        "{}",
        info(
            &format!(
                "Exporting results with exporters: {}",
                exporters
                    .iter()
                    .map(|e| e.name().to_lowercase())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            style,
        )
    );
    for exporter in exporters {
        match exporter.send(&report) {
            Ok(paths) => {
                if paths.is_empty() {
                    continue;
                }
                if paths.len() == 1 {
                    eprintln!(
                        "{}",
                        info(&format!("Saved {} report to {}", exporter.name(), paths[0].display()), style)
                    );
                } else {
                    eprintln!("{}", info(&format!("Saved {} reports to", exporter.name()), style));
                    for p in &paths {
                        eprintln!("   • {}", p.display());
                    }
                }
            }
            Err(e) => eprintln!("{}", err(&format!("{} export failed: {e}", exporter.name()), style)),
        }
    }
}

// ------------------------------------------------------------------ Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comma_split_into_multiple_targets() {
        let out = expand_inputs(vec!["a.com,b.com,c.com".into()], &["host"]);
        assert_eq!(out, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn comma_split_drops_empty_segments() {
        let out = expand_inputs(vec!["a.com,,c.com,".into()], &["host"]);
        assert_eq!(out, vec!["a.com", "c.com"]);
    }

    #[test]
    fn whitespace_only_targets_are_dropped() {
        let out = expand_inputs(vec!["  a.com  ".into(), "   ".into()], &["host"]);
        assert_eq!(out, vec!["a.com"]);
    }

    #[test]
    fn file_path_is_split_into_lines() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "a.com").unwrap();
        writeln!(tmp, "b.com").unwrap();
        writeln!(tmp, "").unwrap();
        writeln!(tmp, "c.com").unwrap();
        let p = tmp.path().to_string_lossy().into_owned();
        let out = expand_inputs(vec![p], &["host"]);
        assert_eq!(out, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn path_typed_input_keeps_file_path_as_is() {
        // `path`-typed tasks (gitleaks, grype) want the file path itself, not its lines.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(tmp, "fake-contents").unwrap();
        let p = tmp.path().to_string_lossy().into_owned();
        let out = expand_inputs(vec![p.clone()], &["path"]);
        assert_eq!(out, vec![p]);
    }

    #[test]
    fn multiple_positional_with_mixed_comma() {
        let out = expand_inputs(
            vec!["a.com,b.com".into(), "c.com".into()],
            &["host"],
        );
        assert_eq!(out, vec!["a.com", "b.com", "c.com"]);
    }

    /// Native task subcommands must accept the global `--sync` / `--worker`
    /// flags at clap parse time. Regression for the task-matrix run where
    /// `urlparser --sync` and `netdetect --sync` bailed with
    /// `error: unexpected argument '--sync' found`.
    #[test]
    fn native_task_cmd_accepts_sync_and_worker_flags() {
        let spec = secator_tasks::get_native("urlparser").expect("urlparser native spec");
        let cmd = build_native_task_cmd(spec);
        // clap surfaces unknown args as errors — a successful parse proves
        // the flags are registered on the subcommand.
        assert!(
            cmd.clone()
                .try_get_matches_from(vec!["urlparser", "https://x?a=1", "--sync"])
                .is_ok(),
            "--sync should be accepted"
        );
        assert!(
            cmd.clone()
                .try_get_matches_from(vec!["urlparser", "https://x?a=1", "--worker"])
                .is_ok(),
            "--worker should be accepted"
        );
        // Mutual exclusion is preserved (Python parity + subprocess-task parity).
        assert!(
            cmd.try_get_matches_from(vec!["urlparser", "x", "--sync", "--worker"])
                .is_err(),
            "--sync + --worker together must conflict"
        );
    }

    /// `default_inputs = Some("")` (Python parity: `default_inputs = ''`)
    /// is what tells the CLI to skip the "no targets" bail — NOT
    /// `input_types.is_empty()` (which is Python's "accept any type" flag).
    /// Regression: `arp`, `netdetect`, `ai`, `prompt` must run empty.
    #[test]
    fn tasks_with_default_inputs_tolerate_empty_input() {
        for name in ["arp"] {
            let spec = secator_tasks::get(name).expect(name);
            assert!(
                spec.default_inputs.is_some(),
                "{name} must declare default_inputs = Some(\"\") to run empty"
            );
        }
        for name in ["netdetect", "ai", "prompt"] {
            let spec = secator_tasks::get_native(name).expect(name);
            assert!(
                spec.default_inputs.is_some(),
                "native {name} must declare default_inputs = Some(\"\") to run empty"
            );
        }
    }

    /// `gf` has `input_types: &[]` (accept any type — Python `input_types =
    /// None`) but no `default_inputs`, so it still requires ≥1 input.
    /// Python parity. Guards against the earlier over-relaxed fix that
    /// treated empty input_types as "no input required".
    #[test]
    fn gf_requires_at_least_one_input_despite_empty_input_types() {
        let spec = secator_tasks::get("gf").expect("gf");
        assert!(spec.input_types.is_empty(), "gf accepts any type");
        assert!(
            spec.default_inputs.is_none(),
            "gf must require at least one input (Python parity)"
        );
    }
}
