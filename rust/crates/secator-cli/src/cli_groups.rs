//! Auxiliary CLI subcommands ported from Python `secator/cli.py`:
//!
//!   * `secator health` — check that each integrated tool's binary is on PATH.
//!   * `secator cheatsheet` — Markdown summary of every task/workflow/scan.
//!   * `secator install` — best-effort run of each task's `install_cmd` (Python
//!     parity is light here — the Rust SPEC doesn't carry `install_cmd` yet, so
//!     we just print the Python `install_cmd` snippet for the operator to run).
//!   * `secator reports list/show/rm` — manage the reports directory.
//!   * `secator config get/set/path/show` — display + edit `~/.secator/config.yml`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};
use secator_model::OutputType;
use secator_ui::{err, info, Style};

// ------------------------------------------------------------------- Health

pub fn build_health_subcommand() -> Command {
    Command::new("health")
        .about("Check whether each integrated tool's binary is installed and on PATH.")
        .visible_alias("h")
        .arg(
            Arg::new("json")
                .long("json")
                .help("Print the result as a single JSON document on stdout")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("missing_only")
                .long("missing-only")
                .visible_alias("missing")
                .help("Only print tools that are NOT installed")
                .action(ArgAction::SetTrue),
        )
}

pub fn run_health_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let want_json = args.get_flag("json");
    let missing_only = args.get_flag("missing_only");

    let mut rows: Vec<(String, String, bool)> = Vec::new();
    for spec in secator_tasks::all() {
        let bin = first_token(spec.cmd);
        let present = which_in_path(bin);
        rows.push((spec.name.into(), bin.into(), present));
    }
    for nspec in secator_tasks::native_all() {
        // Native tasks have no binary — mark as built-in/ready.
        rows.push((nspec.name.into(), "(native)".into(), true));
    }

    if want_json {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .filter(|(_, _, ok)| if missing_only { !ok } else { true })
            .map(|(n, b, ok)| {
                serde_json::json!({"name": n, "binary": b, "installed": ok})
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
        return ExitCode::SUCCESS;
    }

    let total = rows.len();
    let installed = rows.iter().filter(|(_, _, ok)| *ok).count();
    eprintln!(
        "{}",
        info(
            &format!("Health check: {installed}/{total} tools installed"),
            style
        )
    );
    for (name, bin, ok) in &rows {
        if missing_only && *ok {
            continue;
        }
        let status = if *ok { "✓" } else { "✗" };
        eprintln!("  {status} {:<18} → {bin}", name);
    }
    if installed == total {
        ExitCode::SUCCESS
    } else if installed == 0 {
        ExitCode::from(1)
    } else {
        // Mixed → still success; missing tools are operator-fixable.
        ExitCode::SUCCESS
    }
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

fn which_in_path(binary: &str) -> bool {
    if binary.is_empty() {
        return false;
    }
    if binary.contains('/') {
        return Path::new(binary).is_file();
    }
    let paths = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    for dir in std::env::split_paths(&paths) {
        if dir.join(binary).is_file() {
            return true;
        }
    }
    false
}

// ----------------------------------------------------------------- Cheatsheet

pub fn build_cheatsheet_subcommand() -> Command {
    Command::new("cheatsheet")
        .about("Print a Markdown summary of every task/workflow/scan.")
        .visible_alias("ch")
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .default_value("markdown")
                .help("Output format: markdown | plain"),
        )
}

pub fn run_cheatsheet_subcommand(args: &ArgMatches) -> ExitCode {
    let format = args.get_one::<String>("format").map(String::as_str).unwrap_or("markdown");
    let mut out = String::new();
    let md = format == "markdown";
    out.push_str(if md { "# Secator cheatsheet\n\n" } else { "Secator cheatsheet\n\n" });

    // ---- tasks ----
    out.push_str(if md { "## Tasks\n\n" } else { "TASKS\n" });
    if md {
        out.push_str("| Name | Description | Tags |\n");
        out.push_str("|------|-------------|------|\n");
    }
    let mut task_names: Vec<&str> = secator_tasks::all().iter().map(|s| s.name).collect();
    task_names.extend(secator_tasks::native_all().iter().map(|s| s.name));
    task_names.sort_unstable();
    for name in task_names {
        let (desc, tags) = if let Some(s) = secator_tasks::get(name) {
            (s.description, s.tags.join(", "))
        } else if let Some(s) = secator_tasks::get_native(name) {
            (s.description, s.tags.join(", "))
        } else {
            ("", String::new())
        };
        if md {
            out.push_str(&format!("| `{name}` | {desc} | {tags} |\n"));
        } else {
            out.push_str(&format!("  {:<16} {desc}\n", name));
        }
    }

    // ---- workflows ----
    out.push_str(if md { "\n## Workflows\n\n" } else { "\nWORKFLOWS\n" });
    if md {
        out.push_str("| Name | Description |\n");
        out.push_str("|------|-------------|\n");
    }
    for name in crate::workflows::names() {
        let yaml = crate::workflows::get(name).unwrap_or("");
        let desc = extract_top_str(yaml, "description").unwrap_or_default();
        if md {
            out.push_str(&format!("| `{name}` | {desc} |\n"));
        } else {
            out.push_str(&format!("  {:<18} {desc}\n", name));
        }
    }

    // ---- scans ----
    out.push_str(if md { "\n## Scans\n\n" } else { "\nSCANS\n" });
    if md {
        out.push_str("| Name | Description |\n");
        out.push_str("|------|-------------|\n");
    }
    for name in crate::scans::names() {
        let yaml = crate::scans::get(name).unwrap_or("");
        let desc = extract_top_str(yaml, "description").unwrap_or_default();
        if md {
            out.push_str(&format!("| `{name}` | {desc} |\n"));
        } else {
            out.push_str(&format!("  {:<10} {desc}\n", name));
        }
    }
    print!("{out}");
    ExitCode::SUCCESS
}

/// Tiny line-based grep for `key: value` top-level entries — avoids a full
/// YAML re-parse just to render the cheatsheet.
fn extract_top_str(yaml: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}: ");
    for line in yaml.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return Some(rest.trim_matches(['"', '\'']).to_string());
        }
    }
    None
}

// ------------------------------------------------------------------ Install

pub fn build_install_subcommand() -> Command {
    Command::new("install")
        .about("Install task binaries (system packages, source build, post-install).")
        .visible_alias("i")
        .arg(
            Arg::new("task")
                .help("Task name to install (positional). Omit + `--all` to install every task.")
                .value_name("TASK"),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .help("Install every task with an InstallSpec (combine with --missing-only).")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("missing_only")
                .long("missing-only")
                .visible_alias("missing")
                .help("Only install tasks whose binary is missing from PATH")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Print commands without executing them")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .help("Skip the confirmation prompt before executing")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Stream subprocess output verbatim")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .value_name("VER")
                .help("Override the task's install_version (e.g. `latest`)"),
        )
        .arg(
            Arg::new("force_source")
                .long("force-source")
                .help("Skip GitHub releases; build from source")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("github_token")
                .long("github-token")
                .value_name("TOKEN")
                .help("GitHub API token (falls back to $SECATOR_CLI_GITHUB_TOKEN)"),
        )
        .arg(
            Arg::new("bin_dir")
                .long("bin-dir")
                .value_name("PATH")
                .help("Where to drop GitHub-release binaries / source symlinks (default: ~/.local/bin)"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .help("Just list install status per task; don't run anything")
                .action(ArgAction::SetTrue),
        )
}

pub fn run_install_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let want_list = args.get_flag("list");
    let want_all = args.get_flag("all");
    let missing_only = args.get_flag("missing_only");
    let dry_run = args.get_flag("dry_run");
    let yes = args.get_flag("yes");
    let verbose = args.get_flag("verbose");
    let version_override = args.get_one::<String>("version").cloned();
    let only = args.get_one::<String>("task").cloned();

    // ----- list-only path (the previous default).
    if want_list || (only.is_none() && !want_all) {
        eprintln!(
            "{}",
            info(
                "Run `secator install <task>` to install one, or `--all` to install every missing tool.",
                style,
            )
        );
        for spec in secator_tasks::all() {
            let bin = first_token(spec.cmd);
            let installed = which_in_path(bin);
            if missing_only && installed {
                continue;
            }
            let status = if installed { "✓ installed" } else { "✗ MISSING" };
            let has_install = spec.install.cmd.is_some()
                || !spec.install.pre.is_empty()
                || !spec.install.cmd_pre.is_empty();
            let installer = if has_install { "installer ✓" } else { "no installer" };
            eprintln!("  {:<14} [{status}] binary: {bin} ({installer})", spec.name);
        }
        return ExitCode::SUCCESS;
    }

    // ----- targeted install path.
    let targets: Vec<&'static secator_runner::TaskSpec> = if let Some(t) = &only {
        match secator_tasks::get(t) {
            Some(s) => vec![s],
            None => {
                eprintln!("{}", info(&format!("Unknown task: {t}"), style));
                return ExitCode::from(2);
            }
        }
    } else {
        secator_tasks::all()
            .into_iter()
            .filter(|s| {
                let bin = first_token(s.cmd);
                let installed = which_in_path(bin);
                if missing_only && installed {
                    return false;
                }
                s.install.cmd.is_some()
                    || !s.install.pre.is_empty()
                    || !s.install.cmd_pre.is_empty()
            })
            .collect()
    };

    if targets.is_empty() {
        eprintln!("{}", info("No targets to install.", style));
        return ExitCode::SUCCESS;
    }

    // Confirm before running anything (unless --yes or --dry-run).
    if !yes && !dry_run {
        eprintln!(
            "About to install {} task(s): {}",
            targets.len(),
            targets.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
        );
        eprintln!("This will run shell commands as your user (and `sudo` for package installs).");
        eprintln!("Continue? [y/N] ");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err()
            || !matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
        {
            eprintln!("{}", info("Cancelled.", style));
            return ExitCode::from(1);
        }
    }

    // `--force_source` on the CLI wins; otherwise fall back to
    // `CONFIG.security.force_source_install` (Python parity).
    let force_source = args.get_flag("force_source")
        || secator_config::get().security.force_source_install;
    let opts = secator_install::InstallOptions {
        dry_run,
        yes,
        version_override,
        distro: None,
        verbose,
        bin_dir: args.get_one::<String>("bin_dir").map(std::path::PathBuf::from),
        force_source,
        github_token: args.get_one::<String>("github_token").cloned(),
    };

    let mut had_failure = false;
    for spec in &targets {
        eprintln!();
        let status = secator_install::install_task(spec, &opts);
        match &status {
            s if s.is_ok() => {
                eprintln!("{}", info(&format!("✓ {} ({:?})", spec.name, s), style));
            }
            other => {
                had_failure = true;
                eprintln!(
                    "{}",
                    info(&format!("✗ {} failed: {:?}", spec.name, other), style)
                );
            }
        }
    }
    if had_failure {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ------------------------------------------------------------------ Reports

pub fn build_reports_subcommand() -> Command {
    Command::new("reports")
        .about("Browse the reports directory.")
        .visible_alias("r")
        .visible_alias("report")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("List recent runs in the current (or named) workspace")
                .arg(Arg::new("workspace").long("workspace").visible_alias("ws").value_name("NAME"))
                .arg(
                    Arg::new("runner_type")
                        .long("runner-type")
                        .short('r')
                        .value_name("KIND")
                        .help("Filter by runner type. Choices: task, workflow, scan"),
                )
                .arg(
                    Arg::new("time_delta")
                        .long("time-delta")
                        .short('d')
                        .value_name("DELTA")
                        .help("Keep results newer than time delta (e.g. 26m, 1d, 1y, 30s)"),
                )
                .arg(
                    Arg::new("show_all")
                        .long("show-all")
                        .help("Show all columns, including the report path")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .short('n')
                        .value_name("N")
                        .default_value("50")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Print the JSON report for a run id")
                .arg(Arg::new("id").required(true).value_name("ID"))
                .arg(Arg::new("workspace").long("workspace").visible_alias("ws").value_name("NAME"))
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .value_name("KIND")
                        .default_value("workflows")
                        .help("tasks | workflows | scans"),
                ),
        )
        .subcommand(
            Command::new("info")
                .about("Print a one-screen summary for a runner id (e.g. `tasks/42`)")
                .arg(Arg::new("runner_id").required(true).value_name("KIND/ID"))
                .arg(Arg::new("workspace").long("workspace").visible_alias("ws").value_name("NAME")),
        )
        .subcommand(
            Command::new("path")
                .about("Print the reports root directory")
                .arg(Arg::new("workspace").long("workspace").visible_alias("ws").value_name("NAME")),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a runner's report directory (kind/id)")
                .visible_alias("rm")
                .visible_alias("remove")
                .arg(Arg::new("runner_id").required(true).value_name("KIND/ID"))
                .arg(Arg::new("workspace").long("workspace").visible_alias("ws").value_name("NAME"))
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .help("Skip the confirmation prompt")
                        .action(ArgAction::SetTrue),
                ),
        )
}

pub fn run_reports_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let config = secator_config::get();
    match args.subcommand() {
        Some(("list", sub)) => {
            let ws_filter = sub.get_one::<String>("workspace").cloned();
            let kind_filter = sub.get_one::<String>("runner_type").cloned();
            let time_delta = sub
                .get_one::<String>("time_delta")
                .and_then(|s| parse_time_delta(s));
            let show_all = sub.get_flag("show_all");
            let limit = *sub.get_one::<usize>("limit").unwrap_or(&50);

            let rows = collect_report_rows(
                &config.dirs.reports,
                ws_filter.as_deref(),
                kind_filter.as_deref(),
                time_delta,
            );
            if rows.is_empty() {
                eprintln!("{}", info("No reports found.", style));
                return ExitCode::SUCCESS;
            }
            let mut take = rows;
            take.truncate(limit);
            print_report_table(&take, show_all);
            eprintln!(
                "{}",
                info(&format!("Found {} report(s).", take.len()), style)
            );
            ExitCode::SUCCESS
        }
        Some(("info", sub)) => {
            let ws = sub
                .get_one::<String>("workspace")
                .cloned()
                .unwrap_or_else(|| {
                    if config.workspace.default.is_empty() {
                        "default".into()
                    } else {
                        config.workspace.default.clone()
                    }
                });
            let runner_id = sub.get_one::<String>("runner_id").expect("runner_id required");
            let (kind, id) = match runner_id.split_once('/') {
                Some((k, i)) => (k.to_string(), i.to_string()),
                None => {
                    eprintln!(
                        "{}",
                        err("runner_id must be of the form <kind>/<id> (e.g. tasks/42)", style)
                    );
                    return ExitCode::from(2);
                }
            };
            let path = Path::new(&config.dirs.reports)
                .join(&ws)
                .join(&kind)
                .join(&id)
                .join("report.json");
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    print_report_info(&json, &path);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("could not read {}: {e}", path.display()), style));
                    ExitCode::from(1)
                }
            }
        }
        Some(("show", sub)) => {
            let ws = sub
                .get_one::<String>("workspace")
                .cloned()
                .unwrap_or_else(|| {
                    if config.workspace.default.is_empty() {
                        "default".into()
                    } else {
                        config.workspace.default.clone()
                    }
                });
            let kind = sub.get_one::<String>("kind").cloned().unwrap_or_else(|| "workflows".into());
            let id = sub.get_one::<String>("id").expect("id required");
            let path = Path::new(&config.dirs.reports)
                .join(&ws)
                .join(&kind)
                .join(id)
                .join("report.json");
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    print!("{body}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("could not read {}: {e}", path.display()), style));
                    ExitCode::from(1)
                }
            }
        }
        Some(("path", sub)) => {
            let ws = sub
                .get_one::<String>("workspace")
                .cloned()
                .unwrap_or_else(|| {
                    if config.workspace.default.is_empty() {
                        "default".into()
                    } else {
                        config.workspace.default.clone()
                    }
                });
            let p = Path::new(&config.dirs.reports).join(&ws);
            println!("{}", p.display());
            ExitCode::SUCCESS
        }
        Some(("delete", sub)) => {
            let ws = sub
                .get_one::<String>("workspace")
                .cloned()
                .unwrap_or_else(|| {
                    if config.workspace.default.is_empty() {
                        "default".into()
                    } else {
                        config.workspace.default.clone()
                    }
                });
            let runner_id = sub.get_one::<String>("runner_id").expect("runner_id");
            let (kind, id) = match runner_id.split_once('/') {
                Some((k, i)) => (k.to_string(), i.to_string()),
                None => {
                    eprintln!(
                        "{}",
                        err("runner_id must be of the form <kind>/<id> (e.g. tasks/42)", style)
                    );
                    return ExitCode::from(2);
                }
            };
            let dir = Path::new(&config.dirs.reports).join(&ws).join(&kind).join(&id);
            if !dir.exists() {
                eprintln!("{}", err(&format!("no such report: {}", dir.display()), style));
                return ExitCode::from(1);
            }
            // Confirm unless --yes.
            if !sub.get_flag("yes") {
                eprintln!("About to delete {} (this can't be undone).", dir.display());
                eprint!("Continue? [y/N] ");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_err()
                    || !matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
                {
                    eprintln!("{}", info("Cancelled.", style));
                    return ExitCode::from(1);
                }
            }
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => {
                    eprintln!("{}", info(&format!("Deleted {}", dir.display()), style));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("delete {}: {e}", dir.display()), style));
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("usage: secator reports {{list|show|info|path|delete}}");
            ExitCode::from(2)
        }
    }
}

// ------------------------------------------------------------------- Config

pub fn build_config_subcommand() -> Command {
    Command::new("config")
        .about("Inspect or edit `~/.secator/config.yml`.")
        .visible_alias("c")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("path").about("Print the path to the config file"))
        .subcommand(Command::new("show").about("Pretty-print the active config as YAML"))
        .subcommand(
            Command::new("get")
                .about("Print the value of `<key>` (dotted path)")
                .arg(Arg::new("key").required(true).value_name("KEY")),
        )
        .subcommand(
            Command::new("set")
                .about("Set `<key> = <value>` (dotted path) and persist")
                .arg(Arg::new("key").required(true).value_name("KEY"))
                .arg(Arg::new("value").required(true).value_name("VALUE")),
        )
        .subcommand(
            Command::new("unset")
                .about("Remove `<key>` (dotted path) from the persisted config")
                .arg(Arg::new("key").required(true).value_name("KEY")),
        )
        .subcommand(
            Command::new("edit")
                .about("Open the config file in $EDITOR (or $VISUAL, fallback nano/vi)"),
        )
}

pub fn run_config_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let path = secator_config::user_config_path();
    match args.subcommand() {
        Some(("path", _)) => {
            println!("{}", path.display());
            ExitCode::SUCCESS
        }
        Some(("show", _)) => {
            let cfg = secator_config::get();
            match serde_yaml::to_string(&*cfg) {
                Ok(s) => {
                    print!("{s}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("yaml encode failed: {e}"), style));
                    ExitCode::from(1)
                }
            }
        }
        Some(("get", sub)) => {
            let key = sub.get_one::<String>("key").expect("required");
            let cfg = secator_config::get();
            let v = match serde_yaml::to_value(&*cfg).ok().and_then(|y| lookup_dotted(&y, key)) {
                Some(v) => v,
                None => {
                    eprintln!("{}", err(&format!("unknown key: {key}"), style));
                    return ExitCode::from(1);
                }
            };
            match &v {
                serde_yaml::Value::String(s) => println!("{s}"),
                other => {
                    print!("{}", serde_yaml::to_string(other).unwrap_or_default());
                }
            }
            ExitCode::SUCCESS
        }
        Some(("set", sub)) => {
            let key = sub.get_one::<String>("key").expect("required");
            let value = sub.get_one::<String>("value").expect("required");
            // Load existing (or seed from defaults) and patch.
            let mut root: serde_yaml::Mapping = match std::fs::read_to_string(&path) {
                Ok(body) => match serde_yaml::from_str::<serde_yaml::Value>(&body) {
                    Ok(serde_yaml::Value::Mapping(m)) => m,
                    _ => serde_yaml::Mapping::new(),
                },
                Err(_) => serde_yaml::Mapping::new(),
            };
            if let Err(msg) = set_dotted(&mut root, key, value) {
                eprintln!("{}", err(&msg, style));
                return ExitCode::from(1);
            }
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let body = serde_yaml::to_string(&serde_yaml::Value::Mapping(root)).unwrap_or_default();
            if let Err(e) = std::fs::write(&path, body) {
                eprintln!("{}", err(&format!("write failed: {e}"), style));
                return ExitCode::from(1);
            }
            eprintln!("{}", info(&format!("Set {key} = {value} in {}", path.display()), style));
            ExitCode::SUCCESS
        }
        Some(("unset", sub)) => {
            let key = sub.get_one::<String>("key").expect("required");
            let mut root: serde_yaml::Mapping = match std::fs::read_to_string(&path) {
                Ok(body) => match serde_yaml::from_str::<serde_yaml::Value>(&body) {
                    Ok(serde_yaml::Value::Mapping(m)) => m,
                    _ => {
                        eprintln!("{}", info("config file is empty — nothing to unset", style));
                        return ExitCode::SUCCESS;
                    }
                },
                Err(_) => {
                    eprintln!("{}", info("config file doesn't exist — nothing to unset", style));
                    return ExitCode::SUCCESS;
                }
            };
            let removed = unset_dotted(&mut root, key);
            if !removed {
                eprintln!("{}", err(&format!("key {key:?} not present in config"), style));
                return ExitCode::from(1);
            }
            let body = serde_yaml::to_string(&serde_yaml::Value::Mapping(root)).unwrap_or_default();
            if let Err(e) = std::fs::write(&path, body) {
                eprintln!("{}", err(&format!("write failed: {e}"), style));
                return ExitCode::from(1);
            }
            eprintln!("{}", info(&format!("Unset {key} in {}", path.display()), style));
            ExitCode::SUCCESS
        }
        Some(("edit", _)) => {
            // Ensure the file exists so $EDITOR doesn't open a blank phantom.
            if !path.exists() {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(&path, "# secator config (YAML)\n");
            }
            let editor = std::env::var("VISUAL")
                .ok()
                .or_else(|| std::env::var("EDITOR").ok())
                .unwrap_or_else(|| pick_default_editor());
            let status = std::process::Command::new(&editor).arg(&path).status();
            match status {
                Ok(s) if s.success() => ExitCode::SUCCESS,
                Ok(s) => {
                    eprintln!(
                        "{}",
                        err(&format!("editor exited with {} (cmd: {editor})", s.code().unwrap_or(-1)), style)
                    );
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("failed to spawn editor {editor}: {e}"), style));
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("usage: secator config {{path|show|get|set|unset|edit}}");
            ExitCode::from(2)
        }
    }
}

/// Remove a dotted key from the YAML mapping. Returns true when the key
/// existed and was removed. Empty intermediate mappings are cleaned up so a
/// subsequent `show` doesn't leave orphan `addons: {}` blocks.
fn unset_dotted(root: &mut serde_yaml::Mapping, key: &str) -> bool {
    let parts: Vec<&str> = key.split('.').collect();
    fn rec(map: &mut serde_yaml::Mapping, parts: &[&str]) -> bool {
        if parts.is_empty() {
            return false;
        }
        let k = serde_yaml::Value::String(parts[0].into());
        if parts.len() == 1 {
            return map.remove(&k).is_some();
        }
        let removed = match map.get_mut(&k) {
            Some(serde_yaml::Value::Mapping(inner)) => {
                let r = rec(inner, &parts[1..]);
                if inner.is_empty() {
                    map.remove(&k);
                }
                r
            }
            _ => false,
        };
        removed
    }
    rec(root, &parts)
}

/// Pick a default editor when neither $EDITOR nor $VISUAL is set. Tries
/// `nano` (friendliest), `vi` (POSIX), `notepad` (Windows).
fn pick_default_editor() -> String {
    if cfg!(target_os = "windows") {
        "notepad".into()
    } else if Path::new("/usr/bin/nano").exists() || Path::new("/bin/nano").exists() {
        "nano".into()
    } else {
        "vi".into()
    }
}

fn lookup_dotted(root: &serde_yaml::Value, key: &str) -> Option<serde_yaml::Value> {
    let mut cur = root.clone();
    for part in key.split('.') {
        let m = cur.as_mapping().cloned()?;
        cur = m.get(serde_yaml::Value::String(part.into())).cloned()?;
    }
    Some(cur)
}

fn set_dotted(
    root: &mut serde_yaml::Mapping,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() {
        return Err("empty key".into());
    }
    // Walk all but last, creating mappings as needed.
    let mut cur = root;
    for p in &parts[..parts.len() - 1] {
        let k = serde_yaml::Value::String((*p).into());
        if !cur.contains_key(&k) {
            cur.insert(k.clone(), serde_yaml::Value::Mapping(Default::default()));
        }
        cur = cur
            .get_mut(&k)
            .and_then(|v| match v {
                serde_yaml::Value::Mapping(m) => Some(m),
                _ => None,
            })
            .ok_or_else(|| format!("`{p}` is not a mapping"))?;
    }
    let last = parts[parts.len() - 1];
    let yaml_value = coerce_yaml_value(value);
    cur.insert(serde_yaml::Value::String(last.into()), yaml_value);
    Ok(())
}

/// Coerce a CLI-supplied string into a YAML value:
///   * `[a, b]` or `a,b,c` → sequence (comma-separated values)
///   * `true` / `false`    → bool
///   * `12` / `1.5`        → number
///   * everything else     → string
fn coerce_yaml_value(value: &str) -> serde_yaml::Value {
    let trimmed = value.trim();
    // Explicit JSON/YAML sequence syntax.
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
            return v;
        }
    }
    // Comma-separated → sequence of strings (with the same per-element coercion).
    if trimmed.contains(',') {
        let parts: Vec<serde_yaml::Value> = trimmed
            .split(',')
            .map(|s| coerce_scalar(s.trim()))
            .collect();
        return serde_yaml::Value::Sequence(parts);
    }
    coerce_scalar(trimmed)
}

fn coerce_scalar(value: &str) -> serde_yaml::Value {
    match value.to_lowercase().as_str() {
        "true" => serde_yaml::Value::Bool(true),
        "false" => serde_yaml::Value::Bool(false),
        "" => serde_yaml::Value::String(String::new()),
        _ => {
            if let Ok(i) = value.parse::<i64>() {
                serde_yaml::Value::Number(i.into())
            } else if let Ok(f) = value.parse::<f64>() {
                serde_yaml::Value::Number(serde_yaml::Number::from(f))
            } else {
                serde_yaml::Value::String(value.into())
            }
        }
    }
}

// Suppress unused-import warnings when running without the full set of helpers.
const _: fn(&BTreeMap<String, String>) = |_| ();

// ------------------------------------------------------------------ Reports helpers

/// One row in `secator r list`.
struct ReportRow {
    workspace: String,
    kind: String,
    id: String,
    name: String,
    target: String,
    profiles: String,
    start: f64,
    end: f64,
    elapsed_human: String,
    status: String,
    vuln_counts: std::collections::BTreeMap<String, i64>,
    path: std::path::PathBuf,
    mtime: std::time::SystemTime,
}

/// Parse Python's `human_to_timedelta` syntax — `26m`, `1d`, `1y`, `30s`. Returns
/// `Some(Duration)` for known suffixes, `None` for unparseable input.
fn parse_time_delta(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, suffix) = s.split_at(s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len()));
    let n: f64 = num.parse().ok()?;
    let secs = match suffix {
        "s" | "" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        "d" => n * 86400.0,
        "w" => n * 604_800.0,
        "y" => n * 31_536_000.0,
        _ => return None,
    };
    Some(std::time::Duration::from_secs_f64(secs))
}

/// Walk the reports tree under `base` and emit one [`ReportRow`] per runner dir.
/// Filters: optional workspace name (`None` = all), optional kind (task/workflow/scan),
/// optional max-age. Sorted newest-first by mtime.
fn collect_report_rows(
    base: &std::path::Path,
    ws_filter: Option<&str>,
    kind_filter: Option<&str>,
    max_age: Option<std::time::Duration>,
) -> Vec<ReportRow> {
    let mut out: Vec<ReportRow> = Vec::new();
    let now = std::time::SystemTime::now();
    let ws_iter: Vec<String> = if let Some(ws) = ws_filter {
        vec![ws.into()]
    } else {
        match std::fs::read_dir(base) {
            Ok(entries) => entries
                .flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => return out,
        }
    };

    let kinds: Vec<&str> = match kind_filter {
        Some("task") | Some("tasks") => vec!["tasks"],
        Some("workflow") | Some("workflows") => vec!["workflows"],
        Some("scan") | Some("scans") => vec!["scans"],
        _ => vec!["tasks", "workflows", "scans"],
    };

    for ws in ws_iter {
        let ws_dir = base.join(&ws);
        for kind in &kinds {
            let dir = ws_dir.join(kind);
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let id = entry.file_name().to_string_lossy().into_owned();
                let runner_dir = entry.path();
                let report_json = runner_dir.join("report.json");
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                if let Some(age) = max_age {
                    if let Ok(elapsed) = now.duration_since(mtime) {
                        if elapsed > age {
                            continue;
                        }
                    }
                }
                let row = build_row(&ws, kind, &id, &runner_dir, &report_json, mtime);
                out.push(row);
            }
        }
    }
    out.sort_by_key(|r| std::cmp::Reverse(r.mtime));
    out
}

fn build_row(
    ws: &str,
    kind: &str,
    id: &str,
    runner_dir: &std::path::Path,
    report_json: &std::path::Path,
    mtime: std::time::SystemTime,
) -> ReportRow {
    let mut row = ReportRow {
        workspace: ws.into(),
        kind: kind.into(),
        id: id.into(),
        name: String::new(),
        target: String::new(),
        profiles: String::new(),
        start: 0.0,
        end: 0.0,
        elapsed_human: String::new(),
        status: String::new(),
        vuln_counts: Default::default(),
        path: runner_dir.to_path_buf(),
        mtime,
    };
    let Ok(body) = std::fs::read_to_string(report_json) else { return row; };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else { return row; };
    let info = json.get("info").cloned().unwrap_or(serde_json::Value::Null);
    row.name = info.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    row.status = info.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string();
    row.start = info.get("start_time").and_then(|v| v.as_f64()).unwrap_or(0.0);
    row.end = info.get("end_time").and_then(|v| v.as_f64()).unwrap_or(0.0);
    row.elapsed_human = info.get("elapsed_human").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if let Some(targets) = info.get("targets").and_then(|v| v.as_array()) {
        let strs: Vec<&str> = targets.iter().filter_map(|v| v.as_str()).collect();
        if let Some(first) = strs.first() {
            row.target = first.to_string();
            if strs.len() > 1 {
                row.target.push_str(&format!(" (+{})", strs.len() - 1));
            }
        }
    }
    if let Some(p) = info.get("run_opts").and_then(|v| v.get("profiles")) {
        row.profiles = match p {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::new(),
        };
    }
    if let Some(vulns) = json
        .get("results")
        .and_then(|r| r.get("vulnerability"))
        .and_then(|v| v.as_array())
    {
        for v in vulns {
            let sev = v
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            *row.vuln_counts.entry(sev).or_insert(0) += 1;
        }
    }
    row
}

fn print_report_table(rows: &[ReportRow], show_all: bool) {
    // Compute per-column widths.
    let headers: Vec<&str> = if show_all {
        vec!["Workspace", "Name", "Id", "Target", "Profiles", "Start", "End", "Elapsed", "Status", "Vulns", "Path"]
    } else {
        vec!["Workspace", "Name", "Id", "Target", "Profiles", "Start", "End", "Elapsed", "Status", "Vulns"]
    };
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let runner_id = format!("{}/{}", r.kind, r.id);
            let mut v = vec![
                r.workspace.clone(),
                r.name.clone(),
                runner_id,
                r.target.clone(),
                r.profiles.clone(),
                format_unix(r.start),
                format_unix(r.end),
                r.elapsed_human.clone(),
                r.status.clone(),
                format_vuln_counts(&r.vuln_counts),
            ];
            if show_all {
                v.push(r.path.to_string_lossy().into());
            }
            v
        })
        .collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            if c.chars().count() > widths[i] {
                widths[i] = c.chars().count();
            }
        }
    }
    print_row(&headers.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &widths);
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    print_row(&sep, &widths);
    for row in &cells {
        print_row(row, &widths);
    }
}

fn print_row(cells: &[String], widths: &[usize]) {
    let parts: Vec<String> = cells
        .iter()
        .zip(widths.iter())
        .map(|(c, w)| {
            let pad = w.saturating_sub(c.chars().count());
            format!("{}{}", c, " ".repeat(pad))
        })
        .collect();
    println!("{}", parts.join("  "));
}

fn format_unix(secs: f64) -> String {
    if secs <= 0.0 {
        return String::new();
    }
    // No chrono dep — render as `YYYY-MM-DDTHH:MM:SSZ` via std SystemTime arithmetic.
    let ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(secs.max(0.0));
    let secs_since_epoch = ts
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days-based date math (Howard Hinnant's date algorithm — minimal port).
    let secs_in_day = secs_since_epoch % 86_400;
    let days = (secs_since_epoch / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_in_day / 3600;
    let mm = (secs_in_day % 3600) / 60;
    let ss = secs_in_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days-since-1970 → (year, month, day). Adapted from Howard Hinnant's
/// `civil_from_days` algorithm; valid for all Gregorian dates.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}

fn format_vuln_counts(counts: &std::collections::BTreeMap<String, i64>) -> String {
    if counts.is_empty() {
        return "-".into();
    }
    // Severity order matches Python's table column.
    let order = ["critical", "high", "medium", "low", "info", "unknown"];
    let labels = ["C", "H", "M", "L", "I", "?"];
    let mut parts: Vec<String> = Vec::new();
    for (sev, label) in order.iter().zip(labels.iter()) {
        if let Some(n) = counts.get(*sev) {
            if *n > 0 {
                parts.push(format!("{n}{label}"));
            }
        }
    }
    // Pick up any unexpected severities (Python keeps them silent; we surface as "?").
    for (k, v) in counts {
        if !order.contains(&k.as_str()) && *v > 0 {
            parts.push(format!("{v}?"));
        }
    }
    if parts.is_empty() { "-".into() } else { parts.join("|") }
}

fn print_report_info(json: &serde_json::Value, path: &std::path::Path) {
    println!("Report: {}", path.display());
    let info = json.get("info").cloned().unwrap_or(serde_json::Value::Null);
    let kv = |k: &str| -> String {
        match info.get(k) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            Some(v) => v.to_string(),
            None => String::new(),
        }
    };
    println!("  name:           {}", kv("name"));
    println!("  status:         {}", kv("status"));
    println!("  workspace:      {}", kv("workspace"));
    println!("  targets:        {}", kv("targets"));
    let start = info.get("start_time").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let end = info.get("end_time").and_then(|v| v.as_f64()).unwrap_or(0.0);
    println!("  start:          {}", format_unix(start));
    println!("  end:            {}", format_unix(end));
    println!("  elapsed:        {}", kv("elapsed_human"));
    println!("  findings_count: {}", kv("findings_count"));
    println!("  errors_count:   {}", kv("errors_count"));
    if let Some(results) = json.get("results").and_then(|v| v.as_object()) {
        let mut counts: Vec<(String, usize)> = Vec::new();
        for (ty, items) in results {
            if let Some(arr) = items.as_array() {
                if !arr.is_empty() {
                    counts.push((ty.clone(), arr.len()));
                }
            }
        }
        if !counts.is_empty() {
            println!("  results:");
            for (ty, n) in counts {
                println!("    {ty}: {n}");
            }
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn parse_time_delta_known_suffixes() {
        assert_eq!(parse_time_delta("30s").unwrap().as_secs(), 30);
        assert_eq!(parse_time_delta("5m").unwrap().as_secs(), 300);
        assert_eq!(parse_time_delta("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_time_delta("1d").unwrap().as_secs(), 86_400);
        assert_eq!(parse_time_delta("1w").unwrap().as_secs(), 604_800);
        assert_eq!(parse_time_delta("1y").unwrap().as_secs(), 31_536_000);
    }

    #[test]
    fn parse_time_delta_rejects_garbage() {
        assert!(parse_time_delta("abc").is_none());
        assert!(parse_time_delta("5z").is_none());
        assert!(parse_time_delta("").is_none());
    }

    #[test]
    fn format_unix_zero_is_blank() {
        assert_eq!(format_unix(0.0), "");
        assert_eq!(format_unix(-1.0), "");
    }

    #[test]
    fn format_unix_epoch() {
        assert_eq!(format_unix(1.0), "1970-01-01T00:00:01Z");
    }

    #[test]
    fn format_unix_known_date() {
        // 1_781_308_800 = 2026-06-13T00:00:00Z (verified against Python datetime).
        assert_eq!(format_unix(1_781_308_800.0), "2026-06-13T00:00:00Z");
    }

    #[test]
    fn format_vuln_counts_orders_severity() {
        let mut c: std::collections::BTreeMap<String, i64> = Default::default();
        c.insert("medium".into(), 2);
        c.insert("critical".into(), 1);
        c.insert("low".into(), 3);
        // C first, then M, then L.
        assert_eq!(format_vuln_counts(&c), "1C|2M|3L");
    }

    #[test]
    fn format_vuln_counts_empty_is_dash() {
        assert_eq!(format_vuln_counts(&Default::default()), "-");
    }
}

// ------------------------------------------------------------------ Query (`q`)

pub fn build_query_subcommand() -> Command {
    Command::new("query")
        .about("Search findings across reports with MongoDB-style filters.")
        .visible_alias("q")
        .arg(
            Arg::new("expr")
                .help("Query expression. Type-only ('vulnerability'), comparisons \
                       ('url.host == \"x\"'), AND/OR, or raw JSON.")
                .value_name("EXPR")
                .num_args(0..=1),
        )
        .arg(
            Arg::new("paths")
                .long("paths")
                .short('p')
                .value_name("PATHS")
                .help("Comma-separated runner paths (e.g. scans/5,tasks/3)"),
        )
        .arg(
            Arg::new("workspace")
                .long("workspace")
                .short('w')
                .visible_alias("ws")
                .value_name("NAME"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .short('n')
                .value_name("N")
                .default_value("100")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .help("Print only the match count (don't render items)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .value_name("SPEC")
                .help("Output format: 'json' (default), 'raw' (primary field), 'jsonl'"),
        )
        .arg(
            Arg::new("driver")
                .long("driver")
                .value_name("NAME")
                .default_value("json")
                .help("Query backend: 'json' (default, walks reports dir), 'mongodb', 'api'"),
        )
}

pub fn run_query_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let config = secator_config::get();
    let workspace = args
        .get_one::<String>("workspace")
        .cloned()
        .unwrap_or_else(|| {
            if config.workspace.default.is_empty() {
                "default".into()
            } else {
                config.workspace.default.clone()
            }
        });
    let expr = args.get_one::<String>("expr").map(String::as_str).unwrap_or("");
    let paths_filter = args.get_one::<String>("paths").map(String::as_str).unwrap_or("");
    let limit = *args.get_one::<usize>("limit").unwrap_or(&100);
    let want_count = args.get_flag("count");
    let format = args.get_one::<String>("format").map(String::as_str).unwrap_or("json");

    let expr_query = match secator_query::python_expr_to_mongo(expr) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("{}", err(&format!("query parse error: {e}"), style));
            return ExitCode::from(2);
        }
    };
    let path_query = secator_query::parse_report_paths(paths_filter);
    let merged = merge_queries(path_query, expr_query);

    let driver_name = args
        .get_one::<String>("driver")
        .map(String::as_str)
        .unwrap_or("json");
    use secator_query::QueryBackend;
    let backend: Box<dyn QueryBackend> = match driver_name {
        "json" | "" => Box::new(secator_query::JsonBackend::new(
            config.dirs.reports.clone(),
            workspace.clone(),
        )),
        "mongodb" | "mongo" => Box::new(secator_mongo::MongoQueryBackend::new(
            config.addons.mongodb.clone(),
            workspace.clone(),
        )),
        "api" => Box::new(secator_api::ApiQueryBackend::new(
            config.addons.api.clone(),
            workspace.clone(),
        )),
        other => {
            eprintln!(
                "{}",
                err(
                    &format!("unknown query driver `{other}` (try json, mongodb, api)"),
                    style
                )
            );
            return ExitCode::from(2);
        }
    };
    if want_count {
        let n = backend.count(&merged);
        println!("{n}");
        return ExitCode::SUCCESS;
    }
    let results = backend.search(&merged, Some(limit));
    let n = results.len();
    match format {
        "raw" => {
            for item in &results {
                if let Some(p) = primary_field(item) {
                    println!("{p}");
                }
            }
        }
        "jsonl" => {
            for item in &results {
                if let Ok(s) = serde_json::to_string(item) {
                    println!("{s}");
                }
            }
        }
        "json" | "" => {
            let arr = serde_json::Value::Array(results.clone());
            if let Ok(s) = serde_json::to_string_pretty(&arr) {
                println!("{s}");
            }
        }
        // Template form (Python `_apply_format`):
        //   `{port.host}:{port.port}` — render Port items as `host:port`
        //   `{url.url} || {tag.value}` — try first template, fall back to second
        //   `{url}` (no `type.` prefix) — only allowed when exactly one type is present
        _ => render_format_template(&results, format),
    }
    eprintln!(
        "{}",
        info(&format!("Found {n} finding(s) in workspace '{workspace}'."), style)
    );
    ExitCode::SUCCESS
}

/// Render each item through the supplied `--format` template (Python parity).
/// Skip items that don't match the requested type / are missing referenced
/// fields. Lines are printed to stdout; non-matching items produce no output.
fn render_format_template(items: &[serde_json::Value], spec: &str) {
    // Split alternates on `||` (outside braces).
    let alternates: Vec<&str> = spec
        .split("||")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if alternates.is_empty() {
        return;
    }
    // Collect distinct types present in `items` for the field-only fallback.
    let nonempty_types: std::collections::BTreeSet<String> = items
        .iter()
        .filter_map(|i| i.get("_type").and_then(|v| v.as_str()).map(String::from))
        .collect();
    for item in items {
        let item_type = item.get("_type").and_then(|v| v.as_str()).unwrap_or("");
        for tmpl in &alternates {
            if let Some(line) = apply_one_template(tmpl, item, item_type, &nonempty_types) {
                println!("{line}");
                break;
            }
        }
    }
}

/// Apply a single `{type.field}` (or `{field}`) template to one item. Returns
/// `Some(line)` when every `{...}` placeholder resolves on this item, `None`
/// when the item type doesn't match or any field is missing.
fn apply_one_template(
    tmpl: &str,
    item: &serde_json::Value,
    item_type: &str,
    nonempty_types: &std::collections::BTreeSet<String>,
) -> Option<String> {
    // Walk the template, replacing `{...}` placeholders. Use a small state
    // machine so we don't pull in a regex for one-shot interpolation.
    let mut out = String::with_capacity(tmpl.len());
    let bytes = tmpl.as_bytes();
    let mut i = 0;
    // Track placeholder types we encountered so we can enforce "single type"
    // when the operator omitted the `type.` prefix.
    let mut placeholder_types: Vec<String> = Vec::new();
    while i < bytes.len() {
        if bytes[i] != b'{' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        // Find matching `}`.
        let close = match tmpl[i..].find('}') {
            Some(j) => i + j,
            None => return None, // unbalanced — treat as no-match
        };
        let inner = &tmpl[i + 1..close];
        i = close + 1;
        // `inner` is either `type.field` or `field` (no dot ⇒ field-only mode).
        let (req_type, field) = match inner.split_once('.') {
            Some((t, f)) => (Some(t), f),
            None => (None, inner),
        };
        if let Some(t) = req_type {
            placeholder_types.push(t.into());
            if t != item_type {
                return None;
            }
        } else {
            // Field-only: only allowed when exactly one type is present in
            // the result set (Python parity).
            if nonempty_types.len() != 1 {
                return None;
            }
        }
        let v = lookup_template_field(item, field)?;
        out.push_str(&v);
    }
    // If multiple distinct type-prefixed placeholders, all must match the item's type.
    if !placeholder_types.is_empty()
        && !placeholder_types.iter().all(|t| t == item_type)
    {
        return None;
    }
    Some(out)
}

/// Resolve `path` (dotted) against `item` and render the matched value as a
/// string. Returns `None` when any segment is missing. Arrays / objects are
/// JSON-stringified so the operator can still see structure in the output.
fn lookup_template_field(item: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = item;
    for segment in path.split('.') {
        let next = cur.get(segment)?;
        cur = next;
    }
    Some(match cur {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// Merge a runner-path query with an expression query. Overlapping keys land
/// under `$and` so neither side silently overrides the other (Python parity).
fn merge_queries(a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    let (av, bv) = match (a, b) {
        (av, serde_json::Value::Object(bm)) if bm.is_empty() => return av,
        (serde_json::Value::Object(am), bv) if am.is_empty() => return bv,
        (av, bv) => (av, bv),
    };
    let (ao, bo) = match (av.as_object(), bv.as_object()) {
        (Some(a), Some(b)) => (a.clone(), b.clone()),
        _ => return serde_json::json!({"$and": [av, bv]}),
    };
    let overlap = ao.keys().any(|k| bo.contains_key(k));
    if overlap {
        serde_json::json!({"$and": [serde_json::Value::Object(ao), serde_json::Value::Object(bo)]})
    } else {
        let mut merged = ao;
        for (k, v) in bo {
            merged.insert(k, v);
        }
        serde_json::Value::Object(merged)
    }
}

/// Pick a sensible "primary" field for `--format raw` (Python `Output.print_raw`).
fn primary_field(item: &serde_json::Value) -> Option<String> {
    let ty = item.get("_type").and_then(|v| v.as_str()).unwrap_or("");
    let candidates: &[&str] = match ty {
        "subdomain" | "ip" => &["host", "ip"],
        "port" => &["host", "ip"],
        "url" => &["url"],
        "vulnerability" | "exploit" | "tag" => &["name", "matched_at"],
        "domain" => &["domain"],
        "user_account" => &["email", "username"],
        "certificate" => &["host", "subject_cn"],
        _ => &["name", "host", "url", "ip"],
    };
    for c in candidates {
        if let Some(v) = item.get(*c).and_then(|x| x.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_with_no_overlap_flattens() {
        let a = json!({"_context.scan_id": "5"});
        let b = json!({"_type": "url"});
        let merged = merge_queries(a, b);
        assert_eq!(merged, json!({"_context.scan_id": "5", "_type": "url"}));
    }

    #[test]
    fn merge_with_empty_lhs_returns_rhs() {
        let merged = merge_queries(json!({}), json!({"_type": "url"}));
        assert_eq!(merged, json!({"_type": "url"}));
    }

    #[test]
    fn merge_with_overlap_uses_dollar_and() {
        let a = json!({"_type": "url", "host": "x"});
        let b = json!({"_type": "vulnerability"});
        let merged = merge_queries(a, b);
        assert_eq!(
            merged,
            json!({"$and": [
                {"_type": "url", "host": "x"},
                {"_type": "vulnerability"},
            ]})
        );
    }

    #[test]
    fn primary_field_picks_url_for_urls() {
        let item = json!({"_type": "url", "url": "https://example"});
        assert_eq!(primary_field(&item).as_deref(), Some("https://example"));
    }

    #[test]
    fn primary_field_falls_back_when_missing() {
        let item = json!({"_type": "url"});
        assert_eq!(primary_field(&item), None);
    }
}

// ----------------------------------------------------------------- Addons CLI

pub fn build_addons_subcommand() -> Command {
    Command::new("addons")
        .about("List / enable / disable optional addons (Mongo, API, …).")
        .visible_alias("a")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("Show the addon table with current enabled status."),
        )
        .subcommand(
            Command::new("enable")
                .about("Flip an addon's enabled flag in ~/.secator/config.yml to true.")
                .arg(Arg::new("name").required(true).value_name("NAME")),
        )
        .subcommand(
            Command::new("disable")
                .about("Flip an addon's enabled flag in ~/.secator/config.yml to false.")
                .arg(Arg::new("name").required(true).value_name("NAME")),
        )
}

pub fn run_addons_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    match args.subcommand() {
        Some(("list", _)) => {
            let config = secator_config::get();
            let rows: Vec<(&str, &str, bool, &str)> = vec![
                (
                    "mongodb",
                    "MongoDB driver — persist runner state + findings.",
                    config.addons.mongodb.enabled,
                    "addons.mongodb.enabled",
                ),
                (
                    "api",
                    "HTTP API driver — POST findings to a webhook / Secator Cloud.",
                    config.addons.api.enabled,
                    "addons.api.enabled",
                ),
                (
                    "slack",
                    "Slack webhook — post findings + lifecycle events to a channel.",
                    config.addons.slack.enabled,
                    "addons.slack.enabled",
                ),
                (
                    "discord",
                    "Discord webhook — same as Slack, for a Discord server.",
                    config.addons.discord.enabled,
                    "addons.discord.enabled",
                ),
                (
                    "gcs",
                    "Google Cloud Storage — upload screenshots / stored responses to a bucket.",
                    config.addons.gcs.enabled,
                    "addons.gcs.enabled",
                ),
            ];
            println!("{:<10}  {:<8}  {:<24}  {}", "NAME", "ENABLED", "CONFIG KEY", "DESCRIPTION");
            println!("{}", "-".repeat(80));
            for (name, desc, on, key) in rows {
                let mark = if on { "✓ yes" } else { "  no" };
                println!("{name:<10}  {mark:<8}  {key:<24}  {desc}");
            }
            ExitCode::SUCCESS
        }
        Some(("enable", sub)) | Some(("disable", sub)) => {
            let name = sub.get_one::<String>("name").expect("name");
            let enable = matches!(args.subcommand_name(), Some("enable"));
            let key = match name.as_str() {
                "mongodb" => "addons.mongodb.enabled",
                "api" => "addons.api.enabled",
                "slack" => "addons.slack.enabled",
                "discord" => "addons.discord.enabled",
                "gcs" => "addons.gcs.enabled",
                other => {
                    eprintln!("{}", err(&format!("unknown addon: {other}"), style));
                    return ExitCode::from(2);
                }
            };
            match set_config_bool(key, enable) {
                Ok(path) => {
                    eprintln!(
                        "{}",
                        info(
                            &format!(
                                "Set {key} = {} in {}",
                                enable,
                                path.display()
                            ),
                            style,
                        )
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", err(&format!("addons {}: {e}", if enable { "enable" } else { "disable" }), style));
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("{}", err("subcommand required", style));
            ExitCode::from(2)
        }
    }
}

/// Update a dotted bool key in `~/.secator/config.yml`, creating the file if
/// needed. Returns the path that was written.
fn set_config_bool(dotted_key: &str, value: bool) -> Result<std::path::PathBuf, String> {
    let path = secator_config::user_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let body = if path.exists() {
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?
    } else {
        String::new()
    };
    let mut yaml: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?
    };
    set_yaml_dotted(&mut yaml, dotted_key, serde_yaml::Value::Bool(value));
    let out = serde_yaml::to_string(&yaml).map_err(|e| format!("encode yaml: {e}"))?;
    std::fs::write(&path, out).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn set_yaml_dotted(root: &mut serde_yaml::Value, key: &str, value: serde_yaml::Value) {
    let parts: Vec<&str> = key.split('.').collect();
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let is_last = i + 1 == parts.len();
        if !matches!(cur, serde_yaml::Value::Mapping(_)) {
            *cur = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        let map = cur.as_mapping_mut().unwrap();
        let k = serde_yaml::Value::String((*part).into());
        if is_last {
            map.insert(k, value.clone());
            return;
        }
        if !map.contains_key(&k) {
            map.insert(k.clone(), serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        }
        cur = map.get_mut(&k).unwrap();
    }
}

#[cfg(test)]
mod addons_tests {
    use super::*;

    #[test]
    fn set_yaml_dotted_creates_nested_keys() {
        let mut root = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        set_yaml_dotted(&mut root, "addons.mongodb.enabled", serde_yaml::Value::Bool(true));
        let mongo = root
            .get("addons")
            .and_then(|v| v.get("mongodb"))
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool());
        assert_eq!(mongo, Some(true));
    }

    #[test]
    fn set_yaml_dotted_replaces_existing() {
        let mut root = serde_yaml::from_str::<serde_yaml::Value>(
            "addons:\n  mongodb:\n    enabled: false\n",
        )
        .unwrap();
        set_yaml_dotted(&mut root, "addons.mongodb.enabled", serde_yaml::Value::Bool(true));
        assert_eq!(
            root.get("addons")
                .and_then(|v| v.get("mongodb"))
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }
}

// ----------------------------------------------------------------- Alias CLI

pub fn build_alias_subcommand() -> Command {
    Command::new("alias")
        .about("Generate shell aliases for secator commands (`x`, `w`, `s`, …).")
        .arg(
            Arg::new("eval")
                .long("eval")
                .help("Emit a single-line `eval $(...)` form")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("list").about("Print the alias definitions to stdout (default action)"),
        )
        .subcommand(
            Command::new("enable")
                .about("Write the aliases to ~/.secator/.aliases — `source` it from your shell rc"),
        )
        .subcommand(
            Command::new("disable")
                .about("Write `unalias` lines to ~/.secator/.unalias — `source` to undo"),
        )
}

/// (alias, target) pairs — Python `list_aliases` 1:1. Single source of truth so
/// `list` / `enable` / `disable` / `--eval` stay in sync.
const ALIAS_PAIRS: &[(&str, &str)] = &[
    ("x", "secator task"),
    ("w", "secator workflow"),
    ("s", "secator scan"),
    ("wk", "secator worker"),
    ("c", "secator config"),
    ("ws", "secator workspace"),
    ("p", "secator profile"),
    ("a", "secator addons"),
    ("r", "secator reports"),
    ("h", "secator health"),
    ("i", "secator install"),
    ("cs", "secator cheatsheet"),
    ("q", "secator query"),
];

pub fn run_alias_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let eval = args.get_flag("eval");
    match args.subcommand() {
        Some(("enable", _)) => write_alias_file(false, style),
        Some(("disable", _)) => write_alias_file(true, style),
        Some(("list", _)) | None => {
            if eval {
                for (a, t) in ALIAS_PAIRS {
                    print!("alias {a}='{t}'; ");
                }
                println!();
            } else {
                println!("# Source this file (or `eval \"$(secator alias --eval)\"`).");
                for (a, t) in ALIAS_PAIRS {
                    println!("alias {a}='{t}'");
                }
            }
            ExitCode::SUCCESS
        }
        Some((other, _)) => {
            eprintln!("{}", err(&format!("unknown alias subcommand: {other}"), style));
            ExitCode::from(2)
        }
    }
}

/// Persist alias snippets so the operator can `source` them once and forget.
/// `disable=true` writes `unalias x; unalias w; …` to a separate file so the
/// user can source-and-undo without touching their shell rc.
fn write_alias_file(disable: bool, style: Style) -> ExitCode {
    let dir = secator_config::user_config_path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{}", err(&format!("mkdir {}: {e}", dir.display()), style));
        return ExitCode::from(1);
    }
    let (filename, body) = if disable {
        let mut out = String::from("# secator alias DISABLE — `source` this to remove the aliases\n");
        for (a, _) in ALIAS_PAIRS {
            out.push_str(&format!("unalias {a} 2>/dev/null\n"));
        }
        (".unalias", out)
    } else {
        let mut out = String::from("# secator alias snippet — `source` this from your shell rc\n");
        for (a, t) in ALIAS_PAIRS {
            out.push_str(&format!("alias {a}='{t}'\n"));
        }
        (".aliases", out)
    };
    let target = dir.join(filename);
    if let Err(e) = std::fs::write(&target, body) {
        eprintln!("{}", err(&format!("write {}: {e}", target.display()), style));
        return ExitCode::from(1);
    }
    eprintln!(
        "{}",
        info(
            &format!(
                "Wrote {} — run `source {}` to load",
                target.display(),
                target.display()
            ),
            style,
        )
    );
    ExitCode::SUCCESS
}

// ----------------------------------------------------------------- Update CLI

pub fn build_update_subcommand() -> Command {
    Command::new("update")
        .about("Print version info + how to upgrade the secator binary.")
}

pub fn run_update_subcommand(_args: &ArgMatches) -> ExitCode {
    let v = env!("CARGO_PKG_VERSION");
    println!("secator-rs {v}");
    println!();
    println!("To upgrade:");
    println!("  cargo install --git https://github.com/freelabz/secator --force");
    println!();
    println!("To check the latest released version, run:");
    println!("  git ls-remote --tags https://github.com/freelabz/secator | tail -1");
    ExitCode::SUCCESS
}

// ----------------------------------------------------------------- Utils CLI

pub fn build_utils_subcommand() -> Command {
    Command::new("utils")
        .about("Misc utilities.")
        .visible_alias("u")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("ports")
                .about("Print the top-N most common TCP ports (nmap services list).")
                .arg(
                    Arg::new("top")
                        .long("top")
                        .short('t')
                        .value_name("N")
                        .default_value("100")
                        .value_parser(clap::value_parser!(usize)),
                )
                .arg(
                    Arg::new("delim")
                        .long("delim")
                        .short('d')
                        .value_name("CHAR")
                        .default_value(",")
                        .help("Separator (default ',', use ' ' for space)"),
                ),
        )
        .subcommand(
            Command::new("completion")
                .about("Print a shell completion script for `secator` to stdout.")
                .arg(
                    Arg::new("shell")
                        .required(true)
                        .value_name("SHELL")
                        .value_parser(clap::builder::PossibleValuesParser::new([
                            "bash", "zsh", "fish", "elvish", "powershell",
                        ]))
                        .help("Target shell"),
                ),
        )
        .subcommand(
            Command::new("revshell")
                .about("Print reverse-shell payloads, with placeholders rendered for the given LHOST/LPORT.")
                .arg(
                    Arg::new("name")
                        .value_name("NAME")
                        .help("Shell name or alias (omit to list available shells)")
                        .num_args(0..=1),
                )
                .arg(
                    Arg::new("host")
                        .long("host")
                        .short('H')
                        .value_name("IP")
                        .help("LHOST to embed in the payload (default: first non-loopback interface IP)"),
                )
                .arg(
                    Arg::new("port")
                        .long("port")
                        .short('p')
                        .value_name("N")
                        .default_value("9001")
                        .value_parser(clap::value_parser!(u16))
                        .help("LPORT to embed in the payload"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Force re-download of the revshells.json catalogue")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("listen")
                        .long("listen")
                        .short('l')
                        .help("Spawn a `nc -lvnp <port>` listener after printing the payload")
                        .action(ArgAction::SetTrue),
                ),
        )
}

pub fn run_utils_subcommand(args: &ArgMatches, cli: &mut Command) -> ExitCode {
    match args.subcommand() {
        Some(("ports", sub)) => {
            let n = *sub.get_one::<usize>("top").unwrap_or(&100);
            let delim = sub.get_one::<String>("delim").map(String::as_str).unwrap_or(",");
            let take = TOP_TCP_PORTS.iter().take(n).map(|p| p.to_string()).collect::<Vec<_>>();
            println!("{}", take.join(delim));
            ExitCode::SUCCESS
        }
        Some(("completion", sub)) => {
            use clap_complete::Shell;
            let shell_name = sub.get_one::<String>("shell").map(String::as_str).unwrap_or("");
            let shell = match shell_name {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "elvish" => Shell::Elvish,
                "powershell" => Shell::PowerShell,
                _ => return ExitCode::from(2),
            };
            // The clap Command is named `secator-cli` (binary name) — rename
            // for the completion script so users source `secator` completions.
            let name = cli.get_name().to_string();
            let target = if name == "secator-cli" { "secator".to_string() } else { name };
            clap_complete::generate(shell, cli, target, &mut std::io::stdout());
            ExitCode::SUCCESS
        }
        Some(("revshell", sub)) => run_revshell_subcommand(sub),
        _ => ExitCode::from(2),
    }
}

/// `secator utils revshell` — Python parity with `cli.py::revshell`. Downloads
/// the upstream revshells.json catalogue (cached under `<data>/revshells.json`),
/// finds the requested entry by name/alias, substitutes `{ip}` / `{port}` /
/// `{shell}` placeholders, prints the payload, and optionally spawns a
/// listener.
fn run_revshell_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let config = secator_config::get();
    let cache_dir = config.dirs.data.join("revshells");
    let cache_path = cache_dir.join("revshells.json");
    let force = args.get_flag("force");

    if force || !cache_path.exists() {
        if config.offline_mode {
            eprintln!("{}", err("revshell: cache missing and offline mode is on", style));
            return ExitCode::from(1);
        }
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            eprintln!("{}", err(&format!("revshell: mkdir {}: {e}", cache_dir.display()), style));
            return ExitCode::from(1);
        }
        if let Err(e) = download_revshells(&cache_path) {
            eprintln!("{}", err(&format!("revshell: download failed — {e}"), style));
            return ExitCode::from(1);
        }
        eprintln!("{}", info(&format!("revshell: cached catalogue to {}", cache_path.display()), style));
    }

    let raw = match std::fs::read_to_string(&cache_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", err(&format!("revshell: read {}: {e}", cache_path.display()), style));
            return ExitCode::from(1);
        }
    };
    let shells: Vec<serde_json::Value> = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", err(&format!("revshell: parse {}: {e}", cache_path.display()), style));
            return ExitCode::from(1);
        }
    };

    let want = args.get_one::<String>("name").cloned();
    let lhost = args.get_one::<String>("host").cloned().unwrap_or_else(detect_lhost);
    let lport = *args.get_one::<u16>("port").unwrap_or(&9001);

    // Compute alias per Python: lowercase, strip -c/-e/-i/parens, normalize C#.
    let mut catalog: Vec<(String, String, String)> = Vec::new(); // (alias, name, command)
    for sh in &shells {
        let name = sh.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cmd = sh.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let alias = revshell_alias(&name);
        catalog.push((alias, name, cmd));
    }

    let needle = want.as_deref().unwrap_or("");
    let matched = catalog
        .iter()
        .find(|(alias, name, _)| {
            !needle.is_empty() && (alias == needle || name == needle)
        });

    match matched {
        Some((_, name, cmd)) => {
            // Substitute placeholders Python-style: {ip}, {port}, {shell}.
            let rendered = cmd
                .replace("{ip}", &lhost)
                .replace("{port}", &lport.to_string())
                .replace("{shell}", "/bin/bash");
            eprintln!("{}", info(&format!("revshell `{name}` (LHOST={lhost}, LPORT={lport})"), style));
            println!("{rendered}");
            if args.get_flag("listen") {
                eprintln!("{}", info(&format!("Starting listener on port {lport}…"), style));
                let status = std::process::Command::new("nc")
                    .args(["-lvnp", &lport.to_string()])
                    .status();
                match status {
                    Ok(s) if s.success() => ExitCode::SUCCESS,
                    Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                    Err(e) => {
                        eprintln!("{}", err(&format!("revshell: nc launch failed — {e}"), style));
                        ExitCode::from(1)
                    }
                }
            } else {
                ExitCode::SUCCESS
            }
        }
        None => {
            // List mode.
            eprintln!("Available shells (use the alias):");
            eprintln!("  {:<24} {:<28} {}", "alias", "name", "preview");
            for (alias, name, cmd) in &catalog {
                let preview = cmd.replace('\n', " ");
                let preview = if preview.len() > 40 {
                    format!("{}…", &preview[..40])
                } else {
                    preview
                };
                eprintln!("  {alias:<24} {name:<28} {preview}");
            }
            if want.is_some() {
                eprintln!(
                    "\n{}",
                    err(&format!("revshell: `{needle}` didn't match any name or alias"), style)
                );
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

/// Compute the canonical alias Python uses: lower(strip(spaces→_, ditch -c/-e/-i,
/// `#` → `cs` for C#)). Mirrors the inline transformation in
/// `secator/cli.py::revshell`.
fn revshell_alias(raw_name: &str) -> String {
    let lowered = raw_name.to_lowercase();
    let scrubbed = lowered
        .replace("-c", "")
        .replace("-e", "")
        .replace("-i", "")
        .replace("c#", "cs")
        .replace('#', "")
        .replace('(', "")
        .replace(')', "");
    let collapsed: Vec<&str> = scrubbed.split_whitespace().collect();
    collapsed.join("_").replace("_1", "")
}

/// Auto-detect the operator's LHOST by picking the first non-loopback IPv4
/// from the available interfaces. Falls back to `127.0.0.1` (operator must
/// override with `--host` for a real engagement).
fn detect_lhost() -> String {
    if_addrs::get_if_addrs()
        .ok()
        .into_iter()
        .flatten()
        .filter(|iface| !iface.is_loopback())
        .find_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) => Some(v4.ip.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| "127.0.0.1".into())
}

const REVSHELLS_URL: &str =
    "https://raw.githubusercontent.com/freelabz/secator/main/scripts/revshells.json";

/// Best-effort download of the upstream catalogue. We use `curl`/`wget` over
/// reqwest here because the CLI binary is already happy to shell out for
/// installer scripts and this keeps the synchronous flow simple.
fn download_revshells(dest: &std::path::Path) -> Result<(), String> {
    // Prefer curl when available; fall back to wget. Either is fine.
    let try_one = |cmd: &str, args: &[&str]| -> Result<(), String> {
        let status = std::process::Command::new(cmd)
            .args(args)
            .status()
            .map_err(|e| format!("{cmd} spawn: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} returned exit {:?}", status.code()))
        }
    };
    let dest_str = dest.to_string_lossy().into_owned();
    try_one("curl", &["-fsSL", "-o", &dest_str, REVSHELLS_URL])
        .or_else(|_| try_one("wget", &["-qO", &dest_str, REVSHELLS_URL]))
}

/// Top-100 TCP ports from nmap's `nmap-services` (descending frequency). Used by
/// `secator utils ports --top N` for piping into scanners.
pub const TOP_TCP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

#[cfg(test)]
mod aux_cli_tests {
    use super::*;

    #[test]
    fn top_tcp_ports_has_100_entries() {
        assert_eq!(TOP_TCP_PORTS.len(), 100);
    }

    #[test]
    fn top_tcp_ports_contains_well_knowns() {
        for p in [80, 443, 22, 21, 3389] {
            assert!(TOP_TCP_PORTS.contains(&p), "{p} not in top list");
        }
    }
}

// ----------------------------------------------------------------- Beat / schedule

pub fn build_beat_subcommand() -> Command {
    Command::new("beat")
        .about("Run the cron-style scheduler that enqueues scheduled runs.")
        .arg(
            Arg::new("tick_ms")
                .long("tick-ms")
                .value_name("MS")
                .default_value("1000")
                .value_parser(clap::value_parser!(u64))
                .help("Poll interval (ms). 1000 = one tick per second."),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Don't actually enqueue runs — just log what would fire")
                .action(ArgAction::SetTrue),
        )
}

pub fn build_schedule_subcommand() -> Command {
    Command::new("schedule")
        .about("Manage scheduled entries used by `secator beat`.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("Show all schedule entries."))
        .subcommand(
            Command::new("add")
                .about("Add a new entry. Cron is Quartz-style (sec min hour dom mon dow).")
                .arg(Arg::new("name").required(true).value_name("NAME"))
                .arg(Arg::new("cron").required(true).value_name("CRON"))
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .default_value("task")
                        .help("task | workflow | scan"),
                )
                .arg(
                    Arg::new("template")
                        .long("template")
                        .required(true)
                        .value_name("NAME"),
                )
                .arg(
                    Arg::new("inputs")
                        .long("inputs")
                        .value_name("CSV")
                        .help("Comma-separated targets"),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a schedule entry by name.")
                .arg(Arg::new("name").required(true).value_name("NAME")),
        )
}

pub async fn run_beat_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let tick_ms = *args.get_one::<u64>("tick_ms").unwrap_or(&1000);
    let dry_run = args.get_flag("dry_run");
    let path = secator_beat::default_schedule_path();
    let config = secator_config::get();

    eprintln!(
        "{}",
        info(
            &format!(
                "secator beat starting (schedule: {}, tick: {tick_ms}ms{})",
                path.display(),
                if dry_run { ", DRY-RUN" } else { "" },
            ),
            style,
        )
    );

    // Optional Redis transport for the enqueue side. When unset, beat just logs
    // the would-fire entry — operators can wire it later via config.transport.broker_url.
    let broker_url = config.transport.broker_url.clone();
    let redis = if broker_url.starts_with("redis://") || broker_url.starts_with("rediss://") {
        match secator_redis::RedisTransport::open(&broker_url) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("{}", err(&format!("redis open failed ({e}); beat will log-only"), style));
                None
            }
        }
    } else {
        None
    };

    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop2 = stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop2.notify_one();
    });

    let mut last_tick = chrono::Utc::now();
    loop {
        let now = chrono::Utc::now();
        let file = secator_beat::ScheduleFile::load(&path).unwrap_or_default();
        let due = secator_beat::due_indices(&file.entries, last_tick, now);
        for i in &due {
            let entry = &file.entries[*i];
            eprintln!(
                "{}",
                info(
                    &format!(
                        "fire entry '{}' (kind={}, template={}, inputs={:?}){}",
                        entry.name,
                        entry.kind,
                        entry.template,
                        entry.inputs,
                        if dry_run { " [dry-run]" } else { "" },
                    ),
                    style,
                )
            );
            if dry_run {
                continue;
            }
            // Two enqueue paths:
            //   * `task` — submit a WorkUnit directly via Redis Streams (when
            //      configured), which any worker in the consumer group picks up.
            //   * `workflow` / `scan` — spawn `secator <kind> <template> <inputs>`
            //      as a child process. The child does its own planning + routing
            //      (auto-routes through the broker when a worker is alive). This
            //      matches Python's beat-spawns-celery-task model.
            match entry.kind.as_str() {
                "task" if redis.is_some() => {
                    let rt = redis.as_ref().unwrap().clone();
                    let template = entry.template.clone();
                    let inputs = entry.inputs.clone();
                    let opts = entry.opts.clone();
                    tokio::spawn(async move {
                        let (tx, _rx) = tokio::sync::mpsc::channel(1);
                        let _ = rt.execute_task(&template, inputs, opts, None, tx).await;
                    });
                }
                "task" | "workflow" | "scan" => {
                    // Either no Redis, or kind != task. Spawn ourselves as a child.
                    spawn_beat_child(entry);
                }
                other => {
                    eprintln!(
                        "{}",
                        info(&format!("kind={other} not supported (task | workflow | scan)"), style)
                    );
                }
            }
        }
        last_tick = now;
        tokio::select! {
            _ = stop.notified() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(tick_ms)) => {}
        }
    }
    eprintln!("{}", info("secator beat stopped", style));
    ExitCode::SUCCESS
}

pub fn run_schedule_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let path = secator_beat::default_schedule_path();
    match args.subcommand() {
        Some(("list", _)) => {
            let file = secator_beat::ScheduleFile::load(&path).unwrap_or_default();
            if file.entries.is_empty() {
                eprintln!("{}", info("No schedule entries yet.", style));
                return ExitCode::SUCCESS;
            }
            println!("{:<24}  {:<22}  {:<10}  {:<22}  {}", "NAME", "CRON", "KIND", "TEMPLATE", "ENABLED");
            println!("{}", "-".repeat(100));
            for e in &file.entries {
                println!(
                    "{:<24}  {:<22}  {:<10}  {:<22}  {}",
                    e.name,
                    e.cron,
                    e.kind,
                    e.template,
                    if e.enabled { "yes" } else { "no" },
                );
            }
            ExitCode::SUCCESS
        }
        Some(("add", sub)) => {
            let name = sub.get_one::<String>("name").unwrap().clone();
            let cron_expr = sub.get_one::<String>("cron").unwrap().clone();
            if secator_beat::next_fire(&cron_expr, chrono::Utc::now()).is_none() {
                eprintln!(
                    "{}",
                    err(&format!("cron expr {cron_expr:?} doesn't parse or has no future occurrence"), style)
                );
                return ExitCode::from(2);
            }
            let kind = sub.get_one::<String>("kind").unwrap().clone();
            let template = sub.get_one::<String>("template").unwrap().clone();
            let inputs: Vec<String> = sub
                .get_one::<String>("inputs")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let mut file = secator_beat::ScheduleFile::load(&path).unwrap_or_default();
            if file.entries.iter().any(|e| e.name == name) {
                eprintln!("{}", err(&format!("entry {name:?} already exists"), style));
                return ExitCode::from(2);
            }
            file.entries.push(secator_beat::ScheduleEntry {
                name,
                cron: cron_expr,
                kind,
                template,
                inputs,
                opts: Default::default(),
                enabled: true,
            });
            if let Err(e) = file.save(&path) {
                eprintln!("{}", err(&format!("save schedule: {e}"), style));
                return ExitCode::from(1);
            }
            eprintln!("{}", info(&format!("Saved {}", path.display()), style));
            ExitCode::SUCCESS
        }
        Some(("remove", sub)) => {
            let name = sub.get_one::<String>("name").unwrap();
            let mut file = secator_beat::ScheduleFile::load(&path).unwrap_or_default();
            let before = file.entries.len();
            file.entries.retain(|e| &e.name != name);
            if file.entries.len() == before {
                eprintln!("{}", err(&format!("no entry named {name:?}"), style));
                return ExitCode::from(2);
            }
            if let Err(e) = file.save(&path) {
                eprintln!("{}", err(&format!("save schedule: {e}"), style));
                return ExitCode::from(1);
            }
            eprintln!("{}", info(&format!("Removed entry {name:?}"), style));
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(2),
    }
}

/// Spawn `secator <kind> <template> <input1> <input2> ... [--opt=val ...]` as a
/// detached child process. Used by `secator beat` to fire workflow/scan entries
/// (and task entries when no Redis transport is configured). Stdout/stderr are
/// inherited so logs surface alongside the beat scheduler itself.
fn spawn_beat_child(entry: &secator_beat::ScheduleEntry) {
    let exe = std::env::current_exe().unwrap_or_else(|_| "secator".into());
    let kind_arg: &str = match entry.kind.as_str() {
        "workflow" => "workflow",
        "scan" => "scan",
        _ => "task",
    };
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg(kind_arg).arg(&entry.template);
    for t in &entry.inputs {
        cmd.arg(t);
    }
    for (k, v) in &entry.opts {
        cmd.arg(format!("--{}", k.replace('_', "-")));
        cmd.arg(v);
    }
    cmd.stdin(std::process::Stdio::null());
    if let Err(e) = cmd.spawn() {
        eprintln!("beat spawn {} {}: {e}", kind_arg, entry.template);
    }
}

// =============================================================================
// diff CLI — compare findings between two runs.
// =============================================================================

pub fn build_diff_subcommand() -> Command {
    Command::new("diff")
        .about("Compare findings between two runs. Prints A-only, B-only, and common items.")
        .arg(Arg::new("a").required(true).value_name("KIND/ID").help("Left side, e.g. `tasks/42`"))
        .arg(Arg::new("b").required(true).value_name("KIND/ID").help("Right side, e.g. `tasks/43`"))
        .arg(
            Arg::new("workspace")
                .long("workspace")
                .visible_alias("ws")
                .value_name("NAME"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .short('t')
                .value_name("TYPE")
                .help("Restrict the comparison to a single finding type (e.g. vulnerability)"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .value_name("SPEC")
                .default_value("text")
                .value_parser(clap::builder::PossibleValuesParser::new(["text", "json"]))
                .help("Output format"),
        )
}

pub fn run_diff_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let config = secator_config::get();
    let workspace = args
        .get_one::<String>("workspace")
        .cloned()
        .unwrap_or_else(|| {
            if config.workspace.default.is_empty() {
                "default".into()
            } else {
                config.workspace.default.clone()
            }
        });
    let ws_dir = config.dirs.reports.join(&workspace);
    let a_arg = args.get_one::<String>("a").map(String::as_str).unwrap_or("");
    let b_arg = args.get_one::<String>("b").map(String::as_str).unwrap_or("");
    let only_type = args.get_one::<String>("type").cloned();
    let format = args.get_one::<String>("format").map(String::as_str).unwrap_or("text");

    let a_findings = match load_findings_for(&ws_dir, a_arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", err(&format!("diff: {a_arg}: {e}"), style));
            return ExitCode::from(1);
        }
    };
    let b_findings = match load_findings_for(&ws_dir, b_arg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", err(&format!("diff: {b_arg}: {e}"), style));
            return ExitCode::from(1);
        }
    };

    let filter = |v: &serde_json::Value| -> bool {
        only_type.as_ref().map_or(true, |t| {
            v.get("_type").and_then(|x| x.as_str()) == Some(t.as_str())
        })
    };

    // Build maps keyed by a stable "shape" string (Python `compare_key`
    // analogue). We reuse the per-type field projection from the Mongo
    // dedup work — but that lives in secator-mongo so we hand-roll a
    // minimal subset here. Items without a `_type` are dropped.
    let key_of = diff_compare_key;
    let mut a_map: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for v in a_findings.into_iter().filter(filter) {
        if let Some(k) = key_of(&v) {
            a_map.entry(k).or_insert(v);
        }
    }
    let mut b_map: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for v in b_findings.into_iter().filter(filter) {
        if let Some(k) = key_of(&v) {
            b_map.entry(k).or_insert(v);
        }
    }

    let only_a: Vec<&serde_json::Value> =
        a_map.iter().filter(|(k, _)| !b_map.contains_key(*k)).map(|(_, v)| v).collect();
    let only_b: Vec<&serde_json::Value> =
        b_map.iter().filter(|(k, _)| !a_map.contains_key(*k)).map(|(_, v)| v).collect();
    let common: Vec<&serde_json::Value> =
        a_map.iter().filter(|(k, _)| b_map.contains_key(*k)).map(|(_, v)| v).collect();

    match format {
        "text" => {
            eprintln!(
                "{}",
                info(
                    &format!(
                        "diff {a_arg} → {b_arg}: only_a={}, only_b={}, common={}",
                        only_a.len(),
                        only_b.len(),
                        common.len(),
                    ),
                    style
                )
            );
            println!("--- only in {a_arg} ({}) ---", only_a.len());
            for v in &only_a {
                println!("  - {}", diff_summary(v));
            }
            println!("\n+++ only in {b_arg} ({}) +++", only_b.len());
            for v in &only_b {
                println!("  + {}", diff_summary(v));
            }
            println!("\n=== common ({}) ===", common.len());
            for v in &common {
                println!("  = {}", diff_summary(v));
            }
        }
        "json" => {
            let payload = serde_json::json!({
                "a": a_arg, "b": b_arg, "workspace": workspace,
                "only_a": only_a, "only_b": only_b, "common": common,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
        }
        _ => return ExitCode::from(2),
    }

    if !only_a.is_empty() || !only_b.is_empty() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Parse `kind/id` (or just `id` defaulting to `tasks`), find the matching
/// `report.json`, and return its flattened findings list.
fn load_findings_for(ws_dir: &Path, raw: &str) -> Result<Vec<serde_json::Value>, String> {
    let (kind, id) = match raw.split_once('/') {
        Some((k, i)) => (k.to_string(), i.to_string()),
        None => ("tasks".to_string(), raw.to_string()),
    };
    let path = ws_dir.join(&kind).join(&id).join("report.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let results = json
        .get("results")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("{}: no `results` block", path.display()))?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    for ty in secator_model::FINDING_TYPE_NAMES {
        if let Some(arr) = results.get(*ty).and_then(|v| v.as_array()) {
            for item in arr {
                let mut item = item.clone();
                if let Some(obj) = item.as_object_mut() {
                    obj.insert("_type".into(), serde_json::Value::String((*ty).into()));
                }
                out.push(item);
            }
        }
    }
    Ok(out)
}

/// Lightweight compare-key for diff. Mirrors the per-type field set the
/// mongo crate uses for `tag_duplicates`. Returns None when the type isn't
/// recognized.
fn diff_compare_key(v: &serde_json::Value) -> Option<String> {
    let ty = v.get("_type").and_then(|x| x.as_str())?;
    let s = |key: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    let i = |key: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default()
    };
    let parts: Vec<String> = match ty {
        "url" => vec![s("url")],
        "subdomain" => vec![s("host"), s("domain")],
        "ip" => vec![s("ip"), s("protocol")],
        "port" => vec![s("ip"), i("port"), s("protocol")],
        "tag" => vec![s("name"), s("value"), s("match"), s("category")],
        "vulnerability" => vec![s("name"), s("provider"), s("id"), s("matched_at"), s("severity")],
        "exploit" => vec![s("id"), s("provider"), s("matched_at")],
        "technology" => vec![s("product"), s("match"), s("version")],
        "certificate" => vec![s("host"), s("fingerprint_sha256")],
        "domain" => vec![s("host")],
        "user_account" => vec![s("username"), s("site_name")],
        "record" => vec![s("name"), s("type"), s("host")],
        _ => return None,
    };
    Some(format!("{ty}:{}", parts.join("|")))
}

fn diff_summary(v: &serde_json::Value) -> String {
    let ty = v.get("_type").and_then(|x| x.as_str()).unwrap_or("?");
    match ty {
        "url" => format!(
            "url: {} ({})",
            v.get("url").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("status_code").and_then(|x| x.as_i64()).unwrap_or(0)
        ),
        "port" => format!(
            "port: {}/{} {} {}",
            v.get("port").and_then(|x| x.as_i64()).unwrap_or(0),
            v.get("protocol").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("state").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("service_name").and_then(|x| x.as_str()).unwrap_or(""),
        ),
        "vulnerability" => format!(
            "vuln: [{}] {} @ {}",
            v.get("severity").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("name").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("matched_at").and_then(|x| x.as_str()).unwrap_or(""),
        ),
        "subdomain" => format!("subdomain: {}", v.get("host").and_then(|x| x.as_str()).unwrap_or("")),
        "ip" => format!("ip: {}", v.get("ip").and_then(|x| x.as_str()).unwrap_or("")),
        other => format!("{other}: {v}"),
    }
}

// =============================================================================
// vuln lookup CLI — Python-side feature gap, added in Rust.
// =============================================================================

pub fn build_vuln_subcommand() -> Command {
    Command::new("vuln")
        .about("Look up CVE / GHSA / EDB ids against the configured providers + local cache.")
        .visible_alias("v")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("lookup")
                .about("Resolve one or more vulnerability ids")
                .arg(
                    Arg::new("ids")
                        .value_name("ID")
                        .help("CVE-YYYY-NNNN, GHSA-…, or EDB-NNNN ids (one or more)")
                        .num_args(1..)
                        .required(true),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .short('f')
                        .value_name("SPEC")
                        .default_value("table")
                        .value_parser(clap::builder::PossibleValuesParser::new(["table", "json", "jsonl"]))
                        .help("Output format"),
                )
                .arg(
                    Arg::new("refresh")
                        .long("refresh")
                        .help("Skip the local cache; always hit the upstream provider")
                        .action(ArgAction::SetTrue),
                ),
        )
}

pub async fn run_vuln_subcommand(args: &ArgMatches) -> ExitCode {
    let style = Style::detect_stderr();
    let config = secator_config::get();
    let Some(("lookup", sub)) = args.subcommand() else {
        eprintln!("{}", err("vuln: subcommand required (try `vuln lookup <ID>`)", style));
        return ExitCode::from(2);
    };

    let ids: Vec<String> = sub
        .get_many::<String>("ids")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    if ids.is_empty() {
        eprintln!("{}", err("vuln lookup: at least one id required", style));
        return ExitCode::from(2);
    }
    let format = sub.get_one::<String>("format").map(String::as_str).unwrap_or("table");
    let refresh = sub.get_flag("refresh");

    // CVE / GHSA chain — same one the runner uses.
    let cve_cache = secator_providers::LocalCache::new(config.dirs.data.clone());
    let cve_providers: Vec<Box<dyn secator_providers::CveProvider>> = build_cve_chain(&config);
    // Exploit cache + chain — used when the id looks like EDB-NNNN.
    let exploit_cache = secator_providers::ExploitCache::new(config.dirs.data.clone());
    let exploit_providers: Vec<Box<dyn secator_providers::ExploitProvider>> =
        build_exploit_chain_local(&config);

    if format == "table" {
        eprintln!(
            "{:<24} {:<10} {:>10} {:<8} {:<10} {}",
            "id", "severity", "cvss", "epss", "provider", "summary"
        );
        eprintln!("{}", "-".repeat(110));
    }

    let mut exit = ExitCode::SUCCESS;
    let mut first_jsonl = true;
    for id in &ids {
        let kind = classify_id(id);
        match kind {
            VulnKind::Cve | VulnKind::Ghsa => {
                let resolved = if refresh {
                    enrich_via_providers_only(id, &cve_providers).await
                } else {
                    secator_providers::enrich_one(id, &cve_cache, &cve_providers).await
                };
                match resolved {
                    Some(v) => render_cve(id, &v, format, &mut first_jsonl),
                    None => {
                        if format == "table" {
                            eprintln!("{id:<24} (not found in any provider)");
                        } else if format == "json" || format == "jsonl" {
                            let line = serde_json::to_string(&serde_json::json!({
                                "id": id, "status": "not_found"
                            })).unwrap_or_default();
                            if format == "json" {
                                println!("{line}");
                            } else {
                                if !first_jsonl { println!(); }
                                print!("{line}");
                                first_jsonl = false;
                            }
                        }
                        exit = ExitCode::from(1);
                    }
                }
            }
            VulnKind::Edb => {
                let resolved = if refresh {
                    fetch_exploit_via_providers_only(id, &exploit_providers).await
                } else {
                    secator_providers::enrich_one_exploit(id, &exploit_cache, &exploit_providers).await
                };
                match resolved {
                    Some(body) => render_exploit(id, &body, format, &mut first_jsonl),
                    None => {
                        if format == "table" {
                            eprintln!("{id:<24} (no exploit provider matched)");
                        }
                        exit = ExitCode::from(1);
                    }
                }
            }
            VulnKind::Unknown => {
                eprintln!(
                    "{}",
                    err(
                        &format!("vuln lookup: `{id}` isn't a CVE / GHSA / EDB id"),
                        style
                    )
                );
                exit = ExitCode::from(1);
            }
        }
    }
    if format == "jsonl" {
        println!();
    }
    exit
}

#[derive(Debug, Clone, Copy)]
enum VulnKind {
    Cve,
    Ghsa,
    Edb,
    Unknown,
}

fn classify_id(id: &str) -> VulnKind {
    let upper = id.to_uppercase();
    if upper.starts_with("CVE-") {
        VulnKind::Cve
    } else if upper.starts_with("GHSA-") {
        VulnKind::Ghsa
    } else if upper.starts_with("EDB-") {
        VulnKind::Edb
    } else {
        VulnKind::Unknown
    }
}

/// Same shape as the runner-side CVE chain, kept local so we don't have to
/// import the private `build_cve_chain` from `main.rs`.
fn build_cve_chain(
    cfg: &secator_config::Config,
) -> Vec<Box<dyn secator_providers::CveProvider>> {
    if cfg.offline_mode || cfg.runners.skip_cve_search {
        return Vec::new();
    }
    let mut chain: Vec<Box<dyn secator_providers::CveProvider>> = Vec::new();
    match cfg.providers.cve() {
        "circl" | "" => chain.push(Box::new(secator_providers::CirclProvider::new())),
        "vulners" => chain.push(Box::new(secator_providers::VulnersProvider::from_config(
            cfg.addons.vulners.clone(),
        ))),
        _ => {}
    }
    match cfg.providers.ghsa() {
        "ghsa" | "" => chain.push(Box::new(secator_providers::GhsaProvider::new())),
        _ => {}
    }
    if cfg.addons.vulners.enabled
        && !cfg.addons.vulners.api_key.is_empty()
        && cfg.providers.cve() != "vulners"
    {
        chain.push(Box::new(secator_providers::VulnersProvider::from_config(
            cfg.addons.vulners.clone(),
        )));
    }
    chain
}

fn build_exploit_chain_local(
    cfg: &secator_config::Config,
) -> Vec<Box<dyn secator_providers::ExploitProvider>> {
    if cfg.offline_mode || cfg.runners.skip_exploit_search {
        return Vec::new();
    }
    let mut chain: Vec<Box<dyn secator_providers::ExploitProvider>> = Vec::new();
    match cfg.providers.exploit() {
        "exploitdb" | "" => chain.push(Box::new(secator_providers::ExploitDbProvider::new())),
        _ => {}
    }
    chain
}

/// Cache-bypass variant: walk providers in order and return the first hit
/// without consulting / writing the on-disk cache. Used by `--refresh`.
async fn enrich_via_providers_only(
    id: &str,
    providers: &[Box<dyn secator_providers::CveProvider>],
) -> Option<secator_model::Vulnerability> {
    for p in providers {
        if let Ok(v) = p.lookup_cve(id).await {
            return Some(v);
        }
    }
    None
}

async fn fetch_exploit_via_providers_only(
    id: &str,
    providers: &[Box<dyn secator_providers::ExploitProvider>],
) -> Option<String> {
    for p in providers {
        if let Ok(body) = p.lookup_exploit(id).await {
            return Some(body);
        }
    }
    None
}

fn render_cve(id: &str, v: &secator_model::Vulnerability, format: &str, first_jsonl: &mut bool) {
    match format {
        "table" => {
            let preview = first_line(&v.description, 60);
            let provider = if v.provider.is_empty() { "?" } else { v.provider.as_str() };
            let cvss = if v.cvss_score > 0.0 {
                format!("{:.1}", v.cvss_score)
            } else {
                "-".into()
            };
            let epss = if v.epss_score > 0.0 {
                format!("{:.2}", v.epss_score)
            } else {
                "-".into()
            };
            println!(
                "{id:<24} {sev:<10} {cvss:>10} {epss:<8} {provider:<10} {preview}",
                id = id,
                sev = if v.severity.is_empty() { "-".into() } else { v.severity.clone() },
                cvss = cvss,
                epss = epss,
                provider = provider,
                preview = preview,
            );
        }
        "json" => {
            let line = serde_json::to_string(&v.to_map()).unwrap_or_default();
            println!("{line}");
        }
        "jsonl" => {
            let line = serde_json::to_string(&v.to_map()).unwrap_or_default();
            if !*first_jsonl {
                println!();
            }
            print!("{line}");
            *first_jsonl = false;
        }
        _ => {}
    }
}

fn render_exploit(id: &str, body: &str, format: &str, first_jsonl: &mut bool) {
    let bytes = body.len();
    match format {
        "table" => {
            println!(
                "{id:<24} {sev:<10} {cvss:>10} {epss:<8} {provider:<10} {preview}",
                id = id,
                sev = "n/a",
                cvss = "-",
                epss = "-",
                provider = "exploitdb",
                preview = format!("(html cached, {bytes} bytes)"),
            );
        }
        "json" => {
            let line = serde_json::to_string(&serde_json::json!({
                "id": id, "provider": "exploitdb", "bytes": bytes,
            })).unwrap_or_default();
            println!("{line}");
        }
        "jsonl" => {
            let line = serde_json::to_string(&serde_json::json!({
                "id": id, "provider": "exploitdb", "bytes": bytes,
            })).unwrap_or_default();
            if !*first_jsonl {
                println!();
            }
            print!("{line}");
            *first_jsonl = false;
        }
        _ => {}
    }
}

fn first_line(s: &str, max: usize) -> String {
    let first = s.lines().next().unwrap_or("");
    if first.chars().count() <= max {
        first.to_string()
    } else {
        let head: String = first.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}
