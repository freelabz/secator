//! msfconsole — Metasploit framework console wrapper (Python
//! `secator/tasks/msfconsole.py`).
//!
//! msfconsole produces no Secator-typed items: `output_types = []`. The task's
//! job is to construct the right `-x "..."` or `-r <file>` invocation, with
//! `setg RHOST/RHOSTS <target>` injected and user-supplied `KEY=VALUE`
//! environment variables substituted into the resource script (Python
//! `script.format(**env_vars)`).
//!
//! All wiring happens in `before_init`. The runner's positional input would
//! otherwise leak as a stray argument msfconsole doesn't accept, so we clear
//! `runner.inputs` after capturing the target.

use std::collections::BTreeMap;
use std::path::PathBuf;

use secator_model::{Error, Info, OutputItem};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ValidatorRegistry};

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "msfconsole",
    description: "Metasploit framework CLI.",
    cmd: "msfconsole --quiet",
    input_types: &["host", "host_port", "ip"],
    // Python `output_types = []` — msfconsole is exec-only; we surface Info /
    // Error markers from before_init if the operator missed a required opt.
    output_types: &[],
    tags: &["exploit", "attack"],
    json_flag: None,
    // No positional / -input flag — RHOST is set via the -x payload. We still
    // declare a wiring (clearing inputs in before_init), and `Unsupported` on
    // the file mode forces single-chunk runs (Python `input_chunk_size = 1`).
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    item_loaders: &[],
    input_chunk_size: 1,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("6.4.59"),
        cmd: Some("git clone --depth 1 --single-branch -b [install_version] https://github.com/rapid7/metasploit-framework.git $HOME/.local/share/metasploit-framework_[install_version] || true && cd $HOME/.local/share/metasploit-framework_[install_version] && gem install bundler --user-install -n $HOME/.local/bin && bundle config set --local path \"$HOME/.local/share\" && bundle lock --normalize-platforms && bundle install && ln -sf $HOME/.local/share/metasploit-framework_[install_version]/msfconsole $HOME/.local/bin/msfconsole"),
        cmd_pre: &[
            ("apt|apk", &["libpq-dev", "libpcap-dev", "libffi-dev", "g++", "make"]),
            ("pacman", &["ruby-erb", "postgresql-libs", "make"]),
            ("yum|zypper", &["postgresql-devel", "make"]),
        ],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: true,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_build_invocation],
    ..HookRegistry::EMPTY
};

/// Build the msfconsole CLI from the target + execute_command / resource opts.
/// Mirrors Python `on_init`:
/// * `environment` is parsed `KEY=VAL,KEY2=VAL2` → env_vars; RHOST + RHOSTS are
///   added from `inputs[0]`.
/// * `execute_command`: format the user-supplied template with env_vars,
///   prefix `setg RHOST/RHOSTS;`, suffix `exit;`, append `-x "<cmd>"`.
/// * `resource`: read script, strip pre-existing `exit`, append `exit`, format
///   with env_vars, write to `<reports>/.inputs/msfconsole_<pid>.rc`, append
///   `-r <path>`.
/// * Neither: queue an Error in `ctx.extra_results` and bail.
///
/// Always clears `runner.inputs` so the runner doesn't append a stray
/// positional arg.
fn before_init_build_invocation(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    let target = match runner.inputs.first().cloned() {
        Some(t) => t,
        None => {
            ctx.extra_results.push(OutputItem::Error(Error {
                message: "msfconsole requires a target host/ip/host_port input.".into(),
                ..Default::default()
            }));
            return;
        }
    };

    // Parse environment string into a key→value map, then inject RHOST/RHOSTS.
    let mut env_vars: BTreeMap<String, String> = BTreeMap::new();
    if let Some(raw) = runner.opts.get("environment").cloned() {
        for chunk in raw.split(',').map(str::trim).filter(|c| !c.is_empty()) {
            if let Some((k, v)) = chunk.split_once('=') {
                env_vars.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    env_vars.insert("RHOST".into(), target.clone());
    env_vars.insert("RHOSTS".into(), target.clone());

    let exec_cmd = runner.opts.get("execute_command").cloned();
    let resource_path = runner.opts.get("resource").cloned();

    // Always clear inputs — msfconsole doesn't accept a positional target.
    runner.inputs.clear();

    if let Some(template) = exec_cmd {
        let user_part = format_with(&template, &env_vars);
        let full = format!(
            "setg RHOST {target}; setg RHOSTS {target}; {user_part}; exit;"
        );
        append_to_suffix(runner, &format!("-x {}", shell_words::quote(&full)));
        return;
    }

    if let Some(path) = resource_path {
        match prepare_resource_script(&path, &env_vars, runner.reports_folder.as_ref()) {
            Ok(out_path) => {
                ctx.extra_results.push(OutputItem::Info(Info {
                    message: format!("Resource script staged at {out_path}"),
                    ..Default::default()
                }));
                append_to_suffix(runner, &format!("-r {}", shell_words::quote(&out_path)));
            }
            Err(msg) => {
                ctx.extra_results.push(OutputItem::Error(Error {
                    message: msg,
                    ..Default::default()
                }));
            }
        }
        return;
    }

    ctx.extra_results.push(OutputItem::Error(Error {
        message: "msfconsole: at least one of `execute_command` or `resource` must be passed.".into(),
        ..Default::default()
    }));
}

fn append_to_suffix(runner: &mut CommandRunner, fragment: &str) {
    if !runner.cmd_suffix.is_empty() && !runner.cmd_suffix.ends_with(' ') {
        runner.cmd_suffix.push(' ');
    }
    runner.cmd_suffix.push_str(fragment);
}

/// Replace `{KEY}` placeholders with values from `vars`, leaving unknown
/// placeholders intact. Mirrors Python's `template.format(**env_vars)` minus
/// the strict KeyError — we treat missing keys as opaque text so the operator
/// sees the unsubstituted token instead of crashing the run.
fn format_with(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            // Capture `{KEY}`.
            let mut key = String::new();
            let mut closed = false;
            while let Some(&p) = chars.peek() {
                chars.next();
                if p == '}' {
                    closed = true;
                    break;
                }
                key.push(p);
            }
            if closed && vars.contains_key(&key) {
                out.push_str(&vars[&key]);
            } else {
                out.push('{');
                out.push_str(&key);
                if closed {
                    out.push('}');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn prepare_resource_script(
    src_path: &str,
    env_vars: &BTreeMap<String, String>,
    reports: Option<&PathBuf>,
) -> Result<String, String> {
    let original = std::fs::read_to_string(src_path)
        .map_err(|e| format!("Failed to read resource script {src_path}: {e}"))?;
    // Python: `content = f.read().replace('exit', '') + 'exit'` — strip any
    // intermediate `exit` lines, then re-append a single trailing `exit` so the
    // session quits cleanly after running.
    let stripped = original.replace("exit", "") + "exit";
    let formatted = format_with(&stripped, env_vars);

    // Pick destination dir (reports/.inputs preferred, /tmp fallback).
    let mut dest = if let Some(rf) = reports {
        let mut p = rf.clone();
        p.push(".inputs");
        p
    } else {
        std::env::temp_dir()
    };
    std::fs::create_dir_all(&dest).map_err(|e| {
        format!("Failed to create dir {}: {e}", dest.to_string_lossy())
    })?;
    dest.push(format!("msfconsole_{}.rc", std::process::id()));
    std::fs::write(&dest, formatted)
        .map_err(|e| format!("Failed to write resource script {}: {e}", dest.to_string_lossy()))?;
    Ok(dest.to_string_lossy().into_owned())
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // VulnMulti's opt set — every entry is unsupported (msfconsole exposes
    // none of them).
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "resource",
            ty: OptType::Str,
            short: Some("r"),
            is_flag: false,
            default: None,
            help: "Metasploit resource script (.rc)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "execute_command",
            ty: OptType::Str,
            short: Some("x"),
            is_flag: false,
            default: None,
            help: "Metasploit command to run then exit",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "environment",
            ty: OptType::Str,
            short: Some("e"),
            is_flag: false,
            default: None,
            help: "Comma-separated env vars (KEY=VALUE,KEY=VALUE) substituted into resource/cmd",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    for k in ["resource", "execute_command", "environment"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(opts: &[(&str, &str)], inputs: Vec<String>) -> (CommandRunner, HookCtx) {
        let mut runner = CommandRunner::new(&SPEC, inputs);
        for (k, v) in opts {
            runner.opts.insert((*k).into(), (*v).into());
        }
        let mut ctx = HookCtx::default();
        before_init_build_invocation(&mut ctx, &mut runner);
        (runner, ctx)
    }

    #[test]
    fn execute_command_builds_x_payload() {
        let (runner, ctx) = drive(
            &[("execute_command", "run exploit/x/y RHOSTS={RHOSTS}")],
            vec!["10.0.0.5".into()],
        );
        assert!(runner.cmd_suffix.contains("-x "));
        assert!(runner.cmd_suffix.contains("setg RHOST 10.0.0.5"));
        assert!(runner.cmd_suffix.contains("setg RHOSTS 10.0.0.5"));
        assert!(runner.cmd_suffix.contains("RHOSTS=10.0.0.5"));
        assert!(runner.cmd_suffix.contains("exit;"));
        // Inputs cleared.
        assert!(runner.inputs.is_empty());
        // No errors queued.
        assert!(!ctx.extra_results.iter().any(|i| matches!(i, OutputItem::Error(_))));
    }

    #[test]
    fn missing_target_emits_error() {
        let (_, ctx) = drive(&[], Vec::new());
        assert!(ctx.extra_results.iter().any(|i| matches!(i, OutputItem::Error(_))));
    }

    #[test]
    fn missing_both_resource_and_exec_emits_error() {
        let (_, ctx) = drive(&[], vec!["1.2.3.4".into()]);
        let msg = ctx
            .extra_results
            .iter()
            .find_map(|i| match i { OutputItem::Error(e) => Some(&e.message), _ => None })
            .unwrap();
        assert!(msg.contains("execute_command"));
        assert!(msg.contains("resource"));
    }

    #[test]
    fn environment_string_is_parsed_and_substituted() {
        let (runner, _) = drive(
            &[
                ("execute_command", "use {LHOST}:{LPORT}"),
                ("environment", "LHOST=10.0.0.1, LPORT=4444"),
            ],
            vec!["192.168.0.1".into()],
        );
        assert!(runner.cmd_suffix.contains("use 10.0.0.1:4444"));
    }

    #[test]
    fn resource_script_is_staged_in_inputs_dir() {
        let src = {
            let mut p = std::env::temp_dir();
            p.push(format!("msf-src-{}.rc", std::process::id()));
            std::fs::write(
                &p,
                "use exploit/x/y\nset RHOST {RHOST}\nrun\nexit\n",
            )
            .unwrap();
            p
        };
        let reports = {
            let mut p = std::env::temp_dir();
            p.push(format!("msf-reports-{}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            p
        };

        let mut runner = CommandRunner::new(&SPEC, vec!["10.0.0.7".into()]);
        runner.opts.insert("resource".into(), src.to_string_lossy().into_owned());
        runner.reports_folder = Some(reports.clone());
        let mut ctx = HookCtx::default();
        before_init_build_invocation(&mut ctx, &mut runner);

        assert!(runner.cmd_suffix.contains("-r "));
        // Info emitted.
        assert!(ctx.extra_results.iter().any(|i| matches!(i, OutputItem::Info(_))));
        // The path is real — file exists and references RHOST substituted.
        let dest = reports.join(".inputs").join(format!("msfconsole_{}.rc", std::process::id()));
        let body = std::fs::read_to_string(&dest).unwrap();
        assert!(body.contains("set RHOST 10.0.0.7"), "body: {body}");
        assert!(body.trim_end().ends_with("exit"), "body: {body}");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dest);
    }

    #[test]
    fn unknown_placeholders_are_left_in_template() {
        let mut vars = BTreeMap::new();
        vars.insert("RHOST".into(), "x".into());
        let out = format_with("{RHOST} {LHOST}", &vars);
        assert_eq!(out, "x {LHOST}");
    }

    #[test]
    fn schema_drops_internal_opts() {
        let mut r = CommandRunner::new(&SPEC, vec!["1.2.3.4".into()]);
        r.opts.insert("execute_command".into(), "run x".into());
        let cmd = r.build_cmd();
        // The internal opt never becomes a CLI flag — only the suffix appended
        // by before_init does (and that runs at run() time, not build_cmd()).
        assert!(!cmd.contains("--execute-command"), "got: {cmd}");
        assert!(!cmd.contains("--environment"), "got: {cmd}");
    }
}
