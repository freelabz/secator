//! h8mail — email/password OSINT lookup (Python `secator/tasks/h8mail.py`).
//!
//! h8mail writes its results to a JSON file we pass via `--json <path>`.
//! `on_start` injects the path under the run's `.outputs/`; `on_cmd_done`
//! reads the file and emits a `UserAccount` per breach hit (`target.data[0]`
//! is a `["<source>:<site_name>", ...]` list per upstream's format).

use std::fs;

use secator_model::{Error, Info, Map, OutputItem, UserAccount};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "h8mail",
    description: "Email information + password lookup tool (breach data).",
    cmd: "h8mail",
    input_types: &["email"],
    output_types: &["user_account"],
    tags: &["user", "recon", "email"],
    // We pass `--json <path>` ourselves in `on_cmd`; we don't want the default
    // `--json` toggle from the cmd-builder pathway here.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Flag("--targets"), file: FileMode::Flag("-domain") },
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
        version: Some("2.5.6"),
        cmd: Some("pipx install h8mail==[install_version] --force"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_state],
    on_cmd: &[on_cmd_inject_json_path],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

fn before_init_record_state(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(rf) = &runner.reports_folder {
        ctx.state.insert("h8mail:reports".into(), rf.to_string_lossy().into_owned());
    }
    if let Some(lb) = runner.opts.get("local_breach") {
        ctx.state.insert("h8mail:local_breach".into(), lb.clone());
    }
}

fn on_cmd_inject_json_path(ctx: &mut HookCtx, cmd: &mut String) {
    let reports = ctx.state.get("h8mail:reports").cloned().unwrap_or_default();
    let outputs_dir = if reports.is_empty() {
        String::from("/tmp")
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&outputs_dir);
    let path = format!("{outputs_dir}/h8mail.json");
    let quoted = shell_words::quote(&path).into_owned();
    cmd.push_str(&format!(" --json {quoted}"));
    ctx.state.insert("h8mail:output_path".into(), path);
}

fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("h8mail:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            return vec![OutputItem::Error(Error {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })];
        }
    };
    let root: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    let local_breach = ctx
        .state
        .get("h8mail:local_breach")
        .cloned()
        .unwrap_or_default();
    let targets = match root.get("targets").and_then(|v| v.as_array()) {
        Some(t) => t,
        None => return out,
    };
    for target in targets {
        let email = target.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let pwn_num = target.get("pwn_num").and_then(|v| v.as_i64()).unwrap_or(0);
        if pwn_num <= 0 {
            continue;
        }
        let username = email.split_once('@').map(|(u, _)| u.to_string()).unwrap_or_else(|| email.clone());
        let target_data = target
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if let Some(entries) = target_data.first().and_then(|v| v.as_array()) {
            for entry in entries {
                let s = entry.as_str().unwrap_or("");
                let (source, site_name) = s.split_once(':').unwrap_or((s, ""));
                let mut extra: Map = Map::new();
                extra.insert("source".into(), Value::String(source.to_string()));
                out.push(OutputItem::UserAccount(UserAccount {
                    site_name: site_name.to_string(),
                    username: username.clone(),
                    email: email.clone(),
                    extra_data: extra,
                    ..Default::default()
                }));
            }
        } else {
            // No breach detail but pwn_num > 0 — emit a placeholder using local_breach.
            let mut extra: Map = Map::new();
            extra.insert("source".into(), Value::String(local_breach.clone()));
            out.push(OutputItem::UserAccount(UserAccount {
                username: username.clone(),
                email: email.clone(),
                extra_data: extra,
                ..Default::default()
            }));
        }
    }
    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // OSInt category has no HTTP meta opts.
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "config",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Configuration file for API keys",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "local_breach",
            ty: OptType::Str,
            short: Some("lb"),
            is_flag: false,
            default: None,
            help: "Local breach file path",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_h8mail_breach_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        let body = r#"{
            "targets": [
                {"target": "alice@example.com", "pwn_num": 2,
                 "data": [["LinkedIn-2012:linkedin.com", "Adobe-2013:adobe.com"]]},
                {"target": "bob@example.com", "pwn_num": 0, "data": []}
            ]
        }"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("h8mail:output_path".into(), path.to_string_lossy().into_owned());
        let out = on_cmd_done_parse(&mut ctx);
        let accounts: Vec<&UserAccount> = out
            .iter()
            .filter_map(|i| match i { OutputItem::UserAccount(a) => Some(a), _ => None })
            .collect();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().all(|a| a.email == "alice@example.com"));
        assert!(accounts.iter().any(|a| a.site_name == "linkedin.com"));
    }
}
