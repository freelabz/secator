//! maigret — username OSINT (Python `secator/tasks/maigret.py`).
//!
//! maigret writes one JSON line per checked site to a file (the path is either
//! supplied via `--output-path` or discovered in stdout via the regex
//! `JSON ndjson report for .* saved in (.*)`). After the run, `on_cmd_done`
//! reads each line, filters `http_status == 200`, and emits a `UserAccount`
//! with the queried username + the site URL + extra ids.

use std::fs;

use secator_model::{Error, Info, Map, OutputItem, UserAccount};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "maigret",
    description: "Collect a dossier on a person by username (OSINT).",
    cmd: "maigret",
    input_types: &["slug", "string"],
    output_types: &["user_account"],
    tags: &["user", "recon", "username"],
    json_flag: Some("--json ndjson"),
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
        version: Some("0.5.0"),
        cmd: Some("pipx install git+https://github.com/freelabz/maigret.git@main --force"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_input],
    on_line: &[on_line_capture_path],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

fn before_init_record_input(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(i) = runner.inputs.first() {
        ctx.state.insert("maigret:username".into(), i.clone());
    }
}

/// Pull the output file path out of stdout. maigret prints
/// `JSON ndjson report for <user> saved in <path>` — grab the `<path>` group.
fn on_line_capture_path(ctx: &mut HookCtx, line: &str) -> Option<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"JSON ndjson report for .* saved in (.+)$").unwrap()
    });
    if let Some(caps) = re.captures(line) {
        if let Some(p) = caps.get(1) {
            ctx.state.insert("maigret:output_path".into(), p.as_str().trim().to_string());
        }
    }
    Some(line.to_string())
}

fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("maigret:output_path") {
        Some(p) => p.clone(),
        None => {
            return vec![OutputItem::Error(Error {
                message: "JSON output file not found in command output.".into(),
                ..Default::default()
            })];
        }
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => {
            return vec![OutputItem::Error(Error {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })];
        }
    };
    let username = ctx.state.get("maigret:username").cloned().unwrap_or_default();
    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let item: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Python `validate_item`: only http_status == 200 records.
        let status = item.get("http_status").and_then(|v| v.as_i64()).unwrap_or(0);
        if status != 200 {
            continue;
        }
        let site_name = item.get("sitename").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let url = item
            .get("status")
            .and_then(|s| s.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut extra: Map = item
            .get("status")
            .and_then(|s| s.get("ids"))
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // Python also slices `status.ids` into extra_data — we mirror that.
        out.push(OutputItem::UserAccount(UserAccount {
            username: username.clone(),
            url,
            site_name,
            extra_data: std::mem::take(&mut extra),
            ..Default::default()
        }));
    }
    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // ReconUser = OPTS_RECON; maigret accepts proxy/retries/timeout.
    s.meta_opts = crate::meta_opts::opts_recon();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retries".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    for k in ["delay", "rate_limit", "threads"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![OptSpec {
        name: "site",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: None,
        help: "Sites to check (comma-separated subset of maigret's site list)",
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_line_captures_output_path_from_log() {
        let mut ctx = HookCtx::default();
        on_line_capture_path(
            &mut ctx,
            "JSON ndjson report for alice saved in /tmp/maigret_alice.json",
        );
        assert_eq!(
            ctx.state.get("maigret:output_path").map(String::as_str),
            Some("/tmp/maigret_alice.json"),
        );
    }

    #[test]
    fn on_cmd_done_emits_user_accounts_for_200_lines_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.ndjson");
        let body = r#"{"sitename":"GitHub","http_status":200,"status":{"url":"https://github.com/alice","ids":{"name":"Alice"}}}
{"sitename":"NoMatch","http_status":404,"status":{"url":"","ids":{}}}
{"sitename":"X","http_status":200,"status":{"url":"https://x.com/alice","ids":{}}}"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("maigret:output_path".into(), path.to_string_lossy().into_owned());
        ctx.state.insert("maigret:username".into(), "alice".into());
        let out = on_cmd_done_parse(&mut ctx);
        let accounts: Vec<&UserAccount> = out.iter().filter_map(|i| match i {
            OutputItem::UserAccount(a) => Some(a), _ => None
        }).collect();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().any(|a| a.site_name == "GitHub"));
        assert!(accounts.iter().any(|a| a.site_name == "X"));
        assert!(accounts.iter().all(|a| a.username == "alice"));
    }
}
