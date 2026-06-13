//! dirsearch — advanced web path brute-forcer (Python `secator/tasks/dirsearch.py`).
//!
//! dirsearch streams progress to stderr but its findings live in a JSON file:
//! `-O json -o <path>`. Python's `on_init` injects `-o {reports_folder}/.outputs/
//! {fqn}.json` if the user didn't supply one, then `on_cmd_done` reads that file
//! (YAML-loadable because JSON is a YAML subset) and emits one `Url` per
//! `results[i]`.

use std::path::PathBuf;

use secator_model::{Error, Info, Map, OutputItem, Url};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "dirsearch",
    description: "Advanced web path brute-forcer.",
    cmd: "dirsearch",
    // Python `input_types = [URL, HOST, HOST_PORT, IP]`.
    input_types: &["url", "host", "host_port", "ip"],
    output_types: &["url"],
    tags: &["url", "fuzz"],
    // Python `json_flag = '-O json'` — stdout still emits progress text; the real
    // findings come from the `-o <path>` JSON file that `before_init` injects.
    json_flag: Some("-O json"),
    // Python `input_flag = '-u'`, `file_flag = '-l'`.
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-l") },
    // No streaming item loader — findings are parsed from the JSON file in on_cmd_done.
    item_loaders: &[],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        cmd: Some("pipx install git+https://github.com/maurosoria/dirsearch.git --force"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::ALL,
    encoding: "ansi",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_inject_output],
    on_cmd_done: &[on_cmd_done_read_json],
    ..HookRegistry::EMPTY
};

/// Python `on_init`: pick an output path (user-supplied via `output_path`, else
/// `{reports_folder}/.outputs/{fqn}.json`, falling back to a temp file if even
/// that isn't available), and append `-o <path>` to the cmd suffix.
fn before_init_inject_output(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    let user_path = runner.opts.get("output_path").cloned();
    let path = user_path.unwrap_or_else(|| {
        let pid = std::process::id();
        let default_name = format!("secator-dirsearch-{pid}.json");
        if let Some(rf) = &runner.reports_folder {
            let mut p = rf.clone();
            p.push(".outputs");
            // best-effort mkdir — if it fails we still pass the path; dirsearch
            // will surface the error itself.
            let _ = std::fs::create_dir_all(&p);
            p.push(default_name);
            p.to_string_lossy().into_owned()
        } else {
            let mut p = PathBuf::from(std::env::temp_dir());
            p.push(default_name);
            p.to_string_lossy().into_owned()
        }
    });
    if !runner.cmd_suffix.is_empty() && !runner.cmd_suffix.ends_with(' ') {
        runner.cmd_suffix.push(' ');
    }
    runner.cmd_suffix.push_str(&format!("-o {}", shell_words::quote(&path)));
    ctx.state.insert("dirsearch:output_path".into(), path);
    // Stash the raw header opt so on_cmd_done can attach it to each result —
    // Python uses `get_opt_value(HEADER, preprocess=True)` which returns a
    // KEY: VALUE; KEY2: VALUE2 dict; we keep the raw string for now and parse
    // it lazily at emission time.
    if let Some(h) = runner.opts.get("header") {
        ctx.state.insert("dirsearch:header_raw".into(), h.clone());
    }
}

/// Python `on_cmd_done`: open the JSON file, walk `results`, emit `Url` items.
/// Emits a leading `Info` (with the file path) and a `Error` if the path is
/// missing.
fn on_cmd_done_read_json(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("dirsearch:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    if !std::path::Path::new(&path).exists() {
        return vec![OutputItem::Error(Error {
            message: format!("Could not find JSON results in {path}"),
            ..Default::default()
        })];
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return vec![OutputItem::Error(Error {
                message: format!("Failed to read {path}: {e}"),
                ..Default::default()
            })];
        }
    };
    // dirsearch writes JSON (which is a strict subset of YAML). serde_json
    // is enough; we don't need to pull in serde_yaml for this.
    let root: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return vec![OutputItem::Error(Error {
                message: format!("Failed to parse dirsearch JSON {path}: {e}"),
                ..Default::default()
            })];
        }
    };
    let mut out: Vec<OutputItem> = Vec::new();
    out.push(OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    }));
    let results = match root.get("results").and_then(|v| v.as_array()) {
        Some(r) => r,
        None => return out,
    };
    let header_map = ctx
        .state
        .get("dirsearch:header_raw")
        .map(|raw| parse_header_string(raw))
        .unwrap_or_default();
    for r in results {
        if let Some(obj) = r.as_object() {
            out.push(OutputItem::Url(build_url(obj, &header_map)));
        }
    }
    out
}

/// Parse `KEY: VALUE; KEY2: VALUE2` into an obj (Python `headers_to_dict`).
fn parse_header_string(raw: &str) -> Map {
    let mut m: Map = Map::new();
    for chunk in raw.split(';').map(str::trim).filter(|c| !c.is_empty()) {
        if let Some((k, v)) = chunk.split_once(':') {
            m.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        }
    }
    m
}

fn build_url(item: &Map, headers: &Map) -> Url {
    let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let status_code = item.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_length = item.get("content-length").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_type = item.get("content-type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let method = item.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let response_headers = item
        .get("response_headers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    Url {
        url,
        status_code,
        content_length,
        content_type,
        method,
        response_headers,
        request_headers: headers.clone(),
        tags: vec!["fuzz".into()],
        ..Default::default()
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python `opt_key_map` — canonical → dirsearch flag.
    for (canon, flag) in [
        ("header", "header"),
        ("data", "data"),
        ("delay", "delay"),
        ("depth", "max-recursion-depth"),
        ("filter_codes", "exclude-status"),
        ("filter_regex", "exclude-regex"),
        ("filter_size", "exclude-sizes"),
        ("follow_redirect", "follow-redirects"),
        ("match_codes", "include-status"),
        ("method", "http-method"),
        ("proxy", "proxy"),
        ("rate_limit", "max-rate"),
        ("retries", "retries"),
        ("threads", "threads"),
        ("timeout", "timeout"),
        ("user_agent", "user-agent"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    for k in ["filter_words", "match_regex", "match_size", "match_words"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "wordlist",
            ty: OptType::Str,
            short: Some("w"),
            is_flag: false,
            default: None,
            help: "Wordlist(s) to use (path[,path,...])",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        // Canonical `output_path` meta opt — see `meta_opts::OUTPUT_PATH`. We
        // mark it NotSupported below so the option engine doesn't emit a flag;
        // `on_init` injects `-o <path>` directly into cmd_suffix instead.
        meta_opts::OUTPUT_PATH,
    ];
    s.key_map.insert("wordlist".into(), KeyMap::Flag("wordlists".into()));
    s.key_map.insert("output_path".into(), KeyMap::NotSupported);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_results_to_tmp(json: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("dirsearch-test-{}.json", std::process::id()));
        std::fs::write(&p, json).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn header_string_is_parsed_into_request_headers() {
        let h = parse_header_string("X-Test: yes; Authorization: Bearer abc");
        assert_eq!(h.get("X-Test").and_then(|v| v.as_str()), Some("yes"));
        assert_eq!(
            h.get("Authorization").and_then(|v| v.as_str()),
            Some("Bearer abc")
        );
    }

    #[test]
    fn missing_output_file_yields_error_item() {
        let mut ctx = HookCtx::default();
        ctx.state.insert(
            "dirsearch:output_path".into(),
            "/definitely-not-real-1234.json".into(),
        );
        let out = on_cmd_done_read_json(&mut ctx);
        assert!(out.iter().any(|i| matches!(i, OutputItem::Error(_))));
    }

    #[test]
    fn parses_results_into_url_items() {
        let path = write_results_to_tmp(
            r#"{"info":{}, "results":[
                {"url":"https://example.com/admin","status":200,"content-length":1234,"content-type":"text/html"},
                {"url":"https://example.com/api","status":403,"content-length":50,"content-type":"application/json"}
            ]}"#,
        );
        let mut ctx = HookCtx::default();
        ctx.state.insert("dirsearch:output_path".into(), path.clone());
        let out = on_cmd_done_read_json(&mut ctx);
        // 1 Info + 2 Url
        assert!(out.iter().any(|i| matches!(i, OutputItem::Info(_))));
        let urls: Vec<&Url> = out
            .iter()
            .filter_map(|i| match i { OutputItem::Url(u) => Some(u), _ => None })
            .collect();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].url, "https://example.com/admin");
        assert_eq!(urls[0].status_code, 200);
        assert_eq!(urls[0].content_length, 1234);
        assert_eq!(urls[0].tags, vec!["fuzz".to_string()]);
        assert_eq!(urls[1].status_code, 403);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn before_init_appends_output_flag() {
        let mut runner = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        let mut ctx = HookCtx::default();
        before_init_inject_output(&mut ctx, &mut runner);
        assert!(runner.cmd_suffix.contains("-o "));
        assert!(ctx.state.contains_key("dirsearch:output_path"));
    }

    #[test]
    fn user_output_path_overrides_default() {
        let mut runner = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        runner.opts.insert("output_path".into(), "/tmp/custom.json".into());
        let mut ctx = HookCtx::default();
        before_init_inject_output(&mut ctx, &mut runner);
        assert_eq!(
            ctx.state.get("dirsearch:output_path").map(String::as_str),
            Some("/tmp/custom.json")
        );
    }

    #[test]
    fn output_path_does_not_leak_as_cli_flag() {
        let mut runner = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        runner.opts.insert("output_path".into(), "/tmp/custom.json".into());
        let cmd = runner.build_cmd();
        assert!(!cmd.contains("--output-path"), "got: {cmd}");
    }
}
