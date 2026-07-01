//! ffuf — fast web fuzzer (Python `secator/tasks/ffuf.py`).
//!
//! Two parallel item loaders:
//!   * `JsonStrict` for ffuf's per-hit JSONL: `{url, host, status, length, ...}`.
//!     `on_json_loaded` builds a `Url` with `tags=['fuzz']`, and when `subs` is
//!     set, also a `Subdomain`.
//!   * `Regex` for the progress-bar lines (`:: Progress: [N/M] :: ...`). Each
//!     match yields a `Progress { percent, extra_data }`.
//!
//! `before_init` mirrors Python: when the URL has no `FUZZ` keyword and the
//! user didn't supply one via header/data, append `/FUZZ` to the URL.
//! `on_line` catches `[ERR]` lines and emits them as `Warning`s.
//!
//! Deferred: `on_cmd_opts` (Python rewrites the Host header for subdomain
//! fuzzing and swaps the default wordlist) — needs a richer option-processing
//! hook than what we have today.

use secator_model::{Info, Map, OutputItem, Progress, Subdomain, Url, Warning};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{
    empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

const PROGRESS_PATTERN: &str = r":: Progress: \[(?P<count>\d+)/(?P<total>\d+)\] :: Job \[\d/\d\] :: (?P<rps>\d+) req/sec :: Duration: \[(?P<duration>[\d:]+)\] :: Errors: (?P<errors>\d+) ::";

pub static SPEC: TaskSpec = TaskSpec {
    name: "ffuf",
    description: "Fast web fuzzer (Go).",
    cmd: "ffuf -noninteractive",
    input_types: &["url", "string"],
    output_types: &["url", "subdomain", "progress"],
    tags: &["url", "fuzz"],
    json_flag: Some("-json"),
    // Python `input_flag = '-u'`, `file_flag = None`, `input_chunk_size = 1`.
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Unsupported },
    item_loaders: &[
        ItemLoader::JsonStrict,
        ItemLoader::Regex {
            pattern: PROGRESS_PATTERN,
            fields: &["count", "total", "rps", "duration", "errors"],
        },
    ],
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: Some(on_regex_loaded),
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.1.0"),
        cmd: Some("go install -v github.com/ffuf/ffuf/v2@[install_version]"),
        github_handle: Some("ffuf/ffuf"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "ansi",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_add_fuzz],
    on_line: &[on_line_catch_err],
    ..HookRegistry::EMPTY
};

/// Python `before_init`: append `/FUZZ` to the URL when the user didn't put it
/// anywhere (URL, header, data) AND the run isn't a host-header sub-fuzz.
fn before_init_add_fuzz(_ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if runner.inputs.is_empty() {
        return;
    }
    let url = runner.inputs[0].clone();
    let header = runner.opts.get("header").cloned().unwrap_or_default();
    let data = runner.opts.get("data").cloned().unwrap_or_default();
    let recursion = matches!(runner.opts.get("recursion").map(String::as_str), Some("true"));
    let subs = matches!(runner.opts.get("subs").map(String::as_str), Some("true"));
    let fuzz_in_url = url.contains("FUZZ");
    let fuzz_in_header = header.contains("FUZZ");
    let fuzz_in_data = data.contains("FUZZ");
    let needs_fuzz_in_url =
        !fuzz_in_url && (recursion || (!fuzz_in_header && !fuzz_in_data && !subs));
    if needs_fuzz_in_url {
        let stripped = url.trim_end_matches('/');
        runner.inputs[0] = format!("{stripped}/FUZZ");
    }
}

/// Python `on_line` — emit `[ERR] <msg>` as a `Warning` item alongside the
/// passthrough line. We return `Some(line)` so the regex/JSON parsers still
/// see the raw line if needed (Python yields both the Warning and the line).
fn on_line_catch_err(ctx: &mut HookCtx, line: &str) -> Option<String> {
    if let Some(idx) = line.find("[ERR]") {
        let msg = line[idx + 5..].trim().to_string();
        ctx.extra_results.push(OutputItem::Warning(Warning {
            message: msg,
            ..Default::default()
        }));
    }
    Some(line.to_string())
}

/// Per-hit Url + optional Subdomain emission.
pub fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if url.is_empty() {
        return Vec::new();
    }
    let host = item.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let status_code = item.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_length = item.get("length").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_type = item.get("content-type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let duration_ns = item.get("duration").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let time = format!("{:.6}", duration_ns / 1e9);
    let follow_redirect = matches!(
        ctx.state.get("ffuf:follow_redirect").map(String::as_str),
        Some("1")
    );
    let has_redirect_location = item.get("redirectlocation").is_some();
    let has_3xx_status = (300..400).contains(&status_code);
    let is_redirect = (follow_redirect && has_redirect_location) || has_3xx_status;
    let auto_calibration = ctx
        .state
        .get("ffuf:auto_calibration")
        .map(|s| s == "1")
        .unwrap_or(true);

    let mut out: Vec<OutputItem> = Vec::new();
    out.push(OutputItem::Url(Url {
        url: url.clone(),
        host: host.clone(),
        verified: auto_calibration,
        status_code,
        content_length,
        content_type,
        is_redirect,
        time,
        method: ctx.state.get("ffuf:method").cloned().unwrap_or_else(|| "GET".into()),
        confidence: if auto_calibration { "high".into() } else { "medium".into() },
        tags: vec!["fuzz".into()],
        ..Default::default()
    }));

    if ctx.state.get("ffuf:subs").map(|s| s == "1").unwrap_or(false) {
        let has_body = content_length != 0;
        let sources = if ctx.state.get("ffuf:has_fuzz_keyword").map(|s| s == "1").unwrap_or(false)
        {
            vec!["http_url".into()]
        } else {
            vec!["http_host_header".into()]
        };
        let mut extra = Map::new();
        extra.insert("http_body".into(), Value::Bool(has_body));
        extra.insert("http_status_code".into(), Value::Number(status_code.into()));
        extra.insert("http_redirect".into(), Value::Bool(is_redirect));
        out.push(OutputItem::Subdomain(Subdomain {
            host: host.clone(),
            verified: false,
            domain: extract_domain(&host),
            extra_data: extra,
            sources,
            ..Default::default()
        }));
    }
    out
}

/// Map a regex-captured progress record to a `Progress` item with
/// `percent = count/total * 100`. Extras (rps, duration, errors) ride along.
pub fn on_regex_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let count: i64 = record.get("count").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
    let total: i64 = record.get("total").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
    if total <= 0 {
        return Vec::new();
    }
    let percent = (count as f64) * 100.0 / (total as f64);
    let mut extra = Map::new();
    for k in ["count", "total", "rps", "duration", "errors"] {
        if let Some(v) = record.get(k) {
            extra.insert(k.into(), v.clone());
        }
    }
    vec![OutputItem::Progress(Progress { percent, extra_data: extra, ..Default::default() })]
}

fn extract_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        host.to_string()
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema::default();
    // HttpFuzzer base set (we surface HTTP base; wordlist/method/data are added below).
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // ffuf's `-H`, `-d`, `-fc`, etc. mapping.
    for (canon, flag) in [
        ("header", "H"), ("delay", "p"), ("filter_codes", "fc"),
        ("filter_regex", "fr"), ("filter_size", "fs"), ("filter_words", "fw"),
        ("follow_redirect", "r"), ("match_codes", "mc"), ("match_regex", "mr"),
        ("match_size", "ms"), ("match_words", "mw"), ("method", "X"),
        ("proxy", "x"), ("rate_limit", "rate"), ("threads", "t"),
        ("timeout", "timeout"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    s.key_map.insert("retries".into(), KeyMap::NotSupported);
    s.key_map.insert("user_agent".into(), KeyMap::NotSupported);
    s.opts = vec![
        flag_default("auto_calibration", "ac", "Auto-calibration", true),
        flag("recursion", Some("recursion"), "Recursion"),
        flag("stop_on_error", Some("soe"), "Stop on error"),
        flag("subs", None, "Find subdomains via host-header fuzzing"),
        int_opt("depth", None, "Recursion depth"),
        str_opt("data", Some("d"), "Request body data"),
        str_opt("wordlist", Some("w"), "Wordlist"),
        str_opt("replay_proxy", None, "Replay proxy (ffuf `-replay-proxy`)"),
    ];
    s.key_map.insert("auto_calibration".into(), KeyMap::Flag("ac".into()));
    s.key_map.insert("stop_on_error".into(), KeyMap::Flag("sa".into()));
    s.key_map.insert("depth".into(), KeyMap::Flag("recursion-depth".into()));
    s.key_map.insert("wordlist".into(), KeyMap::Flag("w".into()));
    s.key_map.insert("replay_proxy".into(), KeyMap::Flag("replay-proxy".into()));
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn int_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Int, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
fn flag_default(name: &'static str, short: &'static str, help: &'static str, on: bool) -> OptSpec {
    let mut o = flag(name, Some(short), help);
    if on { o.default = Some("true"); }
    o
}

// silence unused Info import (kept for parity comments)
const _: fn() = || { let _ = Info::default(); };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_init_appends_fuzz_when_missing() {
        let mut ctx = HookCtx::default();
        let mut r = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        before_init_add_fuzz(&mut ctx, &mut r);
        assert_eq!(r.inputs[0], "https://example.com/FUZZ");
    }

    #[test]
    fn before_init_keeps_existing_fuzz() {
        let mut ctx = HookCtx::default();
        let mut r = CommandRunner::new(&SPEC, vec!["https://example.com/?p=FUZZ".into()]);
        before_init_add_fuzz(&mut ctx, &mut r);
        assert!(r.inputs[0].contains("p=FUZZ"));
        assert!(!r.inputs[0].ends_with("/FUZZ"));
    }

    #[test]
    fn before_init_skips_fuzz_when_subs_mode() {
        let mut ctx = HookCtx::default();
        let mut r = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        r.opts.insert("subs".into(), "true".into());
        before_init_add_fuzz(&mut ctx, &mut r);
        assert_eq!(r.inputs[0], "https://example.com");
    }

    #[test]
    fn json_hit_emits_url() {
        let mut ctx = HookCtx::default();
        let item: Map = serde_json::from_str(
            r#"{"url":"https://x/api","host":"x","status":200,"length":42,"content-type":"text/html","duration":12345678}"#,
        ).unwrap();
        let items = on_json_loaded(&mut ctx, item);
        assert_eq!(items.len(), 1);
        if let OutputItem::Url(u) = &items[0] {
            assert_eq!(u.url, "https://x/api");
            assert_eq!(u.status_code, 200);
            assert_eq!(u.content_length, 42);
            assert!(u.verified);
            assert_eq!(u.tags, vec!["fuzz".to_string()]);
        } else { panic!() }
    }

    #[test]
    fn progress_line_maps_to_progress_item() {
        use secator_parse::{RegexSerializer, Serializer};
        let mut ctx = HookCtx::default();
        let line = ":: Progress: [50/200] :: Job [1/1] :: 33 req/sec :: Duration: [00:01] :: Errors: 0 ::";
        let records = RegexSerializer::new(
            PROGRESS_PATTERN,
            vec!["count","total","rps","duration","errors"].into_iter().map(String::from).collect(),
        ).unwrap().run(line);
        let items: Vec<OutputItem> = records
            .into_iter()
            .flat_map(|r| on_regex_loaded(&mut ctx, r))
            .collect();
        assert_eq!(items.len(), 1);
        if let OutputItem::Progress(p) = &items[0] {
            assert_eq!(p.percent, 25.0);
        } else { panic!() }
    }

    #[test]
    fn on_line_catches_err_as_warning() {
        let mut ctx = HookCtx::default();
        on_line_catch_err(&mut ctx, "[ERR] something broke");
        let warning = ctx.extra_results.iter().find_map(|i| match i {
            OutputItem::Warning(w) => Some(w), _ => None
        }).expect("ERR line should emit Warning");
        assert!(warning.message.contains("something broke"));
    }
}
