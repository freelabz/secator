//! bup — 40X bypasser (Python `secator/tasks/bup.py`).
//!
//! For each URL bup writes JSONL records of attempted requests. Each record
//! becomes a `Url(tags=["bypass"], ...)`. We translate the Python `output_map`
//! field-by-field:
//!   * `url` ← `request_url`
//!   * `method` ← extracted from `request_curl_payload` ("-X <METHOD>")
//!   * `request_headers` ← parsed from `request_curl_payload` / `request_curl_cmd`
//!   * `response_headers` ← parsed from the `\n`-delimited `response_headers`
//!   * `status_code` ← `response_status_code`
//!   * `content_type` ← `response_content_type` (trimmed)
//!   * `content_length` ← `response_content_length`
//!   * `title` ← `response_title`
//!   * `server` ← `response_server_type` (trimmed)
//!   * `lines/words` ← `response_lines_count` / `response_words_count`
//!   * `stored_response_path` ← `response_html_filename`

use std::sync::OnceLock;

use regex::Regex;
use secator_model::{Map, OutputItem, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "bup",
    description: "40X bypasser — tries paths/methods/headers to circumvent restrictions.",
    cmd: "bup -d",
    input_types: &["url"],
    output_types: &["url"],
    tags: &["url", "bypass"],
    json_flag: Some("--jsonl"),
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-u") },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("0.4.4"),
        cmd: Some("pipx install bypass-url-parser==[install_version] --force"),
        pre: &[("*", &["curl"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_set_response_dir],
    ..HookRegistry::EMPTY
};

/// Python `on_init`: append `-o <reports>/.outputs/response` so bup writes
/// the captured response bodies there.
fn before_init_set_response_dir(
    _ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    let response_path = match &runner.reports_folder {
        Some(rf) => format!("{}/.outputs/response", rf.display()),
        None => "/tmp/response".into(),
    };
    let quoted = shell_words::quote(&response_path).into_owned();
    if !runner.cmd_suffix.contains("-o ") {
        runner.cmd_suffix.push_str(&format!(" -o {quoted}"));
    }
}

fn re_method() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-X\s+(\w+)").unwrap())
}
fn re_hdr_payload() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-H\s*'?([^']*)'?").unwrap())
}

fn parse_method(payload: &str) -> String {
    re_method()
        .captures(payload)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .unwrap_or_else(|| "GET".into())
}

fn parse_request_headers(payload: &str, cmd: &str) -> Map {
    let mut out: Map = Map::new();
    for hay in [payload, cmd] {
        for m in re_hdr_payload().captures_iter(hay) {
            if let Some(g) = m.get(1) {
                let s = g.as_str();
                if let Some((k, v)) = s.split_once(':') {
                    out.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
                }
            }
        }
    }
    out
}

fn parse_response_headers(raw: &str) -> Map {
    let mut out: Map = Map::new();
    // Python: split on '\n', drop the first line (status line).
    for line in raw.split('\n').skip(1) {
        if let Some((k, rest)) = line.split_once(':') {
            out.insert(k.to_string(), Value::String(rest.trim().to_string()));
        }
    }
    out
}

fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let request_url = item.get("request_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if request_url.is_empty() {
        return Vec::new();
    }
    let payload = item.get("request_curl_payload").and_then(|v| v.as_str()).unwrap_or("");
    let cmd = item.get("request_curl_cmd").and_then(|v| v.as_str()).unwrap_or("");
    let method = parse_method(payload);
    let request_headers = parse_request_headers(payload, cmd);
    let response_headers_str = item
        .get("response_headers")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let response_headers = parse_response_headers(response_headers_str);
    let url = Url {
        url: request_url,
        method,
        request_headers,
        response_headers,
        status_code: item
            .get("response_status_code")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        content_type: item
            .get("response_content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        content_length: item
            .get("response_content_length")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        title: item
            .get("response_title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        webserver: item
            .get("response_server_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        lines: item.get("response_lines_count").and_then(|v| v.as_i64()).unwrap_or(0),
        words: item.get("response_words_count").and_then(|v| v.as_i64()).unwrap_or(0),
        stored_response_path: item
            .get("response_html_filename")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tags: vec!["bypass".into()],
        ..Default::default()
    };
    vec![OutputItem::Url(url)]
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    s.key_map.insert("header".into(), KeyMap::Flag("header".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retry".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("threads".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    for k in [
        "data", "delay", "follow_redirect", "method", "rate_limit",
        "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "spoofport",
            ty: OptType::Int,
            short: Some("sp"),
            is_flag: false,
            default: None,
            help: "Port(s) to inject in port-specific headers",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "spoofip",
            ty: OptType::Str,
            short: Some("si"),
            is_flag: false,
            default: None,
            help: "IP(s) to inject in ip-specific headers",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "mode",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Bypass modes (comma-delimited)",
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
    use serde_json::json;

    fn map_from(v: Value) -> Map { v.as_object().cloned().unwrap() }

    #[test]
    fn maps_bup_jsonl_record_to_url() {
        let item = json!({
            "request_url": "https://example.com/admin",
            "request_curl_payload": "-X POST -H 'X-Forwarded-For: 127.0.0.1' /admin",
            "request_curl_cmd": "curl -i -X POST -H 'Content-Type: application/json' https://example.com/admin",
            "response_status_code": 401,
            "response_content_type": "text/html ",
            "response_content_length": 4567,
            "response_title": "401 Unauthorized",
            "response_server_type": "nginx ",
            "response_lines_count": 12,
            "response_words_count": 88,
            "response_html_filename": "/tmp/response/foo.html",
            "response_headers": "HTTP/1.1 401 Unauthorized\nServer: nginx\nContent-Type: text/html"
        });
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(&mut ctx, map_from(item));
        let u = match out.first().unwrap() {
            OutputItem::Url(u) => u,
            _ => panic!("expected Url"),
        };
        assert_eq!(u.method, "POST");
        assert_eq!(u.status_code, 401);
        assert_eq!(u.webserver, "nginx");
        assert_eq!(u.content_type, "text/html");
        assert!(u.request_headers.get("X-Forwarded-For").is_some()
                || u.request_headers.get("Content-Type").is_some());
        assert!(u.response_headers.get("Server").is_some());
        assert!(u.tags.contains(&"bypass".to_string()));
    }
}
