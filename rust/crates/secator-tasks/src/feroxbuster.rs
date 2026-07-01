//! feroxbuster — recursive content discovery in Rust
//! (Python `secator/tasks/feroxbuster.py`).
//!
//! feroxbuster emits jsonl: `{type, status, url, method, headers, ...}`. Only
//! the `type == "response"` records become URLs; everything else (banners,
//! scans, statistics) is filtered out via `validate_item`. `on_cmd` toggles
//! `--insecure` when a non-https proxy is supplied and drops `--auto-tune` if
//! it conflicts with an explicit `--rate-limit` — both Python parity.

use secator_model::{Map, OutputItem, Url};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "feroxbuster",
    description: "Recursive content-discovery / directory brute-forcer (Rust).",
    cmd: "feroxbuster --no-state --silent --json",
    input_types: &["url", "host", "host_port", "ip"],
    output_types: &["url"],
    tags: &["url", "fuzz"],
    json_flag: None,
    // Python `input_flag = '--url'`, `file_flag = OPT_PIPE_INPUT`.
    input_wiring: InputWiring { single: SingleMode::Flag("--url"), file: FileMode::Pipe },
    item_loaders: &[ItemLoader::Json],
    // Python `input_chunk_size = 1`.
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: VALIDATORS,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.11.0"),
        cmd: Some("cd /tmp && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash -s $HOME/.local/bin"),
        github_handle: Some("epi052/feroxbuster"),
        cmd_pre: &[("*", &["curl", "bash"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    on_cmd: &[on_cmd_proxy_and_autotune],
    ..HookRegistry::EMPTY
};

static VALIDATORS: ValidatorRegistry = ValidatorRegistry {
    validate_input: &[],
    validate_item: &[validate_response_only],
};

/// Python `on_cmd`. Two adjustments:
///   * Toggle `--insecure` when either `--proxy` or `--replay-proxy` is HTTP
///     (non-HTTPS) — otherwise feroxbuster refuses to use them.
///   * Drop `--auto-tune` when `--rate-limit` is set (Python: "auto-tune
///     conflicts with rate-limit").
fn on_cmd_proxy_and_autotune(_ctx: &mut HookCtx, cmd: &mut String) {
    // Walk tokens to find proxy values.
    let mut tokens = cmd.split_whitespace().peekable();
    let mut needs_insecure = false;
    while let Some(t) = tokens.next() {
        if t == "--proxy" || t == "--replay-proxy" {
            if let Some(val) = tokens.peek() {
                if val.starts_with("http://") {
                    needs_insecure = true;
                }
            }
        }
    }
    if needs_insecure && !cmd.contains(" --insecure") {
        cmd.push_str(" --insecure");
    }
    // rate-limit vs auto-tune conflict resolution.
    let has_rate_limit = cmd.split_whitespace().any(|t| t == "--rate-limit");
    if has_rate_limit && cmd.contains("--auto-tune") {
        *cmd = cmd.replace(" --auto-tune", "").replace("--auto-tune ", "");
    }
}

/// Python `validate_item`: keep only `{type: "response", ...}` records. Anything
/// else (statistics, banners, scan-start markers) is dropped.
fn validate_response_only(item: &Map) -> bool {
    item.get("type").and_then(|v| v.as_str()) == Some("response")
}

/// Per-record translation: feroxbuster's `response` record → `Url`.
pub fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if url.is_empty() {
        return Vec::new();
    }
    let method = item.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let status_code = item.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    let time = item
        .get("timestamp")
        .and_then(|v| v.as_str().map(String::from).or_else(|| v.as_f64().map(|x| x.to_string())))
        .unwrap_or_default();
    let line_count = item.get("line_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let word_count = item.get("word_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let response_headers = item
        .get("headers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let content_type = response_headers
        .get("content-type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    vec![OutputItem::Url(Url {
        url,
        method,
        status_code,
        time,
        content_type,
        lines: line_count,
        words: word_count,
        response_headers,
        confidence: "low".into(),
        tags: vec!["fuzz".into()],
        ..Default::default()
    })]
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for (canon, flag) in [
        ("header", "headers"), ("data", "data"), ("depth", "depth"),
        ("filter_codes", "filter-status"), ("filter_regex", "filter-regex"),
        ("filter_size", "filter-size"), ("filter_words", "filter-words"),
        ("follow_redirect", "redirects"), ("match_codes", "status-codes"),
        ("method", "methods"), ("proxy", "proxy"), ("rate_limit", "rate-limit"),
        ("threads", "threads"), ("timeout", "timeout"), ("user_agent", "user-agent"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    for k in ["delay", "retries", "match_regex", "match_size", "match_words"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        flag("auto_bail", "Bail out when too many errors occur"),
        flag_default("auto_tune", "Automatically lower scan rate when errors spike", true),
        flag("extract_links", "Extract links from response body"),
        flag("collect_backups", "Request likely backup extensions"),
        flag("collect_extensions", "Discover extensions and add to --extensions"),
        flag("collect_words", "Discover words and add to wordlist"),
        str_opt("wordlist", None, "Wordlist path"),
        str_opt("replay_proxy", None, "Replay proxy"),
    ];
    s.key_map.insert("wordlist".into(), KeyMap::Flag("wordlist".into()));
    s.key_map.insert("replay_proxy".into(), KeyMap::Flag("replay-proxy".into()));
    s.key_map.insert("auto_tune".into(), KeyMap::Flag("auto-tune".into()));
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn flag(name: &'static str, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short: None, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
fn flag_default(name: &'static str, help: &'static str, on: bool) -> OptSpec {
    let mut o = flag(name, help);
    if on { o.default = Some("true"); }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn validate_item_keeps_response_records_only() {
        let mut response = Map::new();
        response.insert("type".into(), Value::String("response".into()));
        assert!(validate_response_only(&response));
        let mut banner = Map::new();
        banner.insert("type".into(), Value::String("banner".into()));
        assert!(!validate_response_only(&banner));
    }

    #[test]
    fn json_response_becomes_url() {
        let mut ctx = HookCtx::default();
        let line = r#"{
            "type":"response","status":200,"url":"https://x/api",
            "method":"GET","timestamp":"2024-01-01T00:00:00Z",
            "line_count":12,"word_count":34,
            "headers":{"content-type":"application/json"}
        }"#;
        let item: Map = serde_json::from_str(line).unwrap();
        let out = on_json_loaded(&mut ctx, item);
        assert_eq!(out.len(), 1);
        if let OutputItem::Url(u) = &out[0] {
            assert_eq!(u.url, "https://x/api");
            assert_eq!(u.status_code, 200);
            assert_eq!(u.lines, 12);
            assert_eq!(u.words, 34);
            assert_eq!(u.content_type, "application/json");
            assert_eq!(u.tags, vec!["fuzz".to_string()]);
            assert_eq!(u.confidence, "low");
        } else { panic!() }
    }

    #[test]
    fn on_cmd_adds_insecure_for_http_proxy() {
        let mut ctx = HookCtx::default();
        let mut cmd = "feroxbuster --proxy http://127.0.0.1:8080 --url https://x".to_string();
        on_cmd_proxy_and_autotune(&mut ctx, &mut cmd);
        assert!(cmd.contains("--insecure"));
    }

    #[test]
    fn on_cmd_drops_autotune_when_rate_limit_set() {
        let mut ctx = HookCtx::default();
        let mut cmd = "feroxbuster --rate-limit 10 --auto-tune --url https://x".to_string();
        on_cmd_proxy_and_autotune(&mut ctx, &mut cmd);
        assert!(!cmd.contains("--auto-tune"));
    }
}
