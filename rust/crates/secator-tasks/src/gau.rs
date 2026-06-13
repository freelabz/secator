//! gau — fetch known URLs from threat-intelligence archives (Wayback, OTX, etc).
//! Python `secator/tasks/gau.py`.
//!
//! Pipeline (mirrors Python):
//!   * `on_line` detects log warnings (`level=warning`) and rewrites them into
//!     a synthetic JSON object so the regular `on_json_loaded` callback can emit
//!     a `Warning` item alongside normal URLs.
//!   * `on_json_loaded` parses the URL, deduplicates by `(base_url, param)` up
//!     to `max_param_occurrences`, and emits either a `Subdomain` (when `subs`
//!     is set) or a `Url` with `tags=['passive']`.

use secator_model::{Map, OutputItem, Subdomain, Url, Warning};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use url::Url as UrlParser;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "gau",
    description:
        "Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl, and URLScan.",
    cmd: "gau --verbose",
    input_types: &["url", "host"],
    output_types: &["url", "subdomain"],
    tags: &["url", "crawl", "passive"],
    json_flag: Some("--json"),
    // Python `file_flag = OPT_PIPE_INPUT`; default single-input is positional.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Pipe },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.2.4"),
        cmd: Some("go install -v github.com/lc/gau/v2/cmd/gau@[install_version]"),
        github_handle: Some("lc/gau"),
        pre: &[("apk", &["libc6-compat"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps { proxychains: false, proxy_http: true, proxy_socks5: false },
    encoding: "ansi",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    on_line: &[on_line_capture_warnings],
    ..HookRegistry::EMPTY
};

/// Mirrors Python `on_line`: rewrite warning log lines into a synthetic JSON
/// payload so the downstream `on_json_loaded` can emit them as `Warning`s.
/// Non-warning lines pass through unchanged.
fn on_line_capture_warnings(_ctx: &mut HookCtx, line: &str) -> Option<String> {
    if !line.contains("level=warning") || line.contains("error reading config") {
        return Some(line.to_string());
    }
    let msg = match line.split_once("msg=") {
        Some((_, after)) => after.trim().trim_matches('"').to_string(),
        None => line.to_string(),
    };
    let msg = if !msg.starts_with("http") {
        // Python `.capitalize()` — uppercase first char, lowercase rest.
        let mut chars = msg.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str().to_lowercase().as_str(),
            None => String::new(),
        }
    } else { msg };
    let synth = serde_json::json!({"message": msg, "_type": "warning"});
    Some(serde_json::to_string(&synth).unwrap_or_default())
}

/// Mirrors Python `on_json_loaded`. Emits `Warning` for synthesized warning
/// records, otherwise emits `Url` (default) or `Subdomain` (when `subs` is set).
/// Deduplicates by `(base_url, param)` up to `max_param_occurrences` to keep
/// the output manageable on noisy archives.
pub fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    if let Some(msg) = item.get("message").and_then(|v| v.as_str()) {
        return vec![OutputItem::Warning(Warning { message: msg.to_string(), ..Default::default() })];
    }
    let raw_url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if raw_url.is_empty() {
        return Vec::new();
    }
    let parsed = match UrlParser::parse(&raw_url) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let hostname = parsed.host_str().unwrap_or("").to_string();
    // Build the param-dedup key: base URL without query/fragment.
    let mut base = parsed.clone();
    base.set_query(None);
    base.set_fragment(None);
    let base_str = base.to_string();
    let max_occurrences: usize = ctx
        .state
        .get("gau:max_param_occurrences")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    for (param, _val) in parsed.query_pairs() {
        let key = format!("gau:seen:{base_str}|{param}");
        let count: usize = ctx.state.get(&key).and_then(|s| s.parse().ok()).unwrap_or(0);
        let next = count + 1;
        ctx.state.insert(key, next.to_string());
        if next > max_occurrences {
            return Vec::new();
        }
    }
    let subs_mode = ctx.state.get("gau:subs").map(|s| s == "1").unwrap_or(false);
    if subs_mode {
        let domain = extract_domain(&hostname);
        if domain.is_empty() {
            return Vec::new();
        }
        let key = format!("gau:seen-sub:{hostname}");
        if ctx.state.contains_key(&key) {
            return Vec::new();
        }
        ctx.state.insert(key, "1".into());
        vec![OutputItem::Subdomain(Subdomain {
            host: hostname,
            domain,
            tags: vec!["passive".into()],
            ..Default::default()
        })]
    } else {
        vec![OutputItem::Url(Url {
            url: raw_url,
            host: hostname,
            tags: vec!["passive".into()],
            ..Default::default()
        })]
    }
}

/// Best-effort second-level domain from a hostname (mirrors Python
/// `extract_domain_info(host, domain_only=True)` for the common cases).
fn extract_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        return host.to_string();
    }
    parts[parts.len() - 2..].join(".")
}

/// Python `opts` + `opt_key_map`. Most HTTP filter / match opts are
/// `OPT_NOT_SUPPORTED` since gau doesn't accept them.
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // HttpCrawler = OPTS_HTTP_CRAWLERS — we surface the HTTP base subset.
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // gau-specific renames + NOT_SUPPORTED entries (Python parity).
    for k in [
        "header", "delay", "follow_redirect", "method", "rate_limit", "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retries".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("threads".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.opts = vec![
        str_opt("providers", None, "Providers (wayback,commoncrawl,otx,urlscan)"),
        flag("subs", None, "Output subdomains as well as URLs"),
        int_opt(
            "max_param_occurrences",
            None,
            "Max times a query parameter can appear on the same base URL (default 10)",
        ),
    ];
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

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{JsonSerializer, Serializer};

    fn run(line: &str, ctx: &mut HookCtx) -> Vec<OutputItem> {
        let kept = on_line_capture_warnings(ctx, line).unwrap_or_default();
        if kept.is_empty() {
            return Vec::new();
        }
        JsonSerializer::new()
            .run(&kept)
            .into_iter()
            .flat_map(|r| on_json_loaded(ctx, r))
            .collect()
    }

    #[test]
    fn parses_url_line_to_url_item() {
        let mut ctx = HookCtx::default();
        let items = run(r#"{"url":"https://example.com/foo?bar=1"}"#, &mut ctx);
        assert_eq!(items.len(), 1);
        if let OutputItem::Url(u) = &items[0] {
            assert_eq!(u.url, "https://example.com/foo?bar=1");
            assert_eq!(u.host, "example.com");
        } else { panic!() }
    }

    #[test]
    fn subs_mode_emits_subdomain_once() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("gau:subs".into(), "1".into());
        let line = r#"{"url":"https://api.example.com/a"}"#;
        assert_eq!(run(line, &mut ctx).len(), 1);
        // Same hostname twice → only one Subdomain.
        assert_eq!(run(line, &mut ctx).len(), 0);
    }

    #[test]
    fn dedupes_param_occurrences_past_threshold() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("gau:max_param_occurrences".into(), "2".into());
        let mut emitted = 0;
        for v in 1..=5 {
            let line = format!(r#"{{"url":"https://example.com/p?q={v}"}}"#);
            emitted += run(&line, &mut ctx).len();
        }
        assert_eq!(emitted, 2, "3rd+ occurrences of `q` get dropped");
    }

    #[test]
    fn warning_log_lines_become_warning_items() {
        let mut ctx = HookCtx::default();
        let line = r#"time=2024 level=warning msg="provider otx down""#;
        let items = run(line, &mut ctx);
        assert_eq!(items.len(), 1);
        match &items[0] {
            OutputItem::Warning(w) => assert!(w.message.contains("Provider")),
            _ => panic!(),
        }
    }
}
