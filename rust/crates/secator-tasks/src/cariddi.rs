//! cariddi — endpoint / secret / info hunter (Python `secator/tasks/cariddi.py`).
//!
//! For every JSON record cariddi emits, we produce:
//!   * 1 `Url(...)` for the record itself (sans `matches` field).
//!   * 1 `Tag(category=info, name=url_param)` per query-string parameter
//!     (Python `parameters[*].attacks[*]`).
//!   * 1 `Tag(category=error, ...)`  per `matches.errors[*]`.
//!   * 1 `Tag(category=secret, ...)` per `matches.secrets[*]`.
//!   * 1 `Tag(category=info, ...)`   per `matches.infos[*]`, with the rename /
//!     ignore lists from Python (e.g. `BTC address` skipped, `IPv4 address`
//!     normalized to `IpV4 address`) plus an HTML-comment-noise filter.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use secator_model::{Map, OutputItem, Tag, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "cariddi",
    description: "Crawl endpoints + hunt for secrets / errors / juicy strings.",
    cmd: "cariddi",
    input_types: &["url", "host", "host_port"],
    output_types: &["url", "tag"],
    tags: &["url", "crawl"],
    json_flag: Some("-json"),
    // cariddi reads inputs from stdin only — no `-l file` flag. We model that
    // as `Stdin` single-mode and `Stdin` file-mode (one input per stdin line).
    input_wiring: InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.4.4"),
        cmd: Some("go install -v github.com/edoardottt/cariddi/cmd/cariddi@[install_version]"),
        github_handle: Some("edoardottt/cariddi"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "ansi",
    ignore_return_code: false,
    requires_sudo: false,
};

const CARIDDI_IGNORE_LIST: &[&str] = &["BTC address"];

fn cariddi_rename(name: &str) -> &str {
    match name {
        "IPv4 address" => "IpV4 address",
        "MySQL error" => "Mysql error",
        "MariaDB error" => "Mariadb error",
        "PostgreSQL error" => "Postgresql error",
        "SQLite error" => "Sqlite error",
        other => other,
    }
}

/// Compiled-once HTML-comment ignore regex (Python `CARIDDI_IGNORE_PATTERNS`).
fn ignore_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Python uses re.match (anchored at start), so all alternatives are
        // joined with `|` and the engine tries them from offset 0. Mirrors
        // `CARIDDI_IGNORE_PATTERNS`.
        let pattern = [
            r"<!--\s*Instance.*\s*-->",
            r"<!--\s*(Styles|Scripts|Fonts|Images|Links|Forms|Inputs|Buttons|List|Next|Prev|Navigation dots)\s*-->",
            r"<!--\s*end.*-->",
            r"<!--\s*start.*-->",
            r"<!--\s*begin.*-->",
            r"<!--\s*here goes.*-->",
            r"<!--\s*.*Yoast SEO.*\s*-->",
            r"<!--\s*.*Google Analytics.*\s*-->",
        ]
        .join("|");
        RegexBuilder::new(&format!("^(?:{pattern})"))
            .case_insensitive(true)
            .build()
            .unwrap()
    })
}

fn snake_name(raw: &str) -> String {
    raw.to_lowercase().split_whitespace().collect::<Vec<_>>().join("_")
}

fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url_str = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if url_str.is_empty() {
        return Vec::new();
    }
    let parsed = match UrlParser::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let url_without_param = {
        let mut b = parsed.clone();
        b.set_query(None);
        b.set_fragment(None);
        b.to_string()
    };

    let mut out: Vec<OutputItem> = Vec::new();

    // Url(...) reconstructs from `item` minus `matches`. We copy known fields
    // and stash the rest as extra_data — that's how the Python `Url(**...)`
    // expansion lines up against secator-model's Url defaults.
    let mut u = Url {
        url: url_str.clone(),
        host: parsed.host_str().unwrap_or("").to_string(),
        ..Default::default()
    };
    if let Some(s) = item.get("status_code").and_then(|v| v.as_i64()) {
        u.status_code = s;
    }
    if let Some(s) = item.get("content_length").and_then(|v| v.as_i64()) {
        u.content_length = s;
    }
    if let Some(s) = item.get("content_type").and_then(|v| v.as_str()) {
        u.content_type = s.to_string();
    }
    if let Some(s) = item.get("title").and_then(|v| v.as_str()) {
        u.title = s.to_string();
    }
    if let Some(s) = item.get("method").and_then(|v| v.as_str()) {
        u.method = s.to_string();
    }
    out.push(OutputItem::Url(u));

    let matches = match item.get("matches").and_then(|v| v.as_object()) {
        Some(m) => m,
        None => return out,
    };

    // Parameters: emit `Tag(category=info, name=url_param, value=<param_name>,
    // match=<url_without_param>)` per attack iteration. Mirrors Python's
    // (somewhat unusual) double loop.
    if let Some(params) = matches.get("parameters").and_then(|v| v.as_array()) {
        for p in params {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let attacks = p
                .get("attacks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if attacks.is_empty() {
                continue;
            }
            if let Some(query) = parsed.query() {
                for q in query.split('&') {
                    let (pn, pv) = q.split_once('=').unwrap_or((q, ""));
                    if pn == name {
                        // Python skips a matching param via `break` — we keep
                        // moving but don't emit for the matched param (parity).
                        continue;
                    }
                    let mut extra: Map = Map::new();
                    extra.insert("value".into(), Value::String(pv.into()));
                    extra.insert("url".into(), Value::String(url_str.clone()));
                    out.push(OutputItem::Tag(Tag {
                        category: "info".into(),
                        name: "url_param".into(),
                        value: pn.into(),
                        match_: url_without_param.clone(),
                        extra_data: extra,
                        ..Default::default()
                    }));
                }
            }
        }
    }

    // errors / secrets: thin wrappers — each has {name, match}; we relabel
    // them into Tag(category=error|secret, name=<snake>, value=<match>,
    // match=<url_without_param>, extra_data.url=<original url>).
    for (key, category) in [("errors", "error"), ("secrets", "secret")] {
        if let Some(arr) = matches.get(key).and_then(|v| v.as_array()) {
            for e in arr {
                let name = e.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let m = e.get("match").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mut extra: Map = Map::new();
                extra.insert("url".into(), Value::String(url_str.clone()));
                out.push(OutputItem::Tag(Tag {
                    category: category.into(),
                    name: snake_name(&name),
                    value: m,
                    match_: url_without_param.clone(),
                    extra_data: extra,
                    ..Default::default()
                }));
            }
        }
    }

    // infos: same shape but with rename / ignore / regex-noise filters.
    if let Some(arr) = matches.get("infos").and_then(|v| v.as_array()) {
        for e in arr {
            let raw_name = e.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if CARIDDI_IGNORE_LIST.contains(&raw_name) {
                continue;
            }
            let renamed = cariddi_rename(raw_name);
            let content = e.get("match").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if ignore_re().is_match(&content) {
                continue;
            }
            let mut extra: Map = Map::new();
            extra.insert("url".into(), Value::String(url_str.clone()));
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: snake_name(renamed),
                value: content,
                match_: url_without_param.clone(),
                extra_data: extra,
                ..Default::default()
            }));
        }
    }

    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python `opt_key_map`.
    s.key_map.insert("header".into(), KeyMap::Flag("headers".into()));
    s.key_map.insert("delay".into(), KeyMap::Flag("d".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("c".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("t".into()));
    s.key_map.insert("user_agent".into(), KeyMap::Flag("ua".into()));
    for k in [
        "depth", "filter_codes", "filter_regex", "filter_size",
        "filter_words", "match_codes", "match_regex", "match_size",
        "match_words", "follow_redirect", "rate_limit", "retries", "method",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "info",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Hunt for useful information in websites",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "secrets",
            ty: OptType::Bool,
            short: Some("s"),
            is_flag: true,
            default: None,
            help: "Hunt for secrets",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "errors",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Hunt for errors in websites",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "juicy_extensions",
            ty: OptType::Int,
            short: None,
            is_flag: false,
            default: None,
            help: "Hunt for juicy file extensions (1=juicy … 7=not juicy)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "juicy_endpoints",
            ty: OptType::Bool,
            short: Some("e"),
            is_flag: true,
            default: None,
            help: "Hunt for juicy endpoints",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    // Python: errors/juicy_extensions/juicy_endpoints have explicit short flags.
    s.key_map.insert("errors".into(), KeyMap::Flag("err".into()));
    s.key_map.insert("juicy_endpoints".into(), KeyMap::Flag("e".into()));
    s.key_map.insert("juicy_extensions".into(), KeyMap::Flag("ext".into()));
    s.key_map.insert("secrets".into(), KeyMap::Flag("s".into()));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map_from(v: Value) -> Map {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn emits_url_plus_tags_for_secrets_and_infos() {
        let item = json!({
            "url": "https://example.com/page?x=1",
            "status_code": 200,
            "matches": {
                "secrets": [{"name": "AWS Access Key", "match": "AKIAXXX"}],
                "infos": [
                    {"name": "BTC address", "match": "bc1q..."},      // ignored
                    {"name": "IPv4 address", "match": "10.0.0.1"},    // renamed
                    {"name": "Email", "match": "<!-- Styles -->"}     // filtered as HTML noise
                ]
            }
        });
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(&mut ctx, map_from(item));
        // Url + 1 secret Tag + 1 info Tag (IpV4 address). Email is filtered.
        let tag_names: Vec<&str> = out
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) => Some(t.name.as_str()), _ => None })
            .collect();
        assert!(tag_names.contains(&"aws_access_key"));
        assert!(tag_names.contains(&"ipv4_address"));
        assert!(!tag_names.contains(&"btc_address"));
        assert!(!tag_names.contains(&"email"));
    }
}
