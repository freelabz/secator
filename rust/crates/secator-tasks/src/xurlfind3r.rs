//! xurlfind3r — passive URL discovery (Python `secator/tasks/xurlfind3r.py`).
//!
//! Inputs that look like URLs are reduced to their netloc in `before_init` so
//! xurlfind3r gets a hostname. `on_json_loaded` emits a `Url(tags=["passive"],
//! extra_data.source=<item.source>)` per record, with a per-(base_url, param)
//! cap (Python `max_param_occurrences`, default 10) to avoid spamming results
//! when many query-string variants of the same endpoint show up.

use std::collections::BTreeMap;

use secator_model::{Map, OutputItem, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "xurlfind3r",
    description: "Discover URLs passively via public archives.",
    cmd: "xurlfind3r",
    input_types: &["host", "url"],
    output_types: &["url"],
    tags: &["url", "crawl", "passive"],
    json_flag: Some("--jsonl"),
    input_wiring: InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Flag("-l") },
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
        version: Some("1.3.0"),
        cmd: Some("go install -v github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@[install_version]"),
        github_handle: Some("hueristiq/xurlfind3r"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps { proxychains: false, proxy_http: true, proxy_socks5: false },
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_normalize_inputs],
    ..HookRegistry::EMPTY
};

/// Python `before_init`: if any input looks like a URL, reduce it to its
/// netloc. Also stash the `max_param_occurrences` cap on `ctx.state` so
/// `on_json_loaded` can read it without poking back at runner state.
fn before_init_normalize_inputs(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    for i in runner.inputs.iter_mut() {
        if let Ok(u) = UrlParser::parse(i) {
            if let Some(host) = u.host_str() {
                *i = host.to_string();
            }
        }
    }
    let cap = runner
        .opts
        .get("max_param_occurrences")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    ctx.state.insert("xurlfind3r:cap".into(), cap.to_string());
}

fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url_str = match item.get("url").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let cap: u32 = ctx
        .state
        .get("xurlfind3r:cap")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    // Per-(base_url, param) counter — store the running totals in ctx.state
    // as `xurlfind3r:p:<base>:<param>` (cheap; same scope as Python `seen_params`).
    let parsed = match UrlParser::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let base_url = {
        let mut b = parsed.clone();
        b.set_query(None);
        b.set_fragment(None);
        b.to_string()
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let mut params: Vec<String> = Vec::new();
    for (k, _) in parsed.query_pairs() {
        params.push(k.into_owned());
    }
    for p in &params {
        let key = format!("xurlfind3r:p:{base_url}:{p}");
        let count: u32 = ctx
            .state
            .get(&key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            + 1;
        ctx.state.insert(key, count.to_string());
        if count > cap {
            return Vec::new();
        }
    }
    let source = item
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut extra: BTreeMap<String, Value> = BTreeMap::new();
    extra.insert("source".into(), Value::String(source));
    let extra: Map = extra.into_iter().collect();
    vec![OutputItem::Url(Url {
        url: url_str,
        host,
        extra_data: extra,
        tags: vec!["passive".into()],
        ..Default::default()
    })]
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    for k in [
        "header", "delay", "depth", "filter_codes", "filter_regex",
        "filter_size", "filter_words", "match_codes", "match_regex",
        "match_size", "match_words", "follow_redirect", "proxy",
        "rate_limit", "retries", "threads", "timeout", "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "sources",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Comma-delimited list of sources to use",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "sources_to_exclude",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Comma-delimited list of sources to exclude",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "include_subdomains",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Include subdomains",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "max_param_occurrences",
            ty: OptType::Int,
            short: None,
            is_flag: false,
            default: Some("10"),
            help: "Cap per (base_url, param) before dropping further dups",
            internal: true,
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

    fn map_from(v: Value) -> Map {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn emits_url_with_passive_tag() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("xurlfind3r:cap".into(), "10".into());
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({"url": "https://example.com/a?x=1", "source": "wayback"})),
        );
        if let Some(OutputItem::Url(u)) = out.first() {
            assert_eq!(u.host, "example.com");
            assert!(u.tags.iter().any(|t| t == "passive"));
            assert_eq!(u.extra_data.get("source").and_then(|v| v.as_str()), Some("wayback"));
        } else {
            panic!("expected Url");
        }
    }

    #[test]
    fn caps_per_base_url_param() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("xurlfind3r:cap".into(), "2".into());
        for _ in 0..3 {
            on_json_loaded(
                &mut ctx,
                map_from(json!({"url": "https://example.com/?id=1", "source": "x"})),
            );
        }
        // 3rd call should return empty.
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({"url": "https://example.com/?id=2", "source": "x"})),
        );
        assert!(out.is_empty());
    }
}
