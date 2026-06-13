//! urlfinder — passive URL discovery (Python `secator/tasks/urlfinder.py`).
//!
//! Same shape as `xurlfind3r`: URL inputs are reduced to netloc in
//! `before_init`, and `on_json_loaded` emits `Url(tags=["passive"])` with a
//! per-(base_url, param) cap (Python `max_param_occurrences`, default 10) to
//! prevent flooding when many query-string variants exist.

use std::collections::BTreeMap;

use secator_model::{Map, OutputItem, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "urlfinder",
    description: "Find URLs in passive sources (alienvault, urlscan, wayback, …).",
    cmd: "urlfinder",
    input_types: &["host", "url"],
    output_types: &["url"],
    tags: &["url", "crawl", "passive"],
    json_flag: Some("-j"),
    input_wiring: InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Flag("-list") },
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
        version: Some("v0.0.3"),
        cmd: Some("go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@[install_version]"),
        github_handle: Some("projectdiscovery/urlfinder"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps { proxychains: false, proxy_http: true, proxy_socks5: false },
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_normalize_inputs],
    ..HookRegistry::EMPTY
};

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
    ctx.state.insert("urlfinder:cap".into(), cap.to_string());
}

fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url_str = match item.get("url").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let cap: u32 = ctx
        .state
        .get("urlfinder:cap")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
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
    for (k, _) in parsed.query_pairs() {
        let key = format!("urlfinder:p:{base_url}:{}", k.as_ref());
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
    let mut extra: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(s) = item.get("source").and_then(|v| v.as_str()) {
        extra.insert("source".into(), Value::String(s.to_string()));
    }
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
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_http_base();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python `opt_key_map` shortens common flags.
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("rl".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("sources".into(), KeyMap::Flag("s".into()));
    s.key_map.insert("exclude_sources".into(), KeyMap::Flag("es".into()));
    for k in [
        "header", "delay", "depth", "filter_codes", "filter_regex",
        "filter_size", "filter_words", "match_codes", "match_regex",
        "match_size", "match_words", "follow_redirect", "method",
        "retries", "threads", "user_agent",
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
            help: "Comma-delimited sources (alienvault, commoncrawl, urlscan, wayback, virustotal)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "exclude_sources",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Comma-delimited sources to exclude",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "stats",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Display source statistics",
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
        ctx.state.insert("urlfinder:cap".into(), "10".into());
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({"url": "https://example.com/a", "source": "wayback"})),
        );
        if let Some(OutputItem::Url(u)) = out.first() {
            assert_eq!(u.host, "example.com");
            assert!(u.tags.iter().any(|t| t == "passive"));
        } else {
            panic!("expected Url");
        }
    }
}
