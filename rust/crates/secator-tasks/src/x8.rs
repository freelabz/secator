//! x8 — hidden parameter discovery (Python `secator/tasks/x8.py`).
//!
//! Reads URLs (one per input), discovers query parameters that change the
//! response, emits a `Url(...)` per visited target and one
//! `Tag(category=info, name=url_param, value=<param>, match=<url_without_param>)`
//! per discovered parameter.

use secator_model::{Map, OutputItem, Tag, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "x8",
    description: "Hidden HTTP parameter discovery (Rust).",
    cmd: "x8",
    input_types: &["url"],
    output_types: &["url", "tag"],
    tags: &["url", "fuzz", "params"],
    json_flag: Some("-O json"),
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-u") },
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
        version: Some("v4.3.1"),
        cmd: Some("cargo install --git https://github.com/freelabz/x8 --tag [install_version] x8 --force"),
        github_handle: Some("freelabz/x8"),
        cmd_pre: &[
            ("apk", &["build-base", "pkgconf", "libssl3", "libcrypto3", "openssl-dev"]),
            ("apt", &["build-essential", "pkg-config", "libssl-dev"]),
            ("pacman", &["base-devel", "pkg-config", "openssl"]),
            ("zypper", &["gcc", "pkg-config", "libopenssl-devel"]),
            ("*", &["gcc", "pkg-config", "openssl-devel"]),
        ],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let url_str = match item.get("url").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let parsed = match UrlParser::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let url_without_param = {
        let mut b = parsed.clone();
        b.set_query(None);
        b.to_string()
    };
    let mut out: Vec<OutputItem> = Vec::new();
    // De-dup Url emission per (target) — track in ctx.state.
    let seen_key = format!("x8:seen:{url_str}");
    if !ctx.state.contains_key(&seen_key) {
        ctx.state.insert(seen_key, "1".into());
        out.push(OutputItem::Url(Url {
            url: url_str.clone(),
            host: parsed.host_str().unwrap_or("").to_string(),
            method: item.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status_code: item.get("status").and_then(|v| v.as_i64()).unwrap_or(0),
            content_length: item.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
            ..Default::default()
        }));
    }
    if let Some(params) = item.get("found_params").and_then(|v| v.as_array()) {
        for p in params {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut extra: Map = Map::new();
            if let Some(o) = p.as_object() {
                for (k, v) in o {
                    if k != "name" {
                        extra.insert(k.clone(), v.clone());
                    }
                }
            }
            extra.insert("url".into(), Value::String(url_str.clone()));
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "url_param".into(),
                match_: url_without_param.clone(),
                value: name,
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
    s.key_map.insert("data".into(), KeyMap::Flag("body".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("c".into()));
    s.key_map.insert("delay".into(), KeyMap::Flag("delay".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("x".into()));
    s.key_map.insert("method".into(), KeyMap::Flag("method".into()));
    s.key_map.insert("wordlist".into(), KeyMap::Flag("w".into()));
    s.key_map.insert("follow_redirect".into(), KeyMap::Flag("follow-redirects".into()));
    for k in [
        "user_agent", "depth", "filter_codes", "filter_regex",
        "filter_size", "filter_words", "match_codes", "match_regex",
        "match_size", "match_words", "header", "retries", "rate_limit",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![OptSpec {
        name: "wordlist",
        ty: OptType::Str,
        short: Some("w"),
        is_flag: false,
        default: None,
        help: "Wordlist of parameter names",
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
    use serde_json::json;

    fn map_from(v: Value) -> Map { v.as_object().cloned().unwrap() }

    #[test]
    fn emits_url_and_tag_per_found_param() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({
                "url": "https://example.com/?x=1",
                "method": "GET",
                "status": 200,
                "size": 1234,
                "found_params": [{"name": "debug", "value": "true"}]
            })),
        );
        let has_url = out.iter().any(|i| matches!(i, OutputItem::Url(_)));
        let tag = out.iter().find_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None }).unwrap();
        assert!(has_url);
        assert_eq!(tag.value, "debug");
    }
}
