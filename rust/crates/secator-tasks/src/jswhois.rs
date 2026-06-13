//! jswhois — WHOIS lookup in JSON list format (Python `secator/tasks/jswhois.py`).
//!
//! Output is a JSON list (`[{...}, {...}]`). Each entry has a `chain` array; the
//! last chain entry's record (key `chain[-1]`) holds a `raw` text blob and is
//! the canonical WHOIS body for the queried host. We emit one
//! `Tag(category=info, name=whois, value=<raw>, match=<host>,
//! extra_data.chain=<last_chain>)` per item.

use secator_model::{Map, OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, SingleMode};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "jswhois",
    description: "WHOIS in JSON format.",
    cmd: "jswhois",
    input_types: &["host"],
    output_types: &["tag"],
    tags: &["domain", "info"],
    json_flag: None,
    // Python `input_flag = None` + `file_flag = None` ⇒ host is positional only.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    // `JSONSerializer(list=True)` ⇒ JsonList — one record per array entry per line.
    item_loaders: &[ItemLoader::JsonList],
    // Python `input_chunk_size = 1`.
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.0.0"),
        cmd: Some("go install -v github.com/freelabz/jswhois@[install_version]"),
        github_handle: Some("freelabz/jswhois"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_capture_input],
    ..HookRegistry::EMPTY
};

fn before_init_capture_input(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if let Some(first) = runner.inputs.first() {
        ctx.state.insert("jswhois:target".into(), first.clone());
    }
}

/// Python `on_json_loaded`: pop the `raw` blob from the last chain step and
/// emit a `Tag`. The chain may be missing or empty in degenerate output; we
/// skip the item rather than crash.
pub fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let chain = match item.get("chain").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a,
        _ => return Vec::new(),
    };
    let last_chain = match chain.last().and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let last_elem = match item.get(&last_chain).and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let raw = last_elem.get("raw").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let target = ctx.state.get("jswhois:target").cloned().unwrap_or_default();
    let mut extra: Map = Map::new();
    extra.insert("chain".into(), Value::String(last_chain));
    vec![OutputItem::Tag(Tag {
        category: "info".into(),
        name: "whois".into(),
        match_: target,
        value: raw,
        extra_data: extra,
        ..Default::default()
    })]
}

/// Python `opts = {}` — no user-facing flags. Drop the canonical meta-opts so
/// they don't leak onto the jswhois cmd line.
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chain_record() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("jswhois:target".into(), "example.com".into());
        // Build via serde_json to avoid escape traps.
        let item = serde_json::json!({
            "chain": ["whois.iana.org", "whois.verisign-grs.com"],
            "whois.iana.org": {"raw": "ignored"},
            "whois.verisign-grs.com": {"raw": "Domain Name: EXAMPLE.COM\nRegistry: ..."}
        });
        let map = item.as_object().unwrap().clone();
        let out = on_json_loaded(&mut ctx, map);
        assert_eq!(out.len(), 1);
        if let OutputItem::Tag(t) = &out[0] {
            assert_eq!(t.name, "whois");
            assert_eq!(t.category, "info");
            assert_eq!(t.match_, "example.com");
            assert!(t.value.starts_with("Domain Name: EXAMPLE.COM"));
            assert_eq!(
                t.extra_data.get("chain").and_then(|v| v.as_str()),
                Some("whois.verisign-grs.com")
            );
        } else { panic!() }
    }

    #[test]
    fn missing_chain_yields_nothing() {
        let mut ctx = HookCtx::default();
        let item = serde_json::json!({"foo": "bar"});
        let out = on_json_loaded(&mut ctx, item.as_object().unwrap().clone());
        assert!(out.is_empty());
    }
}
