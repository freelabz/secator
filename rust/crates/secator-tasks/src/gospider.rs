//! gospider — fast web spider in Go (Python `secator/tasks/gospider.py`).
//!
//! gospider emits one JSON dict per URL hit. The `output_map` renames the URL's
//! `url`/`status_code`/`content_length` fields to gospider's actual keys
//! (`output`/`status`/`length`). `validate_item` drops cross-host hits so the
//! crawl stays scoped to the target.

use secator_model::{Map, OutputItem, OutputMap};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, SingleMode, ValueMap,
};
use secator_parse::{convert_item, OutputMaps};
use secator_runner::{
    HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "gospider",
    description: "Fast web spider written in Go.",
    cmd: "gospider",
    input_types: &["url"],
    output_types: &["url"],
    tags: &["url", "crawl"],
    json_flag: Some("--json"),
    input_wiring: InputWiring { single: SingleMode::Flag("-s"), file: FileMode::Flag("-S") },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: build_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: VALIDATORS,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.1.6"),
        cmd: Some("go install -v github.com/jaeles-project/gospider@[install_version]"),
        github_handle: Some("jaeles-project/gospider"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static VALIDATORS: ValidatorRegistry = ValidatorRegistry {
    validate_input: &[],
    validate_item: &[validate_same_host],
};

/// Python `validate_item`: drop records whose `output` host doesn't match the
/// `input` host. gospider occasionally yields cross-origin URLs (referrers,
/// CDN assets); filtering them keeps the crawl scoped.
fn validate_same_host(item: &Map) -> bool {
    let input = item.get("input").and_then(|v| v.as_str()).unwrap_or("");
    let output = item.get("output").and_then(|v| v.as_str()).unwrap_or("");
    if input.is_empty() || output.is_empty() {
        return false;
    }
    let netloc_in = host_of(input);
    let netloc_out = host_of(output);
    match (netloc_in, netloc_out) {
        (Some(a), Some(b)) => a == b,
        _ => false, // invalid URL → drop (matches Python ValueError branch)
    }
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(String::from))
}

/// Per-record callback. gospider's raw dict already matches the Url schema
/// after the field renames in `build_output_maps`; we just run convert_item.
pub fn on_json_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let maps = build_output_maps();
    convert_item(&record, SPEC.output_types, &maps, None)
        .into_iter()
        .collect()
}

/// Python `output_map[Url]`: rename `url→output`, `status_code→status`,
/// `content_length→length`.
fn build_output_maps() -> OutputMaps {
    let mut maps = OutputMaps::new();
    let mut rename = OutputMap::new();
    rename.insert("url".into(), "output".into());
    rename.insert("status_code".into(), "status".into());
    rename.insert("content_length".into(), "length".into());
    maps.insert("url".into(), rename);
    maps
}

/// Python `opts`/`opt_key_map`/`opt_value_map`. HttpCrawler base + gospider's
/// renames. Note `follow_redirect` → `no-redirect` with value-inversion (the
/// flag is the negation in gospider).
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python NOT_SUPPORTED entries.
    for k in [
        "filter_codes", "filter_regex", "filter_size", "filter_words",
        "match_codes", "match_regex", "match_size", "match_words",
        "rate_limit", "retries", "method",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.key_map.insert("header".into(), KeyMap::Flag("header".into()));
    s.key_map.insert("delay".into(), KeyMap::Flag("delay".into()));
    s.key_map.insert("depth".into(), KeyMap::Flag("depth".into()));
    s.key_map.insert("follow_redirect".into(), KeyMap::Flag("no-redirect".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("threads".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("user_agent".into(), KeyMap::Flag("user-agent".into()));
    // `follow_redirect` is inverted (Python `lambda x: not x`).
    s.value_map.insert("follow_redirect".into(), ValueMap::Func(invert_bool));
    // `delay` is rounded to int (Python `round(x) if float`).
    s.value_map.insert("delay".into(), ValueMap::Func(round_to_int));
    s
}

fn invert_bool(v: &str) -> Option<String> {
    Some(match v {
        "true" => "false".into(),
        "false" => "true".into(),
        other => other.to_string(),
    })
}

fn round_to_int(v: &str) -> Option<String> {
    v.parse::<f64>().ok().map(|x| x.round() as i64).map(|x| x.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_same_host_keeps_matching_origin() {
        let mut m = Map::new();
        m.insert("input".into(), serde_json::Value::String("https://x.com/".into()));
        m.insert("output".into(), serde_json::Value::String("https://x.com/sub".into()));
        assert!(validate_same_host(&m));
    }

    #[test]
    fn validate_same_host_rejects_cross_origin() {
        let mut m = Map::new();
        m.insert("input".into(), serde_json::Value::String("https://x.com/".into()));
        m.insert("output".into(), serde_json::Value::String("https://cdn.example.org/a".into()));
        assert!(!validate_same_host(&m));
    }

    #[test]
    fn output_map_renames_url_status_content_length() {
        let line = r#"{"input":"https://x","output":"https://x/a","status":200,"length":1234}"#;
        let record: Map = serde_json::from_str(line).unwrap();
        let mut ctx = HookCtx::default();
        let items = on_json_loaded(&mut ctx, record);
        assert_eq!(items.len(), 1);
        if let OutputItem::Url(u) = &items[0] {
            assert_eq!(u.url, "https://x/a");
            assert_eq!(u.status_code, 200);
            assert_eq!(u.content_length, 1234);
        } else { panic!() }
    }

    #[test]
    fn invert_bool_swaps_truthiness() {
        assert_eq!(invert_bool("true").as_deref(), Some("false"));
        assert_eq!(invert_bool("false").as_deref(), Some("true"));
    }
}
