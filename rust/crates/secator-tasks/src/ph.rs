//! ph — FreeLabz pattern hunter, YAML-DSL pattern matcher (Python
//! `secator/tasks/ph.py`).
//!
//! `ph -jsonl -sc` emits one JSONL record per match:
//!   `{ "input_path": "...", "match": {...}, "config": {...} }`
//! Python's `on_json_loaded` lifts a `Tag` per record, mapping context/value
//! from `match` and `name` from `config.name`. Records with empty
//! name/match/value are dropped.

use secator_model::{Map, OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "ph",
    description: "Fast pattern hunter — YAML-DSL pattern matcher.",
    cmd: "ph",
    // Python `input_types = [URL, STRING]`. Both lower-cased on the Rust side.
    input_types: &["url", "string"],
    output_types: &["tag"],
    tags: &["url", "tag"],
    json_flag: Some("-jsonl -sc"),
    // Python: `input_flag = OPT_PIPE_INPUT`, `file_flag = OPT_PIPE_INPUT` — every
    // input goes through stdin (single or multi).
    input_wiring: InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v0.1.0"),
        cmd: Some("go install -v github.com/freelabz/ph/cmd/ph@[install_version]"),
        github_handle: Some("freelabz/ph"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: true,
    requires_sudo: false,
    default_inputs: None,
};

/// Python `on_json_loaded`: pull `match.{context,value,...}` and `config.{name,path}`,
/// emit a `Tag(name=config.name, match=context, value=value, extra_data=...)`.
pub fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let match_obj = match item.get("match").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let config_obj = match item.get("config").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let name = str_of(config_obj, "name");
    let match_str = str_of(match_obj, "context");
    let value = str_of(match_obj, "value");
    if name.is_empty() || match_str.is_empty() || value.is_empty() {
        return Vec::new();
    }
    let mut extra: Map = Map::new();
    extra.insert("input_path".into(), Value::String(str_of(&item, "input_path")));
    extra.insert(
        "line_number".into(),
        match_obj.get("line_number").cloned().unwrap_or(Value::Null),
    );
    extra.insert(
        "char_position".into(),
        match_obj.get("char_position").cloned().unwrap_or(Value::Null),
    );
    extra.insert("context".into(), Value::String(match_str.clone()));
    extra.insert(
        "pattern".into(),
        Value::String(str_of(match_obj, "pattern")),
    );
    extra.insert(
        "regex_path".into(),
        Value::String(str_of(config_obj, "path")),
    );
    vec![OutputItem::Tag(Tag {
        name,
        match_: match_str,
        value,
        extra_data: extra,
        ..Default::default()
    })]
}

fn str_of(obj: &Map, key: &str) -> String {
    obj.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    // Python opts = {'p': ...}. We surface it as `patterns` for clarity, but
    // ph's CLI flag is `-p`.
    s.opts = vec![OptSpec {
        name: "patterns",
        ty: OptType::Str,
        short: Some("p"),
        is_flag: false,
        default: None,
        help: "Patterns to match (comma-separated)",
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s.key_map.insert("patterns".into(), KeyMap::Flag("p".into()));
    // Tagger has no recon/http meta opts — mark them unsupported so they don't
    // leak into the cmd line.
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
    use serde_json::json;

    fn run(v: Value) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        on_json_loaded(&mut ctx, v.as_object().unwrap().clone())
    }

    #[test]
    fn full_record_emits_tag() {
        let out = run(json!({
            "input_path": "https://example.com/page",
            "match": {
                "context": "Set-Cookie: SESSIONID=abc",
                "value": "SESSIONID",
                "line_number": 12,
                "char_position": 5,
                "pattern": "SESSIONID=[a-z]+"
            },
            "config": {"name": "session_cookie", "path": "/cfg/cookies.yml"}
        }));
        assert_eq!(out.len(), 1);
        if let OutputItem::Tag(t) = &out[0] {
            assert_eq!(t.name, "session_cookie");
            assert_eq!(t.match_, "Set-Cookie: SESSIONID=abc");
            assert_eq!(t.value, "SESSIONID");
            assert_eq!(
                t.extra_data.get("line_number").and_then(|v| v.as_i64()),
                Some(12)
            );
            assert_eq!(
                t.extra_data.get("regex_path").and_then(|v| v.as_str()),
                Some("/cfg/cookies.yml")
            );
        } else { panic!() }
    }

    #[test]
    fn empty_name_drops_record() {
        let out = run(json!({
            "match": {"context": "x", "value": "y"},
            "config": {"name": ""}
        }));
        assert!(out.is_empty());
    }

    #[test]
    fn missing_match_drops_record() {
        let out = run(json!({"config": {"name": "x"}}));
        assert!(out.is_empty());
    }

    #[test]
    fn patterns_opt_maps_to_p_flag() {
        use secator_runner::CommandRunner;
        let mut r = CommandRunner::new(&SPEC, vec!["https://example.com".into()]);
        r.opts.insert("patterns".into(), "secrets,session".into());
        let cmd = r.build_cmd();
        assert!(cmd.contains("-p"), "got: {cmd}");
        assert!(cmd.contains("secrets,session") || cmd.contains("'secrets,session'"), "got: {cmd}");
    }
}
