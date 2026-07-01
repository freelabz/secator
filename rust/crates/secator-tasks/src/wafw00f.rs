//! wafw00f — Web Application Firewall fingerprinting (Python
//! `secator/tasks/wafw00f.py`).
//!
//! wafw00f writes its detection report to a JSON file we pass via `-o`. We:
//!   1. Inject `-o <reports_folder>/.outputs/wafw00f.json` in `on_cmd` and stash
//!      the path in `ctx.state["wafw00f:output_path"]`.
//!   2. After the subprocess exits, `on_cmd_done` parses that file (a JSON list)
//!      and yields one `Tag(category="info", name="waf", value=<firewall>)` for
//!      each detection. Skips entries where `detected: false`.

use std::fs;

use secator_model::{Map, OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "wafw00f",
    description: "Web Application Firewall fingerprinting tool.",
    cmd: "wafw00f",
    input_types: &["url", "host", "host_port", "ip"],
    output_types: &["tag"],
    tags: &["waf", "scan"],
    // The JSON goes into a file (`-f json -o <path>`), not stdout.
    json_flag: Some("-f json"),
    // Python `file_flag = '-i'`, default single = positional.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Flag("-i") },
    item_loaders: &[],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.3.1"),
        cmd: Some("pipx install git+https://github.com/EnableSecurity/wafw00f.git@[install_version] --force"),
        github_handle: Some("EnableSecurity/wafw00f"),
        github_bin: false,
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    on_cmd: &[on_cmd_inject_output],
    on_cmd_done: &[on_cmd_done_parse_json],
    ..HookRegistry::EMPTY
};

/// Python `on_cmd`: append `-o <reports_folder>/.outputs/wafw00f.json` and
/// stash the path for `on_cmd_done`. Mirrors the file-based output the Python
/// task expects.
fn on_cmd_inject_output(ctx: &mut HookCtx, cmd: &mut String) {
    let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
    let outputs_dir = if reports.is_empty() {
        "/tmp".to_string()
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&outputs_dir);
    let path = format!("{outputs_dir}/wafw00f.json");
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -o {quoted}"));
    ctx.state.insert("wafw00f:output_path".into(), path);
}

/// Python `on_cmd_done`: read the JSON list and emit one `Tag` per detected WAF.
fn on_cmd_done_parse_json(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("wafw00f:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let arr = match serde_json::from_str::<Value>(&body) {
        Ok(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in arr {
        if !entry.get("detected").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let firewall = entry.get("firewall").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let trigger = entry.get("trigger_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let manufacturer = entry
            .get("manufacturer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut extra: Map = Map::new();
        extra.insert("manufacter".into(), Value::String(manufacturer));
        extra.insert("trigger_url".into(), Value::String(trigger));
        out.push(OutputItem::Tag(Tag {
            category: "info".into(),
            name: "waf".into(),
            match_: url,
            value: firewall,
            extra_data: extra,
            ..Default::default()
        }));
    }
    out
}

/// Python `opts` + `opt_key_map`. wafw00f uses `--` for long options.
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // Python keeps just proxy/header/timeout from the HTTP meta block.
    s.meta_opts = meta_opts::opts_http_base()
        .into_iter()
        .filter(|o| matches!(o.name, "proxy" | "header" | "timeout"))
        .collect();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    s.key_map.insert("header".into(), KeyMap::Flag("headers".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.opts = vec![
        flag("list", None, "List all WAFs that wafw00f is able to detect"),
        str_opt("waf_type", Some("wt"), "Test for one specific WAF"),
        flag("find_all", Some("ta"), "Find all WAFs that match (don't stop on first hit)"),
        flag(
            "no_follow_redirects",
            Some("nfr"),
            "Do not follow 3xx redirects",
        ),
    ];
    // Python renames waf_type → test, find_all → findall, no_follow_redirects → noredirect.
    s.key_map.insert("waf_type".into(), KeyMap::Flag("test".into()));
    s.key_map.insert("find_all".into(), KeyMap::Flag("findall".into()));
    s.key_map.insert("no_follow_redirects".into(), KeyMap::Flag("noredirect".into()));
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
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

    #[test]
    fn on_cmd_done_emits_one_tag_per_detected_waf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wafw00f.json");
        let body = r#"[
            {"detected": true, "firewall": "Cloudflare", "url": "https://x", "trigger_url": "https://x/?a", "manufacturer": "CloudflareInc"},
            {"detected": false, "firewall": "ModSecurity", "url": "https://y", "trigger_url": "", "manufacturer": "OWASP"}
        ]"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("wafw00f:output_path".into(), path.to_string_lossy().into_owned());
        let items = on_cmd_done_parse_json(&mut ctx);
        assert_eq!(items.len(), 1);
        let t = match &items[0] { OutputItem::Tag(t) => t, _ => panic!() };
        assert_eq!(t.name, "waf");
        assert_eq!(t.value, "Cloudflare");
        assert_eq!(t.match_, "https://x");
        assert_eq!(t.category, "info");
    }

    #[test]
    fn on_cmd_done_returns_empty_when_file_missing() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("wafw00f:output_path".into(), "/nope".into());
        assert!(on_cmd_done_parse_json(&mut ctx).is_empty());
    }
}
