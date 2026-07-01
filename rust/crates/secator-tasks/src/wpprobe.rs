//! wpprobe — WordPress plugin / theme enumeration & vuln lookup.
//! Python `secator/tasks/wpprobe.py`.
//!
//! Modes: `scan` (default), `update`, `update-db`. The mode is injected as the
//! first subcommand token (e.g. `wpprobe scan -u <url>`). For `scan`, results
//! are written to a YAML file via `-o <path>`; we parse it in `on_cmd_done`
//! and emit Tag(category=info, name=wordpress_plugin|wordpress_theme) per
//! entry, plus a Vulnerability per CVE listed in `severities[*].auth_groups`.

use std::fs;

use secator_model::{Error, Info, Map, OutputItem, Tag, Vulnerability, Warning};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "wpprobe",
    description: "Fast WordPress plugin / theme enumeration with vuln lookup.",
    cmd: "wpprobe",
    input_types: &["url"],
    output_types: &["vulnerability", "tag"],
    tags: &["vuln", "scan", "wordpress"],
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-f") },
    item_loaders: &[],
    input_chunk_size: 1,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v0.11.1"),
        cmd: Some("go install github.com/Chocapikk/wpprobe@[install_version]"),
        github_handle: Some("Chocapikk/wpprobe"),
        post: &[("*", "wpprobe update-db")],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_state],
    on_cmd: &[on_cmd_inject_mode_and_output],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

fn before_init_record_state(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    let mode = runner
        .opts
        .get("mode")
        .cloned()
        .unwrap_or_else(|| "scan".into());
    ctx.state.insert("wpprobe:mode".into(), mode);
    if let Some(rf) = &runner.reports_folder {
        ctx.state.insert("wpprobe:reports".into(), rf.to_string_lossy().into_owned());
    }
    runner.opts.remove("mode");
}

fn on_cmd_inject_mode_and_output(ctx: &mut HookCtx, cmd: &mut String) {
    let mode = ctx
        .state
        .get("wpprobe:mode")
        .cloned()
        .unwrap_or_else(|| "scan".into());
    if mode == "update" || mode == "update-db" {
        // Replace the whole cmd with `wpprobe <mode>` — Python parity.
        *cmd = format!("wpprobe {mode}");
        return;
    }
    // For `scan` mode: inject the subcommand right after `wpprobe`.
    *cmd = cmd.replacen("wpprobe", &format!("wpprobe {mode}"), 1);
    let reports = ctx.state.get("wpprobe:reports").cloned().unwrap_or_default();
    let outputs_dir = if reports.is_empty() {
        String::from("/tmp")
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&outputs_dir);
    let path = format!("{outputs_dir}/wpprobe.yaml");
    let quoted = shell_words::quote(&path).into_owned();
    cmd.push_str(&format!(" -o {quoted}"));
    ctx.state.insert("wpprobe:output_path".into(), path);
}

fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let mode = ctx.state.get("wpprobe:mode").cloned().unwrap_or_default();
    if mode != "scan" {
        return Vec::new();
    }
    let path = match ctx.state.get("wpprobe:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            return vec![OutputItem::Error(Error {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })];
        }
    };
    // The file is YAML; serde_yaml round-trips into serde_json Values for free.
    let yaml: serde_yaml::Value = match serde_yaml::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let json: Value = serde_json::to_value(&yaml).unwrap_or(Value::Null);
    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    let root = match json.as_object() {
        Some(o) => o,
        None => return out,
    };
    let url = root.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if url.is_empty() {
        out.push(OutputItem::Warning(Warning {
            message: "No results found !".into(),
            ..Default::default()
        }));
        return out;
    }
    for kind in ["plugin", "theme"] {
        let key = format!("{kind}s");
        let group = root.get(&key).and_then(|v| v.as_object());
        if let Some(group) = group {
            for (name, versions) in group {
                if let Some(arr) = versions.as_array() {
                    for entry in arr {
                        out.extend(emit_software(entry, name, kind, &url));
                    }
                }
            }
        }
    }
    out
}

fn emit_software(entry: &Value, name: &str, kind: &str, url: &str) -> Vec<OutputItem> {
    let mut out = Vec::new();
    let version = entry.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tag_name = format!("wordpress_{kind}");
    let mut extra: Map = Map::new();
    extra.insert("name".into(), Value::String(name.to_string()));
    extra.insert("version".into(), Value::String(version.clone()));
    extra.insert("type".into(), Value::String(kind.to_string()));
    out.push(OutputItem::Tag(Tag {
        category: "info".into(),
        name: tag_name.clone(),
        match_: url.to_string(),
        value: format!("{name}:{version}"),
        extra_data: extra,
        ..Default::default()
    }));
    // Normalize severities: may be either a dict or a list-of-dicts (wpprobe issue #17).
    let raw_sev = entry.get("severities").cloned().unwrap_or(Value::Object(Default::default()));
    let merged: Value = match &raw_sev {
        Value::Array(arr) => {
            let mut m: serde_json::Map<String, Value> = Default::default();
            for el in arr {
                if let Some(o) = el.as_object() {
                    for (k, v) in o {
                        if k != "n/a" {
                            m.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
            Value::Object(m)
        }
        _ => raw_sev,
    };
    let sevs = match merged.as_object() {
        Some(o) => o,
        None => return out,
    };
    for (severity, auth_groups) in sevs {
        let severity = if severity.to_lowercase() == "none" {
            "unknown".to_string()
        } else {
            severity.clone()
        };
        let groups = match auth_groups.as_array() {
            Some(a) => a,
            None => continue,
        };
        for group in groups {
            let auth_type = group.get("auth_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let vulns = match group.get("vulnerabilities").and_then(|v| v.as_array()) {
                Some(v) => v,
                None => continue,
            };
            for v in vulns {
                let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
                if title.is_empty() {
                    continue;
                }
                let cve = v.get("cve").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let cve_link = v.get("cve_link").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let cvss = v.get("cvss_score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                let mut extra: Map = Map::new();
                extra.insert(format!("{kind}_name"), Value::String(name.to_string()));
                extra.insert(format!("{kind}_version"), Value::String(version.clone()));
                if !auth_type.is_empty() {
                    extra.insert("auth_type".into(), Value::String(auth_type.clone()));
                }
                let mut tags = vec!["wordpress".into(), tag_name.clone(), name.to_string()];
                tags.dedup();
                out.push(OutputItem::Vulnerability(Vulnerability {
                    name: title.into(),
                    id: cve,
                    severity: severity.clone(),
                    cvss_score: cvss,
                    tags,
                    references: if cve_link.is_empty() { Vec::new() } else { vec![cve_link] },
                    extra_data: extra,
                    matched_at: url.into(),
                    confidence: "high".into(),
                    ..Default::default()
                }));
            }
        }
    }
    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    s.meta_opts = vec![]; // wpprobe only takes `--threads`/`-t`, which we model below.
    s.key_map.insert("threads".into(), KeyMap::Flag("t".into()));
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![OptSpec {
        name: "mode",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: Some("scan"),
        help: "WPProbe mode (scan / update / update-db)",
        internal: true,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s.key_map.insert("mode".into(), KeyMap::NotSupported);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_cmd_injects_scan_and_output() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("wpprobe:mode".into(), "scan".into());
        let mut cmd = "wpprobe -u https://example.com".to_string();
        on_cmd_inject_mode_and_output(&mut ctx, &mut cmd);
        assert!(cmd.starts_with("wpprobe scan -u "));
        assert!(cmd.contains(" -o "));
    }

    #[test]
    fn parses_plugin_results_with_vulns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.yaml");
        // Build via serde_yaml to avoid hand-indentation traps.
        let yaml = serde_yaml::to_string(&serde_json::json!({
            "url": "https://example.com",
            "plugins": {
                "contact-form-7": [
                    {
                        "version": "5.4.0",
                        "severities": {
                            "high": [
                                {
                                    "auth_type": "unauth",
                                    "vulnerabilities": [
                                        {
                                            "title": "XSS in CF7",
                                            "cve": "CVE-2024-1000",
                                            "cve_link": "https://nvd.nist.gov/cve/CVE-2024-1000",
                                            "cvss_score": 7.5
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        })).unwrap();
        std::fs::write(&path, yaml).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("wpprobe:mode".into(), "scan".into());
        ctx.state.insert("wpprobe:output_path".into(), path.to_string_lossy().into_owned());
        let out = on_cmd_done_parse(&mut ctx);
        let has_tag = out.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "wordpress_plugin"));
        let has_vuln = out.iter().any(|i| matches!(i, OutputItem::Vulnerability(v) if v.id == "CVE-2024-1000"));
        assert!(has_tag && has_vuln, "out={:?}", out);
    }
}
