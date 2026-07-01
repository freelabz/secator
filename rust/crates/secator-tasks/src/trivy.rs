//! trivy — comprehensive security scanner (Python `secator/tasks/trivy.py`).
//!
//! Three modes (`image`, `fs`, `repo`); we autodetect from the input when the
//! user doesn't pass `--mode`. Output goes to a JSON file via `-o`. After the
//! subprocess exits, `on_cmd_done` walks `data.Results[*].Vulnerabilities` and
//! `data.Results[*].Secrets` and emits `Vulnerability` / `Tag(category=secret)`.

use std::fs;
use std::path::Path;

use secator_model::{Error, Info, Map, OutputItem, Tag, Vulnerability};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

const TRIVY_MODES: &[&str] = &["image", "fs", "repo"];

pub static SPEC: TaskSpec = TaskSpec {
    name: "trivy",
    description: "Aquasec Trivy — versatile vulnerability & secret scanner.",
    cmd: "trivy",
    input_types: &["path", "string"],
    output_types: &["vulnerability", "tag"],
    tags: &["vuln", "scan"],
    json_flag: Some("-f json"),
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
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
        version: Some("v0.69.3"),
        cmd: Some("curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $HOME/.local/bin [install_version]"),
        github_handle: Some("aquasecurity/trivy"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_input],
    on_cmd: &[on_cmd_inject_mode_and_output],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

/// Stash the first input on `ctx.state` so `on_cmd` can autodetect the mode
/// (Python uses `self.inputs[0]`; we have to pre-record it because hooks
/// receive only `ctx` and the cmd string).
fn before_init_record_input(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(input) = runner.inputs.first() {
        ctx.state.insert("trivy:input".into(), input.clone());
    }
}

/// Python `on_cmd`: pick `image`/`fs`/`repo`, inject it after `trivy`, then
/// append `-o <reports>/.outputs/trivy.json`.
fn on_cmd_inject_mode_and_output(ctx: &mut HookCtx, cmd: &mut String) {
    let mode = resolve_mode(ctx);
    // Drop any user-supplied `-mode <m>` placeholder and prefix the actual mode.
    *cmd = strip_mode_arg(cmd).replacen("trivy", &format!("trivy {mode}"), 1);
    let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
    let dir = if reports.is_empty() {
        "/tmp".to_string()
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&dir);
    let path = format!("{dir}/trivy.json");
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -o {quoted}"));
    ctx.state.insert("trivy:output_path".into(), path);
}

fn resolve_mode(ctx: &HookCtx) -> String {
    if let Some(m) = ctx.state.get("trivy:mode") {
        let mapped = match m.as_str() {
            "filesystem" => "fs",
            "git" => "repo",
            other => other,
        };
        if TRIVY_MODES.contains(&mapped) {
            return mapped.to_string();
        }
    }
    let input = ctx.state.get("trivy:input").cloned().unwrap_or_default();
    if input.is_empty() {
        return "fs".into();
    }
    let p = Path::new(&input);
    if p.join(".git").exists() {
        "repo".into()
    } else if p.exists() {
        "fs".into()
    } else {
        // Doesn't look like a local path → treat as a container image.
        "image".into()
    }
}

/// Strip `-mode <value>` and `--mode <value>` tokens from the cmd. We re-prepend
/// the resolved mode after as a subcommand.
fn strip_mode_arg(cmd: &str) -> String {
    let mut tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "-mode" || tokens[i] == "--mode" {
            // Remove this token + next (the value).
            if i + 1 < tokens.len() {
                tokens.drain(i..=i + 1);
                continue;
            }
            tokens.remove(i);
        } else {
            i += 1;
        }
    }
    tokens.join(" ")
}

fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("trivy:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let input = ctx.state.get("trivy:input").cloned().unwrap_or_default();
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => {
            return vec![OutputItem::Error(Error {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })];
        }
    };
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    let Some(results) = parsed.get("Results").and_then(|v| v.as_array()) else {
        return out;
    };
    for item in results {
        let target = item.get("Target").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Some(vulns) = item.get("Vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulns {
                out.push(build_vuln(vuln, &input));
            }
        }
        if let Some(secrets) = item.get("Secrets").and_then(|v| v.as_array()) {
            for secret in secrets {
                out.push(build_secret_tag(secret, &target));
            }
        }
    }
    out
}

fn build_vuln(vuln: &Value, fallback_match: &str) -> OutputItem {
    let vid = vuln.get("VulnerabilityID").and_then(|v| v.as_str()).unwrap_or("");
    let mut extra = Map::new();
    if let Some(pkg) = vuln.get("PkgName").and_then(|v| v.as_str()) {
        extra.insert("product".into(), Value::String(pkg.to_string()));
    }
    if let Some(ver) = vuln.get("InstalledVersion").and_then(|v| v.as_str()) {
        extra.insert("version".into(), Value::String(ver.to_string()));
    }
    // CVSS: take the first non-zero V3Score, fall back to V2Score.
    let mut cvss_score = 0.0_f64;
    if let Some(cvss) = vuln.get("CVSS").and_then(|v| v.as_object()) {
        for (_, data) in cvss {
            let v3 = data.get("V3Score").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let v2 = data.get("V2Score").and_then(|x| x.as_f64()).unwrap_or(0.0);
            if v3 > 0.0 {
                cvss_score = v3;
                break;
            }
            if v2 > 0.0 {
                cvss_score = v2;
            }
        }
    }
    let severity = vuln.get("Severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_lowercase();
    let description = vuln.get("Description").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let primary = vuln.get("PrimaryURL").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let references = vuln
        .get("References")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();
    let provider = vuln
        .get("DataSource")
        .and_then(|v| v.get("ID"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    OutputItem::Vulnerability(Vulnerability {
        id: vid.to_string(),
        name: vid.replace('-', "_"),
        provider,
        confidence: "high".into(),
        severity,
        cvss_score,
        description,
        reference: primary,
        references,
        matched_at: fallback_match.to_string(),
        extra_data: extra,
        ..Default::default()
    })
}

fn build_secret_tag(secret: &Value, target: &str) -> OutputItem {
    let rule_id = secret.get("RuleID").and_then(|v| v.as_str()).unwrap_or("").replace('-', "_");
    let m = secret.get("Match").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let code_context = secret
        .get("Code")
        .and_then(|c| c.get("Lines"))
        .and_then(|l| l.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|line| line.get("Content").and_then(|v| v.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let mut extra = Map::new();
    extra.insert("code_context".into(), Value::String(code_context));
    if let Value::Object(obj) = secret {
        for (k, v) in obj {
            if matches!(k.as_str(), "RuleID" | "Match" | "Code") {
                continue;
            }
            extra.insert(crate::gitleaks::camel_to_snake_pub(k), v.clone());
        }
    }
    OutputItem::Tag(Tag {
        category: "secret".into(),
        name: rule_id,
        value: m,
        match_: target.to_string(),
        extra_data: extra,
        ..Default::default()
    })
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // Vuln meta = OPTS_VULN — but trivy doesn't accept any of them, so all
    // are NOT_SUPPORTED.
    for k in [
        "threads", "header", "delay", "follow_redirect", "proxy",
        "rate_limit", "retries", "timeout", "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![OptSpec {
        name: "mode",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: None,
        help: "Scan mode (image, fs, repo; filesystem/git aliases accepted)",
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    // Mode is internal — routed via `ctx.state["trivy:mode"]`, not the cmd.
    s.key_map.insert("mode".into(), KeyMap::NotSupported);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with_body(body: &str, input: &str) -> Vec<OutputItem> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trivy.json");
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("trivy:output_path".into(), path.to_string_lossy().into_owned());
        ctx.state.insert("trivy:input".into(), input.into());
        on_cmd_done_parse(&mut ctx)
    }

    #[test]
    fn parses_vulnerabilities_and_secrets() {
        let body = r#"{
            "Results": [
                {
                    "Target": "alpine:3.18 (alpine 3.18.4)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.1.0",
                            "Severity": "HIGH",
                            "Description": "test",
                            "CVSS": {"nvd": {"V3Score": 8.1, "V2Score": 7.0}},
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                            "References": ["https://example.com/advisory"]
                        }
                    ],
                    "Secrets": [
                        {"RuleID":"aws-token","Match":"AKIA...","Code":{"Lines":[{"Content":"key=\"AKIA...\""}]}}
                    ]
                }
            ]
        }"#;
        let out = run_with_body(body, "alpine:3.18");
        let v = out.iter().find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None }).unwrap();
        assert_eq!(v.id, "CVE-2024-0001");
        assert_eq!(v.severity, "high");
        assert_eq!(v.cvss_score, 8.1);
        assert!(v.extra_data.get("product").is_some());
        let t = out.iter().find_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None }).unwrap();
        assert_eq!(t.category, "secret");
        assert_eq!(t.name, "aws_token");
        assert!(t.extra_data.get("code_context").is_some());
    }

    #[test]
    fn resolve_mode_image_for_non_path() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("trivy:input".into(), "nginx:latest".into());
        assert_eq!(resolve_mode(&ctx), "image");
    }

    #[test]
    fn strip_mode_arg_removes_both_short_and_long_forms() {
        assert_eq!(strip_mode_arg("trivy -mode fs --json"), "trivy --json");
        assert_eq!(strip_mode_arg("trivy --mode image"), "trivy");
    }
}
