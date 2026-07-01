//! gitleaks — secret detection in git repos & file systems
//! (Python `secator/tasks/gitleaks.py`).
//!
//! gitleaks needs a subcommand (`git` for repos, `dir` for filesystems) and
//! writes its findings to a JSON file pointed to by `-r`. We mirror Python's
//! `on_cmd`: detect the right mode (auto-detect when the input has a `.git/`
//! folder), inject `<cmd> <mode> ...`, and append `-r <reports>/.outputs/...`.
//! `on_cmd_done` parses the JSON list and yields one `Tag(category=secret)`
//! per finding.

use std::fs;
use std::path::Path;

use secator_model::{Map, OutputItem, Tag};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

const GITLEAKS_MODES: &[&str] = &["git", "dir"];

pub static SPEC: TaskSpec = TaskSpec {
    name: "gitleaks",
    description: "Detect secrets (passwords, API keys, tokens) in repos & files.",
    cmd: "gitleaks",
    input_types: &["path"],
    output_types: &["tag"],
    tags: &["secret", "scan"],
    json_flag: Some("-f json"),
    // Single positional path; multi-input via inputs file isn't really
    // supported (one scan per path).
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
        version: Some("v8.29.1"),
        cmd: Some("git clone --single-branch -b [install_version] https://github.com/gitleaks/gitleaks.git $HOME/.local/share/gitleaks_[install_version] || true && cd $HOME/.local/share/gitleaks_[install_version] && make build && mv $HOME/.local/share/gitleaks_[install_version]/gitleaks $HOME/.local/bin"),
        github_handle: Some("gitleaks/gitleaks"),
        cmd_pre: &[("*", &["git", "make"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_inputs],
    on_cmd: &[on_cmd_inject_mode_and_output],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

/// Stash the first input on `ctx.state` so `on_cmd` can read it (Python uses
/// `self.inputs[0]` directly; we need it on the ctx because `on_cmd` sees only
/// the command string + ctx).
fn before_init_record_inputs(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(input) = runner.inputs.first() {
        ctx.state.insert("gitleaks:input".into(), input.clone());
    }
}

/// Python `on_cmd`: pick the right subcommand (`git` vs `dir`), inject it
/// after the binary name, then append `-r <output>.json --exit-code 0`.
fn on_cmd_inject_mode_and_output(ctx: &mut HookCtx, cmd: &mut String) {
    let mode = resolve_mode(ctx);
    // Inject `<mode>` right after `gitleaks `.
    *cmd = cmd.replacen("gitleaks ", &format!("gitleaks {mode} "), 1);
    let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
    let outputs_dir = if reports.is_empty() {
        "/tmp".to_string()
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&outputs_dir);
    let path = format!("{outputs_dir}/gitleaks.json");
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -r {quoted} --exit-code 0"));
    ctx.state.insert("gitleaks:output_path".into(), path);
}

/// Pick a mode for gitleaks: honour explicit `mode` opt; otherwise auto-detect
/// from the input path (`.git/` exists ⇒ `git`, else `dir`). Mirrors Python's
/// `convert_mode` + auto-detection branch.
fn resolve_mode(ctx: &HookCtx) -> String {
    if let Some(m) = ctx.state.get("gitleaks:mode") {
        let mapped = match m.as_str() {
            "filesystem" => "dir",
            "git" => "git",
            other => other,
        };
        if GITLEAKS_MODES.contains(&mapped) {
            return mapped.to_string();
        }
    }
    let input = ctx.state.get("gitleaks:input").cloned().unwrap_or_default();
    if !input.is_empty() && Path::new(&input).join(".git").exists() {
        "git".into()
    } else {
        "dir".into()
    }
}

/// Python `on_cmd_done`: read the JSON list and emit one Tag per finding.
fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("gitleaks:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let arr = match serde_json::from_str::<Value>(&body) {
        Ok(Value::Array(a)) => a,
        // gitleaks emits `null` (not `[]`) when there are no findings.
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in arr {
        let rule_id = entry.get("RuleID").and_then(|v| v.as_str()).unwrap_or("").replace('-', "_");
        let secret = entry.get("Secret").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let file = entry.get("File").and_then(|v| v.as_str()).unwrap_or("");
        let start_line = entry.get("StartLine").and_then(|v| v.as_i64()).unwrap_or(0);
        let start_col = entry.get("StartColumn").and_then(|v| v.as_i64()).unwrap_or(0);
        let match_ = format!("{file}:{start_line}:{start_col}");
        // Python `extra_data = {caml_to_snake(k): v for k,v in result.items()
        // if k not in ['RuleID', 'File', 'Secret']}`.
        let mut extra = Map::new();
        if let Value::Object(obj) = entry {
            for (k, v) in obj {
                if k == "RuleID" || k == "File" || k == "Secret" {
                    continue;
                }
                extra.insert(camel_to_snake(&k), v);
            }
        }
        out.push(OutputItem::Tag(Tag {
            category: "secret".into(),
            name: rule_id,
            value: secret,
            match_,
            extra_data: extra,
            ..Default::default()
        }));
    }
    out
}

/// Public alias of `camel_to_snake` so other modules can share the same
/// implementation. (Python's `utils.caml_to_snake` is used by gitleaks, trivy,
/// trufflehog — we keep one canonical impl here.)
pub fn camel_to_snake_pub(s: &str) -> String { camel_to_snake(s) }

/// Python `utils.caml_to_snake`: `StartLine` → `start_line`,
/// `RuleID` → `rule_id`, etc. Insert `_` before each uppercase that follows a
/// lowercase (or another uppercase if a lowercase follows it), then lowercase.
fn camel_to_snake(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && c.is_ascii_uppercase() {
            let prev = chars[i - 1];
            let next = chars.get(i + 1).copied().unwrap_or(' ');
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                out.push('_');
            } else if prev.is_ascii_uppercase() && next.is_ascii_lowercase() {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.opts = vec![
        str_opt("ignore_path", None, "Path to .gitleaksignore file or folder"),
        str_opt("mode", None, "Scan mode (git, dir, or filesystem alias)"),
        str_opt("config", None, "Config file path"),
    ];
    // Python: `ignore_path → gitleaks-ignore-path`. `mode` is internal — we
    // route the value via `ctx.state["gitleaks:mode"]` in `before_init` instead
    // of through the cmd builder.
    s.key_map.insert("ignore_path".into(), KeyMap::Flag("gitleaks-ignore-path".into()));
    s.key_map.insert("mode".into(), KeyMap::NotSupported);
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_to_snake_basic_cases() {
        assert_eq!(camel_to_snake("StartLine"), "start_line");
        assert_eq!(camel_to_snake("RuleID"), "rule_id");
        assert_eq!(camel_to_snake("URL"), "url");
        assert_eq!(camel_to_snake("ParseHTTPRequest"), "parse_http_request");
    }

    #[test]
    fn resolve_mode_honours_explicit_choice() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("gitleaks:mode".into(), "filesystem".into());
        assert_eq!(resolve_mode(&ctx), "dir");
        ctx.state.insert("gitleaks:mode".into(), "git".into());
        assert_eq!(resolve_mode(&ctx), "git");
    }

    #[test]
    fn on_cmd_done_parses_json_array_to_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gitleaks.json");
        let body = r#"[
            {"RuleID":"aws-access-token","Secret":"AKIA...","File":"src/x.py","StartLine":42,"StartColumn":12,"EndLine":42,"Commit":"abc","Tags":["aws"]}
        ]"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("gitleaks:output_path".into(), path.to_string_lossy().into_owned());
        let items = on_cmd_done_parse(&mut ctx);
        assert_eq!(items.len(), 1);
        let t = match &items[0] { OutputItem::Tag(t) => t, _ => panic!() };
        assert_eq!(t.category, "secret");
        assert_eq!(t.name, "aws_access_token"); // hyphens → underscores
        assert_eq!(t.value, "AKIA...");
        assert_eq!(t.match_, "src/x.py:42:12");
        assert!(t.extra_data.contains_key("start_line"));
        assert!(!t.extra_data.contains_key("RuleID"));
    }

    #[test]
    fn on_cmd_done_tolerates_null_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gitleaks.json");
        std::fs::write(&path, "null").unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("gitleaks:output_path".into(), path.to_string_lossy().into_owned());
        assert!(on_cmd_done_parse(&mut ctx).is_empty());
    }
}
