//! trufflehog — secret scanner (Python `secator/tasks/trufflehog.py`).
//!
//! trufflehog needs a mode subcommand chosen from {git, github, gitlab,
//! s3, filesystem, gcs, docker, postman, jenkins, elasticsearch, huggingface,
//! syslog}. If `--mode` is unset, we auto-detect from the input:
//!   * directory containing `.git/` → `git` (with `file://<path>` submode)
//!   * any other existing path     → `filesystem`
//!   * `https://github.com/<org>` or `https://github.com/<org>/<repo>` → `github`
//!   * `https://gitlab.com/...`    → `gitlab`
//!
//! `on_cmd` rewrites the cmd to inject the mode subcommand and the appropriate
//! per-mode input flag (`--repo`, `--org`, `--bucket`, `--image`, `--url`, ...).
//! `on_json_loaded` parses each JSON line:
//!   * `level: info`   → `Info(msg)`
//!   * `level: *` + `Error running scan` → `Error`
//!   * any record with `SourceMetadata` → `Tag(category="secret", ...)` with
//!     `match` set to a `repo/file:line` string (or the `link` if present).

use std::path::Path;

use secator_model::{Error, Info, Map, OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

const MODES: &[&str] = &[
    "git", "github", "gitlab", "s3", "filesystem", "gcs", "docker",
    "postman", "jenkins", "elasticsearch", "huggingface", "syslog",
];

pub static SPEC: TaskSpec = TaskSpec {
    name: "trufflehog",
    description: "Find secrets in git repos / filesystems / cloud sources.",
    cmd: "trufflehog",
    input_types: &["path", "url", "string", "slug"],
    output_types: &["tag", "info"],
    tags: &["secret", "scan"],
    // trufflehog reads input from positional arguments shaped by the mode flag.
    // The auto-detect logic in `on_cmd` rewrites the cmd to add `--repo`/`--org`/
    // `--bucket`/etc, so the default arg-wiring here is fine.
    json_flag: Some("--json"),
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    // Stream JSON lines directly (trufflehog emits one JSON object per line).
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
        version: Some("v3.91.0"),
        cmd: Some("git clone https://github.com/trufflesecurity/trufflehog.git $HOME/.local/share/trufflehog_[install_version] || true && cd $HOME/.local/share/trufflehog_[install_version] && go build -o trufflehog . && mv $HOME/.local/share/trufflehog_[install_version]/trufflehog $HOME/.local/bin"),
        github_handle: Some("trufflesecurity/trufflehog"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_input],
    on_cmd: &[on_cmd_mode_autodetect],
    ..HookRegistry::EMPTY
};

fn before_init_record_input(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(i) = runner.inputs.first() {
        ctx.state.insert("trufflehog:input".into(), i.clone());
    }
    if let Some(m) = runner.opts.get("mode") {
        ctx.state.insert("trufflehog:mode_in".into(), m.clone());
    }
}

/// Python `on_cmd`: pick mode (CLI-supplied or auto-detected), rewrite the
/// cmd to inject the subcommand + the per-mode input flag. We work on the
/// already-built `cmd` string to mirror Python `self.cmd.replace(...)`.
fn on_cmd_mode_autodetect(ctx: &mut HookCtx, cmd: &mut String) {
    let input = ctx
        .state
        .get("trufflehog:input")
        .cloned()
        .unwrap_or_default();
    // Mode may already be set via --mode (we stash it from opts here).
    let mut mode = ctx.state.get("trufflehog:mode_in").cloned().unwrap_or_default();
    let mut submode: Option<&str> = None;
    let mut new_input: Option<String> = None;

    if !mode.is_empty() && !MODES.contains(&mode.as_str()) {
        // Invalid mode — leave the cmd alone; trufflehog will error and we'll
        // pass that through.
        return;
    }
    if mode.is_empty() && !input.is_empty() {
        let p = Path::new(&input);
        if p.join(".git").exists() {
            mode = "git".into();
            submode = Some("local");
        } else if p.exists() {
            mode = "filesystem".into();
        } else if let Some(rest) = input.strip_prefix("https://github.com/") {
            mode = "github".into();
            let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
            match parts.len() {
                1 => {
                    submode = Some("org");
                    new_input = Some(parts[0].to_string());
                }
                2 => {
                    submode = Some("repo");
                    new_input = Some(parts.join("/"));
                }
                _ => {}
            }
        } else if input.starts_with("https://gitlab.com/") {
            mode = "gitlab".into();
        }
    }
    if mode.is_empty() {
        return;
    }

    // Python `mode_to_option` table: maps `<mode>` (or `<mode>_<submode>` for
    // github org/repo) to the flag that should prefix the input on the cmd.
    let mode_key = match (mode.as_str(), submode) {
        ("github", Some("org")) => "github_org",
        ("github", Some("repo")) => "github_repo",
        _ => mode.as_str(),
    };
    let mode_flag: Option<&str> = match mode_key {
        "github_org" => Some("--org"),
        "github_repo" => Some("--repo"),
        "git" => None,
        "gitlab" => Some("--repo"),
        "s3" => Some("--bucket"),
        "gcs" => Some("--cloud-environment --project-id"),
        "docker" => Some("--image"),
        "jenkins" => Some("--url"),
        _ => None,
    };
    let submode_prefix: Option<&str> = match submode {
        Some("local") => Some("file://"),
        Some("org") => Some("--org "),
        Some("repo") => Some("--repo "),
        _ => None,
    };

    if let Some(ni) = &new_input {
        *cmd = cmd.replace(&input, ni);
    }
    let effective_input = new_input.clone().unwrap_or_else(|| input.clone());
    if let Some(pre) = submode_prefix {
        *cmd = cmd.replace(&effective_input, &format!("{pre}{effective_input}"));
    }
    if let Some(opt) = mode_flag {
        *cmd = cmd.replace(&effective_input, &format!("{opt} {effective_input}"));
    }
    let inject = format!("trufflehog {mode}");
    if !cmd.contains(&inject) {
        *cmd = cmd.replacen("trufflehog", &inject, 1);
    }
    ctx.state.insert("trufflehog:mode".into(), mode);
}

fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    // Log lines: trufflehog emits `{"level":"info","msg":"...","time":"..."}`.
    if let Some(level) = item.get("level").and_then(|v| v.as_str()) {
        let raw_msg = item.get("msg").and_then(|v| v.as_str()).unwrap_or("");
        let msg = capitalize_first(raw_msg);
        if level.starts_with("info") {
            return vec![OutputItem::Info(Info { message: msg, ..Default::default() })];
        }
        if msg == "Error running scan" {
            let err_str = item.get("error").and_then(|v| v.as_str()).unwrap_or("");
            let mut full = msg;
            if !err_str.is_empty() {
                full.push_str(" - ");
                full.push_str(err_str);
            }
            return vec![OutputItem::Error(Error { message: full, ..Default::default() })];
        }
        return Vec::new();
    }
    let src = match item.get("SourceMetadata").and_then(|v| v.get("Data")) {
        Some(d) => d.clone(),
        None => return Vec::new(),
    };
    let rule_id = crate::gitleaks::camel_to_snake_pub(
        item.get("DetectorName").and_then(|v| v.as_str()).unwrap_or("Unknown"),
    );
    let raw = item
        .get("RawV2")
        .and_then(|v| v.as_str())
        .or_else(|| item.get("Raw").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    // `data` = first nested object under SourceMetadata.Data (e.g. `Git`/`Filesystem`).
    let (subtype_raw, data_obj) = match src.as_object().and_then(|o| o.iter().next()) {
        Some((k, v)) => (k.clone(), v.clone()),
        None => return Vec::new(),
    };
    let subtype = subtype_raw.to_lowercase();
    let data_map: Map = data_obj.as_object().cloned().unwrap_or_default()
        .into_iter()
        .filter(|(k, _)| k != "timestamp")
        .map(|(k, v)| (crate::gitleaks::camel_to_snake_pub(&k), v))
        .collect();

    // Detector data: everything from the JSON record minus the metadata/raw.
    let detector_data: Map = item.clone()
        .into_iter()
        .filter(|(k, _)| !matches!(k.as_str(), "SourceMetadata" | "Raw" | "RawV2"))
        .map(|(k, v)| (crate::gitleaks::camel_to_snake_pub(&k), v))
        .collect();

    let mut extra_data: Map = Map::new();
    extra_data.insert("subtype".into(), Value::String(subtype.clone()));
    extra_data.insert("detector_data".into(), Value::Object(detector_data));
    for (k, v) in &data_map {
        extra_data.insert(k.clone(), v.clone());
    }

    // Compose `match`: `<repo>/<file>:<line>` or just `<link>` when present.
    let file = data_map.get("file").and_then(|v| v.as_str()).unwrap_or("");
    let line_no = data_map
        .get("line")
        .and_then(|v| v.as_i64().map(|i| i.to_string()).or_else(|| v.as_str().map(str::to_string)))
        .unwrap_or_default();
    let link = data_map.get("link").and_then(|v| v.as_str()).unwrap_or("");
    let mut repo_path = data_map
        .get("repository")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(stripped) = repo_path.strip_prefix("file://") {
        repo_path = stripped.to_string();
    }
    let mut matched = String::new();
    if !file.is_empty() {
        matched.push_str(file);
    }
    if !line_no.is_empty() {
        matched.push(':');
        matched.push_str(&line_no);
    }
    if !link.is_empty() {
        matched = link.to_string();
    }
    if !repo_path.is_empty() && subtype != "github" {
        matched = format!("{repo_path}/{matched}");
    }
    // (Python falls back to inputs[0] when nothing matched; we don't have it
    //  cheaply here — leave empty. The Tag still has rule + extra_data.)

    // Detector + resource type compose the tag name.
    let rtype = item
        .get("ExtraData")
        .and_then(|v| v.get("resource_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut name = rule_id.to_lowercase();
    if !rtype.is_empty() {
        name.push('_');
        name.push_str(&rtype.to_lowercase().replace(' ', "_"));
    }

    vec![OutputItem::Tag(Tag {
        category: "secret".into(),
        name,
        value: raw,
        match_: matched,
        extra_data,
        ..Default::default()
    })]
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // ProfileSecret has no HTTP knobs — all meta opts are not supported.
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Per-mode renames (Python `opt_key_map`).
    for (rust, flag) in [
        ("jenkins_username", "username"),
        ("jenkins_password", "password"),
        ("postman_collection_id", "collection-id"),
        ("postman_token", "token"),
        ("postman_workspace_id", "workspace-id"),
        ("git_branch", "branch"),
        ("git_depth", "depth"),
        ("git_since_commit", "since-commit"),
        ("git_max_depth", "max-depth"),
        ("gitlab_token", "token"),
        ("gitlab_endpoint", "endpoint"),
        ("elasticsearch_nodes", "nodes"),
        ("elasticsearch_service_token", "service-token"),
        ("elasticsearch_cloud_id", "cloud-id"),
        ("elasticsearch_api_key", "api-key"),
        ("status", "results"),
    ] {
        s.key_map.insert(rust.into(), KeyMap::Flag(flag.into()));
    }
    s.opts = vec![
        OptSpec {
            name: "mode",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Scan mode (auto-detected when omitted)",
            internal: true,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "status",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Results filter (verified, unknown, unverified, filtered_unverified)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "concurrency",
            ty: OptType::Int,
            short: None,
            is_flag: false,
            default: None,
            help: "Concurrent workers",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "config",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Config file path",
            internal: false,
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

    #[test]
    fn on_cmd_injects_mode_for_git_repo() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let input = tmp.path().to_string_lossy().into_owned();
        let mut ctx = HookCtx::default();
        ctx.state.insert("trufflehog:input".into(), input.clone());
        let mut cmd = format!("trufflehog --json {input}");
        on_cmd_mode_autodetect(&mut ctx, &mut cmd);
        assert!(cmd.contains("trufflehog git"));
        assert!(cmd.contains(&format!("file://{input}")));
    }

    #[test]
    fn on_cmd_filesystem_for_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().to_string_lossy().into_owned();
        let mut ctx = HookCtx::default();
        ctx.state.insert("trufflehog:input".into(), input.clone());
        let mut cmd = format!("trufflehog --json {input}");
        on_cmd_mode_autodetect(&mut ctx, &mut cmd);
        assert!(cmd.contains("trufflehog filesystem"));
    }

    #[test]
    fn on_cmd_github_repo_rewrites_input() {
        let mut ctx = HookCtx::default();
        ctx.state.insert(
            "trufflehog:input".into(),
            "https://github.com/owner/name".into(),
        );
        let mut cmd = "trufflehog --json https://github.com/owner/name".to_string();
        on_cmd_mode_autodetect(&mut ctx, &mut cmd);
        assert!(cmd.contains("trufflehog github"));
        assert!(cmd.contains("--repo owner/name"));
    }

    fn map_from(v: Value) -> Map {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn on_json_loaded_emits_info_for_log_lines() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({"level": "info", "msg": "starting scan", "time": "now"})),
        );
        assert!(matches!(out.first(), Some(OutputItem::Info(_))));
    }

    #[test]
    fn on_json_loaded_emits_tag_for_secret() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(
            &mut ctx,
            map_from(json!({
                "DetectorName": "AWS",
                "Raw": "AKIA1234567890ABCDEF",
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {"file": "/etc/foo", "line": 12}
                    }
                }
            })),
        );
        assert_eq!(out.len(), 1);
        if let Some(OutputItem::Tag(t)) = out.first() {
            assert_eq!(t.category, "secret");
            assert_eq!(t.value, "AKIA1234567890ABCDEF");
            assert!(t.match_.ends_with("/etc/foo:12"));
        } else {
            panic!("expected Tag");
        }
    }
}
