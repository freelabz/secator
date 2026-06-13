//! arjun — HTTP parameter discovery (Python `secator/tasks/arjun.py`).
//!
//! arjun writes its findings to a JSON file we point to with `-oJ`. The file
//! shape is `{<url>: {method, headers, params: [...]}, ...}`. For each entry
//! we emit:
//!   * one `Url(verified=true)` for the base URL,
//!   * one `Tag(category=info, name=url_param)` per discovered parameter,
//!   * one extra `Url` per parameter with `?<param>=` so downstream fuzzers can
//!     pivot on the parameter shape.
//!
//! `on_cmd` swaps Python's `--follow-redirect` toggle into `--disable-redirects`
//! when the user opted out (arjun has no positive flag), then appends `-oJ`.
//! `on_line` drops the `Processing chunks` progress noise.

use std::fs;

use secator_model::{Info, OutputItem, Tag, Url, Warning};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode, ValueMap,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "arjun",
    description: "HTTP parameter discovery suite.",
    cmd: "arjun",
    input_types: &["url"],
    output_types: &["url", "tag"],
    tags: &["url", "fuzz", "params"],
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-i") },
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
        version: Some("2.2.7"),
        cmd: Some("pipx install arjun==[install_version] --force"),
        github_handle: Some("s0md3v/Arjun"),
        github_bin: false,
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_capture_output_path],
    on_cmd: &[on_cmd_redirects_and_output],
    on_line: &[on_line_drop_progress],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

/// Stash the operator's `output_path` opt into ctx.state so `on_cmd` (which
/// doesn't get runner access) can honor it. Otherwise the default
/// `<reports>/.outputs/arjun.json` is used.
fn before_init_capture_output_path(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(p) = runner.opts.get("output_path").cloned().filter(|s| !s.is_empty()) {
        ctx.state.insert("arjun:user_output_path".into(), p);
    }
}

/// Python `on_cmd`: arjun has `--disable-redirects` (negation) not a positive
/// `--follow-redirect`. The key-map adds `--follow-redirect` when the user
/// supplied `true`; we strip it and substitute `--disable-redirects` when the
/// user actually wants redirects off. Then append `-oJ <path>`.
fn on_cmd_redirects_and_output(ctx: &mut HookCtx, cmd: &mut String) {
    let user_wants_redirects = cmd.contains(" --follow-redirect");
    *cmd = cmd.replace(" --follow-redirect", "");
    if !user_wants_redirects {
        cmd.push_str(" --disable-redirects");
    }
    let path = if let Some(p) = ctx.state.get("arjun:user_output_path").cloned() {
        if let Some(parent) = std::path::Path::new(&p).parent() {
            let _ = fs::create_dir_all(parent);
        }
        p
    } else {
        let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
        let outputs_dir = if reports.is_empty() {
            "/tmp".to_string()
        } else {
            format!("{reports}/.outputs")
        };
        let _ = fs::create_dir_all(&outputs_dir);
        format!("{outputs_dir}/arjun.json")
    };
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -oJ {quoted}"));
    ctx.state.insert("arjun:output_path".into(), path);
}

/// Python `on_line`: arjun spams "Processing chunks" progress noise. Drop it.
fn on_line_drop_progress(_ctx: &mut HookCtx, line: &str) -> Option<String> {
    if line.contains("Processing chunks") {
        None
    } else {
        Some(line.to_string())
    }
}

/// Python `on_cmd_done`: read the JSON file and walk each URL's
/// `{method, headers, params}` block.
fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("arjun:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        // Python silences a missing file (an empty result set); we do the same.
        Err(_) => return Vec::new(),
    };
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Value::Object(obj) = parsed else {
        return vec![OutputItem::Warning(Warning {
            message: "arjun: results file is not a JSON object".into(),
            ..Default::default()
        })];
    };
    if obj.is_empty() {
        return vec![OutputItem::Warning(Warning {
            message: "No results found !".into(),
            ..Default::default()
        })];
    }
    let mut out = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    for (url, values) in obj {
        let parsed_url = match UrlParser::parse(&url) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let host = parsed_url.host_str().unwrap_or("").to_string();
        let mut without_query = parsed_url.clone();
        without_query.set_query(None);
        let url_without_param = without_query.to_string();
        let method = values
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let request_headers = values
            .get("headers")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        out.push(OutputItem::Url(Url {
            url: url.clone(),
            host: host.clone(),
            request_headers: request_headers.clone(),
            method: method.clone(),
            confidence: "high".into(),
            verified: true,
            tags: vec!["fuzz".into()],
            ..Default::default()
        }));
        let params = values
            .get("params")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for param in params {
            let name = match param.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "url_param".into(),
                value: name.clone(),
                match_: url_without_param.clone(),
                ..Default::default()
            }));
            out.push(OutputItem::Url(Url {
                url: format!("{url_without_param}?{name}="),
                host: host.clone(),
                request_headers: request_headers.clone(),
                method: method.clone(),
                confidence: "high".into(),
                verified: true,
                tags: vec!["fuzz".into()],
                ..Default::default()
            }));
        }
    }
    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for (canon, flag) in [
        ("threads", "t"), ("delay", "d"), ("timeout", "T"),
        ("rate_limit", "rate-limit"), ("method", "m"),
        ("header", "headers"), ("follow_redirect", "follow-redirect"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    for k in ["data", "user_agent", "retries"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Python opt_value_map[HEADER]: `;;`-joined headers → arjun's `\n` form.
    s.value_map.insert("header".into(), ValueMap::Func(headers_to_arjun));
    s.opts = vec![
        // Canonical output_path meta opt — see `meta_opts::OUTPUT_PATH`. Marked
        // NotSupported below; honored via `before_init_capture_output_path`.
        meta_opts::OUTPUT_PATH,
        int_opt("chunk_size", Some("c"), "Control query/chunk size"),
        flag("stable", None, "Use stable mode"),
        str_opt("include", None, "Persistent data (e.g. 'api_key=xxx')"),
        flag("passive", None, "Passive mode"),
        str_opt(
            "casing",
            None,
            "Param casing style: like_this, likeThis, LIKE_THIS, like-this",
        ),
        str_opt("wordlist", Some("w"), "Wordlist to use"),
    ];
    s.key_map.insert("chunk_size".into(), KeyMap::Flag("c".into()));
    s.key_map.insert("wordlist".into(), KeyMap::Flag("w".into()));
    s.key_map.insert("output_path".into(), KeyMap::NotSupported);
    s
}

/// Python `opt_value_map[HEADER]`: take secator's `;;`-joined header form
/// (`K1:V1;;K2:V2`) and rewrite it to arjun's `\n`-joined form.
fn headers_to_arjun(v: &str) -> Option<String> {
    Some(
        v.split(";;")
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
            .join("\\n"),
    )
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn int_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Int, short, is_flag: false, default: None,
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
    fn on_line_drops_progress_noise() {
        let mut ctx = HookCtx::default();
        assert!(on_line_drop_progress(&mut ctx, "Processing chunks ...").is_none());
        assert_eq!(
            on_line_drop_progress(&mut ctx, "Found 3 parameters"),
            Some("Found 3 parameters".to_string())
        );
    }

    #[test]
    fn on_cmd_swaps_follow_redirect_to_disable_when_off() {
        let mut ctx = HookCtx::default();
        let mut cmd = "arjun -u https://x".to_string();
        on_cmd_redirects_and_output(&mut ctx, &mut cmd);
        assert!(cmd.contains("--disable-redirects"));
        assert!(cmd.contains("-oJ "));
    }

    #[test]
    fn on_cmd_strips_follow_redirect_when_explicitly_on() {
        let mut ctx = HookCtx::default();
        let mut cmd = "arjun --follow-redirect -u https://x".to_string();
        on_cmd_redirects_and_output(&mut ctx, &mut cmd);
        assert!(!cmd.contains("--follow-redirect"));
        assert!(!cmd.contains("--disable-redirects"));
    }

    #[test]
    fn on_cmd_done_parses_results_to_url_and_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("arjun.json");
        let body = r#"{
            "https://x/api": {
                "method": "GET",
                "headers": {"User-Agent": "x"},
                "params": ["q", "page"]
            }
        }"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("arjun:output_path".into(), path.to_string_lossy().into_owned());
        let items = on_cmd_done_parse(&mut ctx);
        let urls: Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Url(u) => Some(u), _ => None }).collect();
        let tags: Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None }).collect();
        // 1 base URL + 1 URL per param = 3.
        assert_eq!(urls.len(), 3);
        // 1 Tag per param.
        assert_eq!(tags.len(), 2);
        assert!(tags.iter().all(|t| t.name == "url_param"));
        // Param URLs have the `?<name>=` form.
        assert!(urls.iter().any(|u| u.url.contains("?q=")));
        assert!(urls.iter().any(|u| u.url.contains("?page=")));
    }

    #[test]
    fn headers_to_arjun_joins_with_backslash_n() {
        assert_eq!(
            headers_to_arjun("User-Agent: x;;Accept: */*").as_deref(),
            Some("User-Agent: x\\nAccept: */*"),
        );
    }
}
