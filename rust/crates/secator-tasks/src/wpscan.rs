//! wpscan — WordPress security scanner (Python `secator/tasks/wpscan.py`).
//!
//! wpscan writes a single JSON document via `-o <file>`. After the subprocess
//! exits, `on_cmd_done` parses it and emits, in order:
//!   * `Error` if the scan aborted;
//!   * a `Vulnerability` for an outdated WordPress core version;
//!   * a `Tag(category=info, name=wordpress_theme)` for the active theme +
//!     a `Vulnerability` when the theme is outdated;
//!   * one `Vulnerability` per entry in `interesting_findings`;
//!   * for each plugin in `plugins`: a `Tag(name=wordpress_plugin)` plus an
//!     outdated-plugin `Vulnerability` when version < latest_version.

use std::fs;

use secator_model::{Error, Info, Map, OutputItem, Tag, Vulnerability, Warning};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode, ValueMap,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "wpscan",
    description: "WordPress security scanner.",
    cmd: "wpscan --force --verbose",
    input_types: &["url", "host", "ip"],
    output_types: &["vulnerability", "tag"],
    tags: &["vuln", "scan", "wordpress"],
    json_flag: Some("-f json"),
    input_wiring: InputWiring { single: SingleMode::Flag("--url"), file: FileMode::Unsupported },
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
        version: Some("v3.8.28"),
        cmd: Some("gem install wpscan -v [install_version_strip] --user-install -n $HOME/.local/bin"),
        github_handle: Some("wpscanteam/wpscan"),
        github_bin: false,
        cmd_pre: &[
            ("apt", &["make", "kali:libcurl4t64", "libffi-dev"]),
            ("pacman", &["make", "ruby-erb"]),
            ("*", &["make"]),
        ],
        post: &[(
            "kali",
            "gem uninstall nokogiri --user-install -n $HOME/.local/bin --force --executables && gem install nokogiri --user-install -n $HOME/.local/bin --platform=ruby",
        )],
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
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

/// Python `on_init`: append `-o <reports_folder>/.outputs/wpscan.json`. We do
/// it in `on_cmd` (fires after the cmd is assembled) and stash the path.
fn on_cmd_inject_output(ctx: &mut HookCtx, cmd: &mut String) {
    let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
    let dir = if reports.is_empty() {
        "/tmp".to_string()
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&dir);
    let path = format!("{dir}/wpscan.json");
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -o {quoted}"));
    ctx.state.insert("wpscan:output_path".into(), path);
}

/// Python `on_cmd_done` — read the JSON file and emit derived items.
fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("wpscan:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(_) => {
            // wpscan skips its JSON output when the target isn't a WordPress
            // site (or when scanning is refused). Treat as a Warning so the
            // run status stays SUCCESS.
            return vec![OutputItem::Warning(Warning {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })]
        }
    };
    let data: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];
    let target = data
        .get("target_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Scan aborted → Error short-circuit.
    if let Some(reason) = data.get("scan_aborted").and_then(|v| v.as_str()) {
        if !reason.is_empty() {
            let trace = data
                .get("trace")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            out.push(OutputItem::Error(Error {
                message: reason.to_string(),
                traceback: trace,
                ..Default::default()
            }));
            return out;
        }
    }

    // Outdated WP core version → Vulnerability.
    if let Some(version) = data.get("version").and_then(|v| v.as_object()) {
        let number = version
            .get("number")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let status = version.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status == "outdated" {
            out.push(OutputItem::Vulnerability(Vulnerability {
                name: "Wordpress outdated version".into(),
                matched_at: target.clone(),
                confidence: "high".into(),
                severity: "info".into(),
                tags: vec![number.clone()],
                provider: "wpscan".into(),
                ..Default::default()
            }));
        }
    }

    // Main theme → Tag + (optional) Vulnerability.
    if let Some(theme) = data.get("main_theme").and_then(|v| v.as_object()) {
        if let Some(version) = theme.get("version").and_then(|v| v.as_object()) {
            let number = version
                .get("number")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let slug = theme.get("slug").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let location = theme.get("location").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let latest = theme
                .get("latest_version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mut extra = Map::new();
            extra.insert("url".into(), Value::String(location));
            extra.insert("latest_version".into(), Value::String(latest.clone()));
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "wordpress_theme".into(),
                match_: target.clone(),
                value: format!("{slug}:{number}"),
                extra_data: extra,
                ..Default::default()
            }));
            if is_outdated(&number, &latest) {
                out.push(OutputItem::Vulnerability(Vulnerability {
                    matched_at: target.clone(),
                    name: format!("Wordpress theme - {slug} {number} outdated"),
                    description: format!(
                        "The wordpress theme {slug} is outdated, consider updating to the latest version {latest}"
                    ),
                    confidence: "high".into(),
                    severity: "info".into(),
                    tags: vec!["wordpress".into(), "wordpress_theme".into()],
                    provider: "wpscan".into(),
                    ..Default::default()
                }));
            }
        }
    }

    // Interesting findings → Vulnerability each (just lift `name`/`url` for now).
    if let Some(findings) = data.get("interesting_findings").and_then(|v| v.as_array()) {
        for f in findings {
            let url_field = f.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let to_s = f.get("to_s").and_then(|v| v.as_str()).unwrap_or("");
            let kind = f.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let confidence = match f.get("confidence").and_then(|v| v.as_i64()) {
                Some(c) if c == 100 => "high",
                _ => "low",
            }
            .to_string();
            let references = f
                .get("references")
                .and_then(|r| r.get("url"))
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default();
            let mut extra = Map::new();
            extra.insert(
                "data".into(),
                f.get("interesting_entries").cloned().unwrap_or(Value::Array(Vec::new())),
            );
            extra.insert(
                "found_by".into(),
                f.get("found_by").cloned().unwrap_or(Value::String(String::new())),
            );
            out.push(OutputItem::Vulnerability(Vulnerability {
                matched_at: if url_field.is_empty() { target.clone() } else { url_field },
                name: to_s.split(':').next().unwrap_or(to_s).to_string(),
                confidence,
                severity: "info".into(),
                tags: vec![kind],
                references,
                extra_data: extra,
                provider: "wpscan".into(),
                ..Default::default()
            }));
        }
    }

    // Plugins → Tag (+ Vulnerability if outdated).
    if let Some(plugins) = data.get("plugins").and_then(|v| v.as_object()) {
        for (_key, plugin) in plugins {
            let version = plugin
                .get("version")
                .and_then(|v| v.as_object());
            let slug = plugin.get("slug").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let location = plugin
                .get("location")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let Some(version) = version else { continue };
            let number = version
                .get("number")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let latest = plugin
                .get("latest_version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mut extra = Map::new();
            extra.insert("url".into(), Value::String(location));
            extra.insert("name".into(), Value::String(slug.clone()));
            extra.insert("version".into(), Value::String(number.clone()));
            extra.insert("latest_version".into(), Value::String(latest.clone()));
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "wordpress_plugin".into(),
                match_: target.clone(),
                value: format!("{slug}:{number}"),
                extra_data: extra,
                ..Default::default()
            }));
            if is_outdated(&number, &latest) {
                out.push(OutputItem::Vulnerability(Vulnerability {
                    matched_at: target.clone(),
                    name: format!("Wordpress plugin - {slug} {number} outdated"),
                    description: format!(
                        "The wordpress plugin {slug} is outdated, consider updating to the latest version {latest}."
                    ),
                    confidence: "high".into(),
                    severity: "info".into(),
                    tags: vec!["wordpress".into(), "wordpress_plugin".into()],
                    provider: "wpscan".into(),
                    ..Default::default()
                }));
            }
        }
    }
    out
}

/// Best-effort version comparison (Python `parse_version` parity for the
/// common dotted-numeric case). Returns true when `current < latest` AND both
/// are non-empty and `latest != "unknown"`.
fn is_outdated(current: &str, latest: &str) -> bool {
    if latest.is_empty() || latest == "unknown" || current.is_empty() {
        return false;
    }
    parse_dotted(current) < parse_dotted(latest)
}

fn parse_dotted(s: &str) -> Vec<i64> {
    s.split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<i64>().ok())
        .collect()
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = meta_opts::opts_http_base()
        .into_iter()
        .filter(|o| matches!(o.name, "proxy" | "delay" | "timeout" | "threads" | "user_agent"))
        .collect();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    s.key_map.insert("delay".into(), KeyMap::Flag("throttle".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("request-timeout".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("max-threads".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("user_agent".into(), KeyMap::Flag("user-agent".into()));
    for k in ["header", "follow_redirect", "rate_limit", "retries"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Python `opt_value_map[DELAY] = lambda x: x * 1000` (seconds → ms).
    s.value_map.insert("delay".into(), ValueMap::Func(s_to_ms));
    s.opts = vec![
        str_opt("cookie_string", Some("cookie"), "Cookie string (cookie1=value1;...)"),
        str_opt("api_token", Some("token"), "WPScan API token"),
        str_opt("wp_content_dir", Some("wcd"), "Custom wp-content dir"),
        str_opt("wp_plugins_dir", Some("wpd"), "Custom wp-plugins dir"),
        str_opt("passwords", None, "Password list for the password attack"),
        str_opt("usernames", None, "Username list for the password attack"),
        str_opt("login_uri", Some("lu"), "Login URI if not /wp-login.php"),
        str_opt("detection_mode", Some("dm"), "mixed | passive | aggressive"),
        flag("random_user_agent", Some("rua"), "Random user agent"),
        flag("disable_tls_checks", Some("dtc"), "Disable TLS checks"),
    ];
    s
}

fn s_to_ms(v: &str) -> Option<String> {
    v.parse::<f64>().ok().map(|s| ((s * 1000.0) as i64).to_string())
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

    fn run_with_body(body: &str) -> Vec<OutputItem> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wpscan.json");
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("wpscan:output_path".into(), path.to_string_lossy().into_owned());
        on_cmd_done_parse(&mut ctx)
    }

    /// wpscan against a non-WordPress target skips its JSON output — we
    /// must emit a Warning (not an Error) so the run stays SUCCESS.
    #[test]
    fn missing_json_file_emits_warning_not_error() {
        let mut ctx = HookCtx::default();
        ctx.state.insert(
            "wpscan:output_path".into(),
            "/nonexistent/path/wpscan.json".into(),
        );
        let out = on_cmd_done_parse(&mut ctx);
        assert_eq!(out.len(), 1);
        assert!(
            matches!(&out[0], OutputItem::Warning(w) if w.message.contains("Could not find JSON results")),
            "expected a Warning for missing JSON, got {:?}",
            out[0]
        );
        assert!(!out.iter().any(|i| matches!(i, OutputItem::Error(_))));
    }

    #[test]
    fn version_status_outdated_emits_vulnerability() {
        let body = r#"{"target_url":"https://x","version":{"number":"5.0","status":"outdated"}}"#;
        let out = run_with_body(body);
        let v = out
            .iter()
            .find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None })
            .expect("expected outdated-version Vulnerability");
        assert_eq!(v.name, "Wordpress outdated version");
        assert_eq!(v.matched_at, "https://x");
    }

    #[test]
    fn plugin_emits_tag_and_outdated_vulnerability() {
        let body = r#"{
            "target_url": "https://x",
            "plugins": {
                "foo": {
                    "slug": "foo",
                    "location": "https://x/wp-content/plugins/foo/",
                    "version": {"number": "1.0.0"},
                    "latest_version": "1.2.0"
                }
            }
        }"#;
        let out = run_with_body(body);
        let tag = out.iter().find_map(|i| match i { OutputItem::Tag(t) if t.name == "wordpress_plugin" => Some(t), _ => None }).unwrap();
        assert_eq!(tag.value, "foo:1.0.0");
        let v = out.iter().find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None }).unwrap();
        assert!(v.name.contains("foo 1.0.0 outdated"));
        assert!(v.tags.contains(&"wordpress_plugin".to_string()));
    }

    #[test]
    fn scan_aborted_emits_error_and_stops() {
        let body = r#"{"target_url":"https://x","scan_aborted":"target unreachable"}"#;
        let out = run_with_body(body);
        assert!(out.iter().any(|i| matches!(i, OutputItem::Error(_))));
        // Outdated-version Vulnerability should NOT appear after the abort.
        assert!(out.iter().all(|i| !matches!(i, OutputItem::Vulnerability(_))));
    }

    #[test]
    fn version_compare_detects_outdated() {
        assert!(is_outdated("1.0.0", "1.2.0"));
        assert!(!is_outdated("1.2.0", "1.2.0"));
        assert!(!is_outdated("2.0.0", "1.9.0"));
        assert!(!is_outdated("1.0.0", "unknown"));
        assert!(!is_outdated("", "1.0.0"));
    }
}
