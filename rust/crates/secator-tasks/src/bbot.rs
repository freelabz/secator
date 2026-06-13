//! bbot — black-lantern security's multipurpose scanner (Python
//! `secator/tasks/bbot.py`).
//!
//! bbot streams one JSON line per event. We mirror Python's discriminator +
//! `on_json_loaded` end-to-end: detect the event type, capture SCAN config
//! (carries `preset.modules` for `extra_data.bbot_modules`), parse the
//! `description` regex (`Name: [value]` pairs flattened into `extra_data`),
//! resolve the right item `name`, then emit one typed `OutputItem`.
//!
//! WEBSCREENSHOT events also trigger a file copy: bbot writes the PNG under
//! `~/.bbot/scans/<scan_name>/<relative_path>`; we copy it into
//! `<reports_folder>/.outputs/<basename>` and rewrite the `screenshot_path`
//! field to the local copy so the report tree is self-contained (matches
//! Python's `on_json_loaded` shutil.copyfile branch). When `reports_folder`
//! isn't set or the source file is missing, we keep the original path so
//! operators can still locate it.

use std::sync::OnceLock;

use regex::Regex;
use secator_model::{
    Error, Ip, Map, OutputItem, Port, Record, Tag, Url, UserAccount, Vulnerability, Warning,
};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
// `secator_debug::debug!` is invoked unqualified-import-style via the macro path —
// the macro lives in `secator-debug` and is already a dep through the workspace.
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "bbot",
    description: "BlackLanternSecurity multipurpose scanner.",
    cmd: "bbot -y --allow-deadly --force",
    // Python `input_types = [HOST, IP, URL, PORT, ORG_NAME, USERNAME, FILENAME]`.
    // `port` / `org_name` / `filename` aren't first-class Rust input types yet —
    // we use the closest equivalents (`host_port`, `string`, `path`).
    input_types: &["host", "ip", "url", "host_port", "string", "username", "path"],
    output_types: &[
        "vulnerability", "port", "url", "record", "ip", "tag", "user_account",
    ],
    tags: &["vuln", "scan"],
    json_flag: Some("--json"),
    // Python `input_flag = '-t'`, `file_flag = None`. Multi-target via repeated
    // `-t` would be possible, but Python falls back to one-input-per-subprocess
    // chunking, so we do the same.
    input_wiring: InputWiring { single: SingleMode::Flag("-t"), file: FileMode::Unsupported },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("2.7.2"),
        cmd: Some("pipx install bbot==[install_version] --force"),
        pre: &[
            ("apk", &[
                "python3-dev", "linux-headers", "musl-dev", "gcc", "git",
                "openssl", "unzip", "tar", "chromium",
            ]),
            ("*", &["gcc", "git", "openssl", "unzip", "tar", "chromium"]),
        ],
        post: &[(
            "*",
            "rm -fr $HOME/.local/share/pipx/venvs/bbot/lib/python3.12/site-packages/ansible_collections/*",
        )],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

/// Python `BBOT_MAP_TYPES`. Returns the canonical Rust `output_types` name.
fn map_bbot_type(t: &str) -> Option<&'static str> {
    match t {
        "IP_ADDRESS" => Some("ip"),
        "PROTOCOL" | "OPEN_TCP_PORT" => Some("port"),
        "URL" | "URL_HINT" | "WEBSCREENSHOT" => Some("url"),
        "ASN" | "DNS_NAME" => Some("record"),
        "VULNERABILITY" => Some("vulnerability"),
        "EMAIL_ADDRESS" => Some("user_account"),
        "FINDING" | "AZURE_TENANT" | "STORAGE_BUCKET" | "TECHNOLOGY" => Some("tag"),
        _ => None,
    }
}

/// `Name: [Value, Value2]` description regex (Python `BBOT_DESCRIPTION_REGEX`).
fn description_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?P<name>[\w ]+): \[(?P<value>[^\[\]]+)\]").unwrap())
}

/// Strip the trailing `( ... )` / `. ...` / `Detected. ...` clauses a bbot
/// description carries (Python `re.split(r'\s*(\(|\.|Detected.)', ...)`).
fn description_regex_tail() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s*(\(|\.|Detected.)").unwrap())
}

/// `extract_status_code` + `extract_title`: scan the bbot `tags` array for
/// `status-NNN` / `http-title-...` markers.
fn extract_status_code(tags: &[Value]) -> i64 {
    for t in tags {
        if let Some(s) = t.as_str() {
            if let Some(num) = s.strip_prefix("status-") {
                return num.parse().unwrap_or(0);
            }
        }
    }
    0
}
fn extract_title(tags: &[Value]) -> String {
    for t in tags {
        if let Some(s) = t.as_str() {
            if let Some(rest) = s.strip_prefix("http-title-") {
                return rest.replace('-', " ");
            }
        }
    }
    String::new()
}

/// Replace each space in `key` with `_` and lowercase (Python `_'.join(...).lower()`).
fn snake_key(key: &str) -> String {
    key.split_whitespace().collect::<Vec<_>>().join("_").to_lowercase()
}

/// Title-case for the type-derived name (e.g. `AZURE_TENANT` → `Azure Tenant`).
fn title_case_type(t: &str) -> String {
    t.split('_')
        .map(|word| {
            let mut c = word.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Pull resolved_hosts as `Vec<String>` (filters out non-strings).
fn resolved_hosts(item: &Map) -> Vec<String> {
    item.get("resolved_hosts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Python `BBOT_MAP_TYPES` + the heavy `on_json_loaded`. Returns a single typed
/// item per event (or a Warning / Error for malformed inputs).
pub fn on_json_loaded(ctx: &mut HookCtx, mut item: Map) -> Vec<OutputItem> {
    let event_type = item.get("type").and_then(|v| v.as_str()).map(String::from);
    let message = item.get("message").and_then(|v| v.as_str()).map(String::from);

    // Python: `if not _type and message → yield Error`.
    let Some(etype) = event_type else {
        if let Some(m) = message {
            return vec![OutputItem::Error(Error {
                message: m,
                ..Default::default()
            })];
        }
        return Vec::new();
    };

    // SCAN events carry the preset / module list. Capture for later events.
    if etype == "SCAN" {
        if let Some(d) = item.get("data") {
            if let Ok(s) = serde_json::to_string(d) {
                ctx.state.insert("bbot:scan_config".into(), s);
            }
        }
        return Vec::new();
    }

    let Some(target_type) = map_bbot_type(&etype) else {
        return vec![OutputItem::Warning(Warning {
            message: format!("Found unsupported bbot type: {etype}. Skipping."),
            ..Default::default()
        })];
    };

    let module = item.get("module").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let source = if module.is_empty() {
        "bbot".to_string()
    } else {
        format!("bbot-{module}")
    };
    let tags = item.get("tags").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let hosts = resolved_hosts(&item);
    let discovery_context = item
        .get("discovery_context")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Pull scan_name + reports_outputs from ctx state for the WEBSCREENSHOT branch.
    let (scan_name, reports_outputs) = derive_paths_from_ctx(ctx);

    // ----- Simple-data path: `item["data"]` is a string (ASN/DNS_NAME). Python
    // just sets `name = data` and yields the item as-is.
    let data_value = item.remove("data").unwrap_or(Value::Null);
    let data_is_str = matches!(data_value, Value::String(_));
    if data_is_str {
        let name = data_value.as_str().unwrap_or("").to_string();
        return emit_typed(
            target_type,
            BuiltEvent {
                name,
                data_str: data_value.as_str().map(String::from),
                data_obj: None,
                extra_data: Map::new(),
                tags,
                hosts,
                source,
                event_type: etype,
                scan_name,
                reports_outputs,
                queued_info: Vec::new(),
            },
        );
    }

    // ----- Dict-data path: stash `data` as `extra_data`, augment with bbot
    // modules, parse description, derive name.
    let mut data_obj = data_value.as_object().cloned().unwrap_or_default();
    let mut extra_data = data_obj.clone();
    if let Some(cfg_str) = ctx.state.get("bbot:scan_config") {
        if let Ok(cfg) = serde_json::from_str::<Value>(cfg_str) {
            let modules = cfg
                .get("preset")
                .and_then(|p| p.get("modules"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            extra_data.insert("bbot_modules".into(), modules);
        }
    }

    // Description regex: collect Name: [value] pairs, drop description from
    // data when at least one pair landed.
    let raw_desc = data_obj
        .get("description")
        .and_then(|v| v.as_str())
        .map(String::from);
    let mut cleaned_desc: Option<String> = None;
    if let Some(desc) = &raw_desc {
        let head = match desc.split_once(':') {
            Some((h, _)) if !desc[h.len() + 1..].contains(':') => h.trim().to_string(),
            _ => desc.clone(),
        };
        let mut matched = false;
        for cap in description_regex().captures_iter(&head) {
            matched = true;
            let key = cap.name("name").map(|m| m.as_str().trim()).unwrap_or("");
            let val = cap.name("value").map(|m| m.as_str().trim()).unwrap_or("");
            let snake = snake_key(key);
            let value: Value = if val.contains(',') {
                Value::Array(
                    val.split(',').map(|s| Value::String(s.trim().to_string())).collect(),
                )
            } else {
                Value::String(val.to_string())
            };
            extra_data.insert(snake, value);
        }
        if matched {
            data_obj.remove("description");
        }
        let trimmed = head.trim();
        let stripped = description_regex_tail()
            .split(trimmed)
            .next()
            .unwrap_or(trimmed)
            .trim_end()
            .to_string();
        if !stripped.is_empty() {
            cleaned_desc = Some(stripped);
        }
    }

    // Derive `name` per Python's branched logic.
    let mut name = String::new();
    let tech_keys = ["technology", "tenant-names", "url"];
    if matches!(etype.as_str(), "AZURE_TENANT" | "STORAGE_BUCKET" | "TECHNOLOGY") {
        name = title_case_type(&etype);
        // info = first matching key's value
        let info = tech_keys
            .iter()
            .find_map(|k| data_obj.get(*k).cloned());
        if let Some(v) = info {
            extra_data.insert("info".into(), v);
            for k in tech_keys {
                data_obj.remove(k);
                extra_data.remove(k);
            }
        }
    } else if let Some(n) = data_obj.get("name").and_then(|v| v.as_str()).map(String::from) {
        name = n;
        data_obj.remove("name");
        extra_data.remove("name");
    } else if let Some(n) = extra_data.get("name").and_then(|v| v.as_str()).map(String::from)
    {
        name = n;
        extra_data.remove("name");
    } else if let Some(d) = cleaned_desc.clone() {
        name = d;
        data_obj.remove("description");
    } else if !discovery_context.is_empty() {
        name = discovery_context.clone();
    }

    let _ = discovery_context; // name was set above when applicable
    emit_typed(
        target_type,
        BuiltEvent {
            name,
            data_str: None,
            data_obj: Some(data_obj),
            extra_data,
            tags,
            hosts,
            source,
            event_type: etype,
            scan_name,
            reports_outputs,
            queued_info: Vec::new(),
        },
    )
}

/// Copy a bbot screenshot into `<reports>/.outputs/<basename>` and return the
/// new path. Returns `Err(reason)` when any of: reports_folder is unset, the
/// source file doesn't exist, or fs::copy itself fails — caller falls back to
/// the original bbot path.
fn copy_screenshot(
    raw_path: &str,
    scan_name: &str,
    reports_outputs: &str,
) -> Result<String, String> {
    if reports_outputs.is_empty() {
        return Err("reports_folder not set on ctx".into());
    }
    // bbot's `data.path` is relative to `~/.bbot/scans/<scan_name>/` (the
    // canonical bbot layout). If it already looks absolute, use it as-is —
    // some bbot builds emit absolute paths.
    let src = if raw_path.starts_with('/') {
        std::path::PathBuf::from(raw_path)
    } else if scan_name.is_empty() {
        return Err(format!("no scan_name to resolve relative path {raw_path}"));
    } else {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "HOME not set".to_string())?;
        home.join(".bbot").join("scans").join(scan_name).join(raw_path)
    };
    if !src.exists() {
        return Err(format!("source file missing: {}", src.display()));
    }
    let basename = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "empty basename".to_string())?;
    let outputs_dir = std::path::PathBuf::from(reports_outputs);
    std::fs::create_dir_all(&outputs_dir)
        .map_err(|e| format!("mkdir {}: {e}", outputs_dir.display()))?;
    let dest = outputs_dir.join(basename);
    std::fs::copy(&src, &dest).map_err(|e| format!("copy {} → {}: {e}", src.display(), dest.display()))?;
    Ok(dest.to_string_lossy().into_owned())
}

/// Pull `scan_name` (from the stashed SCAN config) + `<reports>/.outputs/`
/// (from `HookCtx.state["reports_folder"]`) out of the hook context so the
/// URL branch can copy WEBSCREENSHOTs in.
fn derive_paths_from_ctx(ctx: &HookCtx) -> (String, String) {
    let scan_name = ctx
        .state
        .get("bbot:scan_config")
        .and_then(|cfg_str| serde_json::from_str::<Value>(cfg_str).ok())
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
        .unwrap_or_default();
    let reports_outputs = ctx
        .state
        .get("reports_folder")
        .map(|rf| format!("{}/.outputs", rf.trim_end_matches('/')))
        .unwrap_or_default();
    (scan_name, reports_outputs)
}

/// All the context build-up needed by per-type emitters.
struct BuiltEvent {
    name: String,
    /// If the bbot event's `data` was a plain string (ASN/DNS_NAME), this holds it.
    data_str: Option<String>,
    /// If the bbot event's `data` was an object, this holds the (possibly-pruned) copy.
    data_obj: Option<Map>,
    extra_data: Map,
    tags: Vec<Value>,
    hosts: Vec<String>,
    source: String,
    event_type: String,
    /// Scan name from the SCAN event (`ctx.state["bbot:scan_config"]`). Drives
    /// the WEBSCREENSHOT source-path resolution.
    scan_name: String,
    /// `<reports_folder>/.outputs/` (from `HookCtx.state["reports_folder"]`).
    /// Empty when the runner hasn't allocated a reports folder yet.
    reports_outputs: String,
    /// Extra Info items the URL branch may queue (e.g. screenshot-copied
    /// confirmation). Returned alongside the Url so the operator sees both.
    queued_info: Vec<OutputItem>,
}

/// Build the right OutputItem variant for the target type. Mirrors Python's
/// per-type `output_map` lambdas, but with direct field assignment instead of
/// going through the schema converter.
fn emit_typed(target_type: &str, ev: BuiltEvent) -> Vec<OutputItem> {
    let BuiltEvent {
        name, data_str, data_obj, extra_data, tags, hosts, source, event_type,
        scan_name, reports_outputs, mut queued_info,
    } = ev;
    let mut meta = secator_model::Meta::default();
    meta.source = source;

    let data_url = data_obj.as_ref().and_then(|o| o.get("url")).and_then(|v| v.as_str()).map(String::from);
    let data_host = data_obj.as_ref().and_then(|o| o.get("host")).and_then(|v| v.as_str()).map(String::from);
    let matched_at = data_url.clone().or(data_host.clone()).unwrap_or_default();

    match target_type {
        "ip" => {
            let ip = data_str.unwrap_or_default();
            vec![OutputItem::Ip(Ip {
                ip: ip.clone(),
                host: ip,
                alive: true,
                meta,
                ..Default::default()
            })]
        }

        "port" => {
            // Port number: data.port if dict, else int(data.split(':').last).
            let mut port_num: i64 = 0;
            let host;
            if let Some(obj) = &data_obj {
                port_num = obj.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                host = obj.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
            } else if let Some(s) = &data_str {
                if let Some((h, p)) = s.rsplit_once(':') {
                    port_num = p.parse().unwrap_or(0);
                    host = h.to_string();
                } else {
                    host = s.clone();
                }
            } else {
                host = String::new();
            }
            // ip = first non-`::*` resolved host.
            let ip = hosts.into_iter().find(|h| !h.starts_with("::")).unwrap_or_default();
            let service_name = data_obj
                .as_ref()
                .and_then(|o| o.get("protocol"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            vec![OutputItem::Port(Port {
                port: port_num,
                ip,
                state: "OPEN".into(),
                service_name,
                cpes: Vec::new(),
                host,
                extra_data,
                meta,
                ..Default::default()
            })]
        }

        "url" => {
            let url = data_url.clone().unwrap_or_else(|| data_str.clone().unwrap_or_default());
            let host = hosts.first().cloned().unwrap_or_default();
            let status_code = extract_status_code(&tags);
            let title = extract_title(&tags);
            let raw_screenshot = data_obj
                .as_ref()
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Copy WEBSCREENSHOT into <reports>/.outputs/ so report bundles are
            // self-contained (Python parity).
            let screenshot_path = if event_type == "WEBSCREENSHOT" && !raw_screenshot.is_empty() {
                match copy_screenshot(&raw_screenshot, &scan_name, &reports_outputs) {
                    Ok(dest) => {
                        queued_info.push(OutputItem::Info(secator_model::Info {
                            message: format!("Copied screenshot {raw_screenshot} → {dest}"),
                            ..Default::default()
                        }));
                        dest
                    }
                    Err(why) => {
                        // Soft-fail: keep the original path so the operator
                        // can still find it under ~/.bbot/scans/.
                        secator_debug::debug!("hooks.bbot", "screenshot copy skipped: {why}");
                        raw_screenshot
                    }
                }
            } else {
                raw_screenshot
            };
            let mut out = vec![OutputItem::Url(Url {
                url,
                host,
                status_code,
                title,
                screenshot_path,
                meta,
                ..Default::default()
            })];
            out.extend(queued_info);
            out
        }

        "record" => {
            // Records cover ASN/DNS_NAME. Name was set above (data_str path) or
            // computed via description.
            vec![OutputItem::Record(Record {
                name,
                type_: event_type,
                extra_data,
                meta,
                ..Default::default()
            })]
        }

        "vulnerability" => {
            let severity = data_obj
                .as_ref()
                .and_then(|o| o.get("severity"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| "unknown".into());
            vec![OutputItem::Vulnerability(Vulnerability {
                name,
                matched_at,
                extra_data,
                confidence: "high".into(),
                severity,
                meta,
                ..Default::default()
            })]
        }

        "user_account" => {
            let email = data_str.clone().unwrap_or_default();
            let username = email.split('@').next().unwrap_or("").to_string();
            let site_name = data_host.unwrap_or_default();
            vec![OutputItem::UserAccount(UserAccount {
                username,
                email,
                site_name,
                extra_data,
                meta,
                ..Default::default()
            })]
        }

        "tag" => {
            // category = event_type or "bbot"
            let category = if event_type.is_empty() { "bbot".into() } else { event_type };
            vec![OutputItem::Tag(Tag {
                name,
                category: category.to_lowercase(),
                match_: matched_at,
                extra_data,
                meta,
                ..Default::default()
            })]
        }

        _ => Vec::new(),
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_recon();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Python opts: modules (-m), presets (-ps → bbot -p), flags (-fl → bbot -f).
    s.opts = vec![
        OptSpec {
            name: "modules",
            ty: OptType::Str,
            short: Some("m"),
            is_flag: false,
            default: None,
            help: "Comma-separated bbot module list (-m)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "presets",
            ty: OptType::Str,
            short: Some("ps"),
            is_flag: false,
            default: None,
            help: "Comma-separated bbot preset list (-p, space-joined)",
            internal: false,
            requires_sudo: false,
            // shlex=False in Python — preset list goes through verbatim because
            // it's space-separated after the value transform.
            shlex: false,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "flags",
            ty: OptType::Str,
            short: Some("fl"),
            is_flag: false,
            default: None,
            help: "Comma-separated bbot flag list (-f)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    s.key_map.insert("modules".into(), KeyMap::Flag("m".into()));
    s.key_map.insert("presets".into(), KeyMap::Flag("p".into()));
    s.key_map.insert("flags".into(), KeyMap::Flag("f".into()));
    // Python opt_value_map: presets get comma → space.
    s.value_map.insert(
        "presets".into(),
        secator_options::ValueMap::Func(presets_join),
    );
    s
}

fn presets_join(v: &str) -> Option<String> {
    let v = v.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.split(',').map(str::trim).collect::<Vec<_>>().join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(item: Value) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        on_json_loaded(&mut ctx, item.as_object().unwrap().clone())
    }

    #[test]
    fn ip_address_emits_ip() {
        let out = run(json!({
            "type": "IP_ADDRESS",
            "data": "1.2.3.4",
            "module": "asn",
            "tags": [],
            "resolved_hosts": [],
            "discovery_context": "scan"
        }));
        assert_eq!(out.len(), 1);
        if let OutputItem::Ip(ip) = &out[0] {
            assert_eq!(ip.ip, "1.2.3.4");
            assert!(ip.alive);
            assert_eq!(ip.meta.source, "bbot-asn");
        } else { panic!() }
    }

    #[test]
    fn open_tcp_port_emits_port() {
        let out = run(json!({
            "type": "OPEN_TCP_PORT",
            "data": "10.0.0.1:443",
            "module": "portscan",
            "tags": [],
            "resolved_hosts": ["10.0.0.1", "::1"],
            "discovery_context": "scan"
        }));
        if let OutputItem::Port(p) = &out[0] {
            assert_eq!(p.port, 443);
            assert_eq!(p.host, "10.0.0.1");
            assert_eq!(p.ip, "10.0.0.1");
            assert_eq!(p.state, "OPEN");
        } else { panic!() }
    }

    #[test]
    fn url_with_tags_extracts_title_and_status() {
        let out = run(json!({
            "type": "URL",
            "data": {"url": "https://example.com/x", "host": "example.com"},
            "module": "httpx",
            "tags": ["status-200", "http-title-Welcome-Home"],
            "resolved_hosts": ["1.2.3.4"],
            "discovery_context": "scan"
        }));
        if let OutputItem::Url(u) = &out[0] {
            assert_eq!(u.url, "https://example.com/x");
            assert_eq!(u.status_code, 200);
            assert_eq!(u.title, "Welcome Home");
            assert_eq!(u.host, "1.2.3.4");
        } else { panic!() }
    }

    #[test]
    fn finding_emits_tag_with_description_parsed_into_extra() {
        // Python's BBOT_DESCRIPTION_REGEX matches the outer `Name: [value]`
        // pair as a whole — value is the entire `[...]` contents (commas
        // become a list). So `Origin: example.com, Method: POST` lands under
        // a single snake-cased key (the outer name).
        let out = run(json!({
            "type": "FINDING",
            "data": {
                "host": "example.com",
                "url": "https://example.com",
                "description": "Possible CORS misconfiguration: [Origin: example.com, Method: POST]"
            },
            "module": "cors",
            "tags": [],
            "resolved_hosts": ["1.2.3.4"],
            "discovery_context": "scan"
        }));
        assert_eq!(out.len(), 1);
        if let OutputItem::Tag(t) = &out[0] {
            assert_eq!(t.category, "finding");
            assert_eq!(t.match_, "https://example.com");
            // Outer pair captured under the snake-cased name.
            let arr = t
                .extra_data
                .get("possible_cors_misconfiguration")
                .and_then(|v| v.as_array())
                .expect(&format!("extras: {:?}", t.extra_data));
            assert_eq!(arr.len(), 2);
            // Description used as name (cleaned of trailing punctuation /
            // parenthetical).
            assert!(t.name.starts_with("Possible CORS misconfiguration"));
        } else { panic!() }
    }

    #[test]
    fn vulnerability_emits_with_lowercased_severity() {
        let out = run(json!({
            "type": "VULNERABILITY",
            "data": {"url": "https://x/v", "severity": "HIGH", "name": "RCE-2024"},
            "module": "nuclei",
            "tags": [],
            "resolved_hosts": ["1.2.3.4"],
            "discovery_context": "scan"
        }));
        if let OutputItem::Vulnerability(v) = &out[0] {
            assert_eq!(v.severity, "high");
            assert_eq!(v.matched_at, "https://x/v");
            assert_eq!(v.confidence, "high");
            assert_eq!(v.name, "RCE-2024");
        } else { panic!() }
    }

    #[test]
    fn email_emits_user_account() {
        let out = run(json!({
            "type": "EMAIL_ADDRESS",
            "data": "admin@example.com",
            "host": "example.com",
            "module": "emailformat",
            "tags": [],
            "resolved_hosts": [],
            "discovery_context": "scan"
        }));
        if let OutputItem::UserAccount(u) = &out[0] {
            assert_eq!(u.username, "admin");
            assert_eq!(u.email, "admin@example.com");
        } else { panic!() }
    }

    #[test]
    fn azure_tenant_extracts_info_field() {
        let out = run(json!({
            "type": "AZURE_TENANT",
            "data": {"tenant-names": ["contoso"], "host": "contoso.com"},
            "module": "azure_tenant",
            "tags": [],
            "resolved_hosts": [],
            "discovery_context": "scan"
        }));
        if let OutputItem::Tag(t) = &out[0] {
            assert_eq!(t.name, "Azure Tenant");
            assert_eq!(t.category, "azure_tenant");
            assert!(t.extra_data.contains_key("info"));
        } else { panic!() }
    }

    #[test]
    fn unsupported_type_yields_warning() {
        let out = run(json!({
            "type": "PYTHON_SECRET",
            "data": "foo",
            "module": "x",
            "tags": [],
            "resolved_hosts": [],
            "discovery_context": "scan"
        }));
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], OutputItem::Warning(_)));
    }

    #[test]
    fn missing_type_with_message_yields_error() {
        let out = run(json!({"message": "boom"}));
        assert_eq!(out.len(), 1);
        if let OutputItem::Error(e) = &out[0] {
            assert_eq!(e.message, "boom");
        } else { panic!() }
    }

    #[test]
    fn scan_captures_modules_for_later_extra_data() {
        let mut ctx = HookCtx::default();
        on_json_loaded(
            &mut ctx,
            json!({
                "type": "SCAN",
                "data": {"preset": {"modules": ["nuclei", "httpx"]}}
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        // No items yet.
        // Next event should pick modules up.
        let out = on_json_loaded(
            &mut ctx,
            json!({
                "type": "VULNERABILITY",
                "data": {"url": "https://x", "severity": "medium", "name": "test"},
                "module": "nuclei",
                "tags": [],
                "resolved_hosts": [],
                "discovery_context": "scan"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        if let OutputItem::Vulnerability(v) = &out[0] {
            let modules = v
                .extra_data
                .get("bbot_modules")
                .and_then(|x| x.as_array())
                .unwrap();
            assert_eq!(modules.len(), 2);
        } else { panic!() }
    }

    #[test]
    fn presets_value_map_joins_with_space() {
        assert_eq!(presets_join("cloud-enum,subdomain-enum"), Some("cloud-enum subdomain-enum".into()));
        assert_eq!(presets_join(""), None);
    }

    #[test]
    fn webscreenshot_copies_file_into_reports_outputs() {
        // Stage a fake bbot scan dir + screenshot.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let scan_name = "scan_demo";
        let scan_dir = home.join(".bbot").join("scans").join(scan_name);
        std::fs::create_dir_all(&scan_dir).unwrap();
        let src_rel = "https-example-com.png";
        std::fs::write(scan_dir.join(src_rel), b"fake-png-bytes").unwrap();

        // Stage a reports dir.
        let reports = tmp.path().join("reports");
        let outputs = reports.join(".outputs");

        // copy_screenshot expects HOME to point at our tmp.
        unsafe {
            std::env::set_var("HOME", home);
        }

        let dest = copy_screenshot(src_rel, scan_name, outputs.to_string_lossy().as_ref()).unwrap();
        assert!(std::path::Path::new(&dest).exists());
        assert_eq!(std::fs::read(&dest).unwrap(), b"fake-png-bytes");
    }

    #[test]
    fn copy_screenshot_returns_err_when_reports_unset() {
        let r = copy_screenshot("x.png", "scan", "");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("reports_folder"));
    }

    #[test]
    fn copy_screenshot_returns_err_when_source_missing() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", tmp.path()); }
        let r = copy_screenshot("missing.png", "scan", tmp.path().to_string_lossy().as_ref());
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("source file missing"));
    }
}
