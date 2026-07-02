//! testssl.sh — TLS/SSL scanner (Python `secator/tasks/testssl.py`).
//!
//! testssl emits a JSON file via `--jsonfile <path>`. We inject the path inside
//! `on_cmd` (under the run's `.outputs/`), then parse it in `on_cmd_done`:
//!   * `cipher-*`            → grouped per `(ip, protocol)` → Vulnerability(low)
//!   * `cert_*`              → grouped per ip → Certificate
//!   * `id == scanProblem*`  → Warning
//!   * `id == engine_problem*` → Warning
//!   * severity ∈ {info, ok} → Tag(category=info, name=ssl_tls) when verbose
//!   * everything else with non-info/ok severity → Vulnerability
//!
//! Mirrors `Python ::on_cmd_done` field-by-field. Skip-id list (`scanTime`,
//! `overall_grade`, `DNS_CAArecord`) is preserved.

use std::fs;

use secator_model::{Certificate, Info, Ip, Map, OutputItem, Tag, Vulnerability, Warning};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "testssl",
    description: "SSL/TLS security scanner — ciphers, protocols, crypto flaws.",
    cmd: "testssl.sh",
    input_types: &["host", "host_port", "url", "ip"],
    output_types: &["certificate", "vulnerability", "ip", "tag"],
    tags: &["dns", "recon", "tls"],
    // No `--json` on stdout — testssl writes a JSON file at `--jsonfile <path>`.
    // We don't stream stdout JSON; everything happens in `on_cmd_done`.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Flag("-iL") },
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
        version: Some("v3.2.0"),
        cmd: Some("git clone --depth 1 --single-branch -b [install_version] https://github.com/drwetter/testssl.sh.git $HOME/.local/share/testssl.sh_[install_version] || true && ln -sf $HOME/.local/share/testssl.sh_[install_version]/testssl.sh $HOME/.local/bin"),
        github_handle: Some("testssl/testssl.sh"),
        github_bin: false,
        cmd_pre: &[
            ("apk", &["hexdump", "coreutils", "procps", "bash"]),
            ("pacman", &["util-linux", "bash"]),
            ("*", &["bsdmainutils", "bash"]),
        ],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_state],
    on_cmd: &[on_cmd_inject_jsonfile],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

fn before_init_record_state(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(rf) = &runner.reports_folder {
        ctx.state.insert("testssl:reports".into(), rf.to_string_lossy().into_owned());
    }
    if runner.opts.get("verbose").map(|v| v.as_str()) == Some("true") {
        ctx.state.insert("testssl:verbose".into(), "1".into());
    }
}

/// Python `on_cmd`: append `--jsonfile <reports>/.outputs/testssl.json` to the
/// cmd. The target also needs to be the LAST positional in testssl.sh —
/// we don't reorder here because `CommandRunner::build_cmd` already places
/// inputs at the end.
fn on_cmd_inject_jsonfile(ctx: &mut HookCtx, cmd: &mut String) {
    let reports = ctx.state.get("testssl:reports").cloned().unwrap_or_default();
    let outputs_dir = if reports.is_empty() {
        String::from("/tmp")
    } else {
        format!("{reports}/.outputs")
    };
    let _ = fs::create_dir_all(&outputs_dir);
    let path = format!("{outputs_dir}/testssl.json");
    let quoted = shell_words::quote(&path).into_owned();
    cmd.push_str(&format!(" --jsonfile {quoted}"));
    ctx.state.insert("testssl:output_path".into(), path);
}

fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("testssl:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            // testssl exits cleanly against hosts without TLS / with hardened
            // configs — the JSON file just never gets written. Treat as a
            // Warning (not an Error) so the run status stays SUCCESS.
            return vec![OutputItem::Warning(Warning {
                message: format!("Could not find JSON results in {path}"),
                ..Default::default()
            })];
        }
    };
    let arr: Vec<Value> = match serde_json::from_str(&body) {
        Ok(Value::Array(a)) => a,
        Ok(_) | Err(_) => return Vec::new(),
    };
    let verbose = ctx.state.contains_key("testssl:verbose");
    let ignored_prefixes = ["scanTime", "overall_grade", "DNS_CAArecord"];

    let mut out: Vec<OutputItem> = vec![OutputItem::Info(Info {
        message: format!("JSON results saved to {path}"),
        ..Default::default()
    })];

    // Two accumulators: per-ip bad ciphers (id starts with `cipher-`) and per-ip
    // certificate fields (id starts with `cert_` / `cert ` / `intermediate_cert_`).
    use std::collections::BTreeMap;
    let mut bad_cyphers: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut cert_items: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut host_to_ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen_ips: Vec<String> = Vec::new();

    for item in &arr {
        let ip_field = item.get("ip").and_then(|v| v.as_str()).unwrap_or("");
        let (host, ip) = ip_field
            .split_once('/')
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap_or((ip_field.to_string(), String::new()));
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let finding = item.get("finding").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let severity = item.get("severity").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let cwe = item.get("cwe").and_then(|v| v.as_str()).unwrap_or("").to_string();

        if ignored_prefixes.iter().any(|p| id.starts_with(p)) {
            continue;
        }

        host_to_ips.entry(host.clone()).or_default().push(ip.clone());
        if !ip.is_empty() && !seen_ips.contains(&ip) {
            seen_ips.push(ip.clone());
            out.push(OutputItem::Ip(Ip {
                host: host.clone(),
                ip: ip.clone(),
                alive: true,
                ..Default::default()
            }));
        }

        if id.starts_with("scanProblem") || id.starts_with("engine_problem") {
            out.push(OutputItem::Warning(Warning { message: finding, ..Default::default() }));
            continue;
        }
        if id.starts_with("cipher-") {
            let parts: Vec<&str> = finding.split_whitespace().collect();
            if parts.len() >= 2 {
                let protocol = parts[0].to_string();
                let bad = parts.last().unwrap().to_string();
                bad_cyphers
                    .entry(ip.clone())
                    .or_default()
                    .entry(protocol)
                    .or_default()
                    .push(bad);
            }
            continue;
        }
        if id.starts_with("cert_") || id.starts_with("cert ") {
            cert_items.entry(ip.clone()).or_default().push(item.clone());
            continue;
        }
        if id.starts_with("intermediate_cert_") {
            continue;
        }
        if severity == "info" || severity == "ok" {
            if !verbose {
                continue;
            }
            let mut extra: Map = Map::new();
            extra.insert("subtype".into(), Value::String(id.clone()));
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "ssl_tls".into(),
                match_: host.clone(),
                value: finding,
                extra_data: extra,
                ..Default::default()
            }));
            continue;
        }
        // Anything else with a real severity ⇒ Vulnerability.
        let human_name = if id == "TLS1" || id == "TLS1_1" {
            format!("SSL/TLS deprecated protocol offered: {id}")
        } else {
            format!("SSL/TLS {id}")
        };
        let mut extra: Map = Map::new();
        extra.insert("id".into(), Value::String(id.clone()));
        extra.insert("finding".into(), Value::String(finding));
        let mut tags = vec!["ssl".to_string(), "tls".to_string()];
        if !cwe.is_empty() {
            tags.push(cwe);
        }
        out.push(OutputItem::Vulnerability(Vulnerability {
            name: human_name,
            matched_at: host.clone(),
            ip: ip.clone(),
            tags,
            severity,
            confidence: "high".into(),
            extra_data: extra,
            ..Default::default()
        }));
    }

    // Emit a low-severity Vulnerability per (ip, protocol) for deprecated ciphers.
    for (ip, by_proto) in &bad_cyphers {
        for (protocol, cyphers) in by_proto {
            let mut extra: Map = Map::new();
            extra.insert(
                "cyphers".into(),
                Value::Array(cyphers.iter().map(|s| Value::String(s.clone())).collect()),
            );
            out.push(OutputItem::Vulnerability(Vulnerability {
                name: format!("SSL/TLS vulnerability ciphers for {protocol} deprecated"),
                matched_at: ip.clone(),
                ip: ip.clone(),
                severity: "low".into(),
                confidence: "high".into(),
                extra_data: extra,
                ..Default::default()
            }));
        }
    }

    // Reverse-lookup: ip → host (use the first host that mentions this ip).
    let ip_to_host = |needle: &str| -> String {
        for (h, ips) in &host_to_ips {
            if ips.iter().any(|i| i == needle) {
                return h.clone();
            }
        }
        String::new()
    };

    for (ip, certs) in &cert_items {
        let mut cert = Certificate {
            host: ip_to_host(ip),
            ip: ip.clone(),
            ..Default::default()
        };
        for c in certs {
            let cid = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let fnd = c.get("finding").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if cid.starts_with("cert_crlDistributionPoints") && fnd != "--" {
                cert.status = "Unknown".into();
            }
            if cid.starts_with("cert_ocspRevoked") {
                cert.status = if fnd.starts_with("not revoked") {
                    "Trusted".into()
                } else {
                    "Revoked".into()
                };
            }
            if cid.starts_with("cert_fingerprintSHA256") {
                cert.fingerprint_sha256 = fnd.clone();
            }
            if cid.starts_with("cert_commonName") {
                cert.subject_cn = fnd.clone();
            }
            if cid.starts_with("cert_subjectAltName") {
                cert.subject_an = fnd.split_whitespace().map(str::to_string).collect();
            }
            if cid.starts_with("cert_notBefore") {
                cert.not_before = Some(fnd.clone());
            }
            if cid.starts_with("cert_notAfter") {
                cert.not_after = Some(fnd.clone());
            }
            if cid.starts_with("cert_caIssuers") {
                cert.issuer_cn = fnd.clone();
            }
            if cid.starts_with("cert_chain_of_trust") {
                cert.self_signed = fnd.contains("self signed");
                cert.trusted = fnd.starts_with("passed");
            }
            if cid.starts_with("cert_keySize") {
                if let Some(num) = fnd.split_whitespace().nth(1) {
                    cert.keysize = num.parse().ok();
                }
            }
            if cid.starts_with("cert_serialNumber") {
                cert.serial_number = fnd.clone();
            }
            if cid.starts_with("cert ") && fnd.starts_with("-----BEGIN CERTIFICATE-----") {
                cert.raw_value = fnd.clone();
            }
        }
        out.push(OutputItem::Certificate(cert));
    }

    out
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.meta_opts = crate::meta_opts::opts_recon();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python `opt_key_map`: rename a couple of common opts to testssl's flag names.
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("user_agent".into(), KeyMap::Flag("user-agent".into()));
    s.key_map.insert("header".into(), KeyMap::Flag("reqheader".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("connect-timeout".into()));
    for k in ["delay", "rate_limit", "retries", "threads"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        OptSpec {
            name: "verbose",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Record all SSL/TLS info, not only critical issues",
            internal: true,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "parallel",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Test multiple hosts in parallel",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "warnings",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: None,
            help: "Set to 'batch' to stop on errors, 'off' to skip them",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "ids_friendly",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Avoid IDS blocking by skipping some vulnerability checks",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "hints",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Additional hints to findings",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "server_defaults",
            ty: OptType::Bool,
            short: None,
            is_flag: true,
            default: None,
            help: "Display the server default picks and certificate info",
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

    #[test]
    fn parses_minimal_testssl_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.json");
        let body = r#"[
            {"id": "TLS1", "ip": "example.com/93.184.216.34", "port": "443",
             "severity": "HIGH", "finding": "offered", "cwe": "CWE-310"},
            {"id": "cipher-tls1_3-1", "ip": "example.com/93.184.216.34", "port": "443",
             "severity": "MEDIUM", "finding": "TLSv1.3 weak NULL"},
            {"id": "cert_commonName", "ip": "example.com/93.184.216.34", "port": "443",
             "severity": "ok", "finding": "www.example.com"},
            {"id": "scanProblem-1", "ip": "example.com/93.184.216.34", "port": "443",
             "severity": "WARN", "finding": "host is down"}
        ]"#;
        std::fs::write(&path, body).unwrap();
        let mut ctx = HookCtx::default();
        ctx.state.insert("testssl:output_path".into(), path.to_string_lossy().into_owned());
        let out = on_cmd_done_parse(&mut ctx);

        // Expect: Info (saved), Ip, Vulnerability (TLS1), Warning (scanProblem),
        // Certificate, Vulnerability (deprecated ciphers).
        let has_vuln_tls = out.iter().any(|i| matches!(i, OutputItem::Vulnerability(v) if v.name.contains("TLS1")));
        let has_cert = out.iter().any(|i| matches!(i, OutputItem::Certificate(_)));
        let has_warning = out.iter().any(|i| matches!(i, OutputItem::Warning(_)));
        let has_ip = out.iter().any(|i| matches!(i, OutputItem::Ip(_)));
        let has_bad_cypher_vuln = out
            .iter()
            .any(|i| matches!(i, OutputItem::Vulnerability(v) if v.name.contains("deprecated")));
        assert!(has_vuln_tls && has_cert && has_warning && has_ip && has_bad_cypher_vuln);
    }

    /// When testssl exits without writing its JSON file (target has no TLS,
    /// hardened target, etc.) we must emit a Warning, not an Error — the run
    /// status should stay SUCCESS.
    #[test]
    fn missing_json_file_emits_warning_not_error() {
        let mut ctx = HookCtx::default();
        ctx.state.insert(
            "testssl:output_path".into(),
            "/nonexistent/path/testssl.json".into(),
        );
        let out = on_cmd_done_parse(&mut ctx);
        assert_eq!(out.len(), 1);
        assert!(
            matches!(&out[0], OutputItem::Warning(w) if w.message.contains("Could not find JSON results")),
            "expected a Warning for missing JSON, got {:?}",
            out[0]
        );
        // Explicitly assert *no* Error variant.
        assert!(!out.iter().any(|i| matches!(i, OutputItem::Error(_))));
    }
}
