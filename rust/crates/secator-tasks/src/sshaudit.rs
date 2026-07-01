//! ssh-audit — SSH server security auditor (Python `secator/tasks/sshaudit.py`).
//!
//! ssh-audit emits a single JSON object covering the SSH banner, advertised
//! ciphers, kex/mac/host-key algorithms, and a list of related CVEs. We parse
//! the object once and emit:
//!   * a single `Tag(name=ssh_banner)` carrying the raw banner.
//!   * one `Vulnerability` per CVE (`severity=high`).
//!   * for each `enc`/`mac`/`kex`/`key` entry:
//!       * `Vulnerability(severity=high)` per `notes.fail`,
//!       * `Vulnerability(severity=medium)` per `notes.warn`,
//!       * `Tag(category=info)` carrying any `notes.info` when no fail/warn.

use secator_model::{Map, OutputItem, Tag, Vulnerability};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "sshaudit",
    description: "SSH server & client security audit.",
    cmd: "ssh-audit",
    input_types: &["host", "ip"],
    output_types: &["vulnerability", "tag"],
    tags: &["ssh", "audit", "security"],
    json_flag: Some("-j"),
    input_wiring: InputWiring {
        // Python uses positional single-input, `-T <file>` for many inputs.
        single: SingleMode::Arg,
        file: FileMode::Flag("-T"),
    },
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
        version: Some("v3.3.0"),
        cmd: Some("git clone --depth 1 --single-branch -b [install_version] https://github.com/jtesta/ssh-audit.git $HOME/.local/share/ssh-audit_[install_version] || true && ln -sf $HOME/.local/share/ssh-audit_[install_version]/ssh-audit.py $HOME/.local/bin/ssh-audit && chmod +x $HOME/.local/bin/ssh-audit"),
        github_handle: Some("jtesta/ssh-audit"),
        github_bin: false,
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: true,
    requires_sudo: false,
    default_inputs: None,
};

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // ssh-audit's flags are mostly short. Map a couple Python-style names.
    s.key_map.insert("ssh_port".into(), KeyMap::Flag("-p".into()));
    s.key_map.insert("ipv4".into(), KeyMap::Flag("-4".into()));
    s.key_map.insert("ipv6".into(), KeyMap::Flag("-6".into()));
    s
}

/// Walk the ssh-audit JSON object and emit one item per CVE / weak algorithm /
/// info-grade algorithm. Mirrors `sshaudit.py::on_json_loaded` line-for-line.
pub fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let mut out: Vec<OutputItem> = Vec::new();
    let target = item.get("target").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let banner = item.get("banner").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let software = banner.get("software").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let raw_banner = banner.get("raw").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let protocol = banner.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Banner tag.
    let mut extra: Map = Map::new();
    extra.insert("software".into(), Value::String(software.clone()));
    extra.insert("protocol".into(), Value::String(protocol));
    out.push(OutputItem::Tag(Tag {
        category: "info".into(),
        name: "ssh_banner".into(),
        value: raw_banner,
        match_: target.clone(),
        extra_data: extra,
        ..Default::default()
    }));

    // CVEs — each becomes a high-severity vulnerability.
    if let Some(cves) = item.get("cves").and_then(|v| v.as_array()) {
        for cve in cves {
            let cve_str = match cve {
                Value::String(s) => s.clone(),
                Value::Object(o) => o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| serde_json::to_string(o).unwrap_or_default()),
                other => other.to_string(),
            };
            let mut ed: Map = Map::new();
            ed.insert("cve".into(), Value::String(cve_str.clone()));
            ed.insert("software".into(), Value::String(software.clone()));
            out.push(OutputItem::Vulnerability(Vulnerability {
                name: format!("SSH {cve_str}"),
                matched_at: target.clone(),
                tags: vec!["ssh".into(), "cve".into()],
                severity: "high".into(),
                confidence: "high".into(),
                provider: "ssh_audit".into(),
                extra_data: ed,
                ..Default::default()
            }));
        }
    }

    // Algorithm groups (enc / mac / kex / key) all share the same shape.
    for (group, kind_label, weak_name, warn_name, info_tag) in [
        ("enc", "encryption", "SSH weak encryption algorithm", "SSH encryption algorithm warning", "ssh_encryption"),
        ("mac", "mac", "SSH weak MAC algorithm", "SSH MAC algorithm warning", "ssh_mac"),
        ("kex", "kex", "SSH weak key exchange algorithm", "SSH key exchange algorithm warning", "ssh_kex"),
        ("key", "host_key", "SSH weak host key algorithm", "SSH host key algorithm warning", "ssh_host_key"),
    ] {
        let group_tags: Vec<String> = match group {
            "enc" => vec!["ssh".into(), "encryption".into(), "cipher".into()],
            "mac" => vec!["ssh".into(), "mac".into(), "authentication".into()],
            "kex" => vec!["ssh".into(), "kex".into(), "key-exchange".into()],
            "key" => vec!["ssh".into(), "host-key".into()],
            _ => vec!["ssh".into()],
        };
        let Some(entries) = item.get(group).and_then(|v| v.as_array()) else { continue };
        for entry in entries {
            let entry = match entry.as_object() {
                Some(o) => o,
                None => continue,
            };
            let algorithm = entry.get("algorithm").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let notes = entry.get("notes").and_then(|v| v.as_object()).cloned().unwrap_or_default();
            let failures: Vec<String> = notes
                .get("fail")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let warnings: Vec<String> = notes
                .get("warn")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();

            for failure in &failures {
                let mut ed: Map = Map::new();
                ed.insert("algorithm".into(), Value::String(algorithm.clone()));
                ed.insert("issue".into(), Value::String(failure.clone()));
                ed.insert("type".into(), Value::String(kind_label.into()));
                out.push(OutputItem::Vulnerability(Vulnerability {
                    name: weak_name.into(),
                    matched_at: target.clone(),
                    tags: group_tags.clone(),
                    severity: "high".into(),
                    confidence: "high".into(),
                    provider: "ssh_audit".into(),
                    extra_data: ed,
                    ..Default::default()
                }));
            }

            for warning in &warnings {
                let mut ed: Map = Map::new();
                ed.insert("algorithm".into(), Value::String(algorithm.clone()));
                ed.insert("issue".into(), Value::String(warning.clone()));
                ed.insert("type".into(), Value::String(kind_label.into()));
                out.push(OutputItem::Vulnerability(Vulnerability {
                    name: warn_name.into(),
                    matched_at: target.clone(),
                    tags: group_tags.clone(),
                    severity: "medium".into(),
                    confidence: "high".into(),
                    provider: "ssh_audit".into(),
                    extra_data: ed,
                    ..Default::default()
                }));
            }

            // Clean algorithm: emit an info-grade Tag carrying any `notes.info`.
            if failures.is_empty() && warnings.is_empty() {
                let info_notes: Vec<String> = notes
                    .get("info")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let value = if info_notes.is_empty() {
                    algorithm.clone()
                } else {
                    format!("{} {}", algorithm, info_notes.join(", "))
                };
                let mut ed: Map = Map::new();
                ed.insert("algorithm".into(), Value::String(algorithm.clone()));
                out.push(OutputItem::Tag(Tag {
                    category: "info".into(),
                    name: info_tag.into(),
                    value,
                    match_: target.clone(),
                    extra_data: ed,
                    ..Default::default()
                }));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Map {
        // Trimmed shape modeled on real ssh-audit JSON output.
        let v = serde_json::json!({
            "target": "example.com:22",
            "banner": {
                "raw": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7",
                "software": "OpenSSH_7.6p1",
                "protocol": "2.0"
            },
            "cves": ["CVE-2018-15473", "CVE-2016-10708"],
            "enc": [
                {
                    "algorithm": "aes128-cbc",
                    "notes": {
                        "fail": ["using weak cipher mode"],
                        "warn": [],
                        "info": []
                    }
                },
                {
                    "algorithm": "aes128-ctr",
                    "notes": {"info": ["available since OpenSSH 3.7"]}
                }
            ],
            "mac": [
                {
                    "algorithm": "hmac-sha1",
                    "notes": {"warn": ["using weak hash algorithm"]}
                }
            ],
            "kex": [
                {
                    "algorithm": "diffie-hellman-group-exchange-sha256",
                    "notes": {}
                }
            ],
            "key": [
                {
                    "algorithm": "ssh-rsa",
                    "notes": {"warn": ["using broken SHA-1 hash"], "info": ["available since OpenSSH 2.5"]}
                }
            ]
        });
        v.as_object().unwrap().clone()
    }

    #[test]
    fn emits_banner_tag() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(&mut ctx, fixture());
        let banner = out
            .iter()
            .find_map(|i| match i {
                OutputItem::Tag(t) if t.name == "ssh_banner" => Some(t),
                _ => None,
            })
            .expect("banner tag");
        assert_eq!(banner.match_, "example.com:22");
        assert!(banner.value.starts_with("SSH-2.0-OpenSSH"));
        assert_eq!(banner.extra_data.get("software").and_then(|v| v.as_str()), Some("OpenSSH_7.6p1"));
        assert_eq!(banner.extra_data.get("protocol").and_then(|v| v.as_str()), Some("2.0"));
    }

    #[test]
    fn emits_cve_vulnerabilities() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(&mut ctx, fixture());
        let cve_vulns: Vec<&Vulnerability> = out
            .iter()
            .filter_map(|i| match i {
                OutputItem::Vulnerability(v) if v.name.starts_with("SSH CVE-") => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(cve_vulns.len(), 2);
        assert!(cve_vulns.iter().any(|v| v.name == "SSH CVE-2018-15473"));
        assert!(cve_vulns.iter().all(|v| v.severity == "high"));
        assert!(cve_vulns.iter().all(|v| v.provider == "ssh_audit"));
    }

    #[test]
    fn emits_fail_high_warn_medium_and_info_tag() {
        let mut ctx = HookCtx::default();
        let out = on_json_loaded(&mut ctx, fixture());
        // aes128-cbc has a `fail` → high vuln; aes128-ctr is clean → info tag.
        let high_enc = out
            .iter()
            .find_map(|i| match i {
                OutputItem::Vulnerability(v) if v.name == "SSH weak encryption algorithm" => Some(v),
                _ => None,
            })
            .expect("weak encryption vuln");
        assert_eq!(high_enc.severity, "high");
        assert_eq!(
            high_enc.extra_data.get("algorithm").and_then(|v| v.as_str()),
            Some("aes128-cbc"),
        );

        let info_enc = out
            .iter()
            .find_map(|i| match i {
                OutputItem::Tag(t) if t.name == "ssh_encryption" => Some(t),
                _ => None,
            })
            .expect("encryption info tag");
        assert_eq!(info_enc.match_, "example.com:22");
        assert!(info_enc.value.contains("aes128-ctr"));

        // hmac-sha1 → warn → medium vuln.
        let mac_warn = out
            .iter()
            .find_map(|i| match i {
                OutputItem::Vulnerability(v) if v.name == "SSH MAC algorithm warning" => Some(v),
                _ => None,
            })
            .expect("mac warn vuln");
        assert_eq!(mac_warn.severity, "medium");

        // ssh-rsa has `warn` so it should NOT emit an info tag (only warn vuln).
        let rsa_warn = out
            .iter()
            .find_map(|i| match i {
                OutputItem::Vulnerability(v) if v.name == "SSH host key algorithm warning" => Some(v),
                _ => None,
            })
            .expect("host-key warn vuln");
        assert_eq!(rsa_warn.severity, "medium");
        let host_key_info = out.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "ssh_host_key"));
        assert!(!host_key_info, "ssh-rsa has a warn note — should not emit info tag");
    }
}
