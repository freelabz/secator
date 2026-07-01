//! search_vulns — CPE/product vuln lookup (Python `secator/tasks/search_vulns.py`).
//!
//! Each target may be a plain query (`"nginx 1.18"`) OR a `matched_at~query` pair
//! (`"82.66.157.114:53~dnsmasq 2.91"`). `before_init` splits on `~`, stashing
//! `matched_at` in `ctx.state` so `on_json_loaded` can tag each emitted vuln with
//! the originating service / port. This mirrors Python's `before_init(self)` which
//! rewrites `self.inputs[0]` and sets `self.matched_at`.

use secator_model::{Exploit, Info, Map, OutputItem, Vulnerability};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{
    empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "search_vulns",
    description: "Search for known vulnerabilities by product name or CPE.",
    cmd: "search_vulns",
    input_types: &["string"],
    output_types: &["vulnerability", "exploit"],
    tags: &["vuln", "recon"],
    json_flag: Some("-f json"),
    // Python `file_flag = None` — search_vulns can't read an inputs file. The
    // runner detects `FileMode::Unsupported` and chunks every input into its own
    // `-q <query>` subprocess (Python `celery.break_task` parity).
    input_wiring: InputWiring {
        single: SingleMode::Flag("-q"),
        file: FileMode::Unsupported,
    },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("1.0.9"),
        cmd: Some("pipx install --force search_vulns==[install_version]"),
        github_handle: Some("ra1nb0rn/search_vulns"),
        github_bin: false,
        post: &[("*", "search_vulns -u")],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_split_matched_at],
    ..HookRegistry::EMPTY
};

/// Python `tasks/search_vulns.py::before_init`. Each chunked invocation has exactly
/// one input. If that input contains `~`, the left side is preserved as `matched_at`
/// (where the originating service lives) and the right side becomes the actual
/// `-q <query>` value. Slashes are also flattened to spaces (Python parity).
fn before_init_split_matched_at(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if runner.inputs.len() != 1 {
        return;
    }
    let raw = runner.inputs[0].clone();
    let (matched_at, query) = match raw.split_once('~') {
        Some((m, q)) => (Some(m.to_string()), q.to_string()),
        None => (None, raw),
    };
    let query = query.replace('/', " ").trim_end().to_string();
    runner.inputs[0] = query.clone();
    if let Some(m) = matched_at {
        ctx.state.insert("search_vulns:matched_at".into(), m);
    }
    ctx.state.insert("search_vulns:query".into(), query);
}

/// Mirrors Python `tasks/search_vulns.py::on_json_loaded`. For each top-level key
/// (a queried product), iterate `vulns: { CVE-…: {...} }` and emit:
///   - one `Info { "Targets: …" }` once per run (Python `_targets_info_yielded` gate);
///   - one `Vulnerability` per CVE per matched_at (comma-split, Python parity);
///   - one `Exploit` per exploit URL per matched_at (max 3, emitted Info if truncated);
///   - the `exploitable` tag on vulns that have at least one exploit.
pub fn on_json_loaded(ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let matched_ats: Vec<String> = match ctx.state.get("search_vulns:matched_at") {
        Some(m) => m.split(',').map(|s| s.trim().to_string()).collect(),
        None => vec![ctx.state.get("search_vulns:query").cloned().unwrap_or_default()],
    };
    let mut out = Vec::new();
    // Python `_targets_info_yielded`: emit once per run.
    if !ctx.state.contains_key("search_vulns:targets_yielded") {
        ctx.state.insert("search_vulns:targets_yielded".into(), "1".into());
        out.push(OutputItem::Info(Info {
            message: format!("Targets: {}", matched_ats.join(", ")),
            ..Default::default()
        }));
    }
    for (_product, value) in record.iter() {
        // Python: when the value is a string, it's a "Warning: <msg>" line.
        if let Some(s) = value.as_str() {
            out.push(OutputItem::Info(Info {
                message: s.trim_start_matches("Warning: ").to_string(),
                ..Default::default()
            }));
            continue;
        }
        let vulns = match value.get("vulns").and_then(|v| v.as_object()) {
            Some(v) => v,
            None => continue,
        };
        for (cve_id, vuln_data) in vulns {
            // Python `float(severity.CVSS.score)` — search_vulns sometimes encodes
            // the score as a JSON string, so accept either f64 or parseable string.
            let cvss_score = vuln_data
                .get("severity")
                .and_then(|s| s.get("CVSS"))
                .and_then(|c| c.get("score"))
                .and_then(|s| s.as_f64().or_else(|| s.as_str().and_then(|t| t.parse().ok())))
                .unwrap_or(0.0);
            let description = vuln_data
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let references = extract_references(vuln_data, cve_id);
            let mut tags = extract_tags(vuln_data);
            let extra_data = extract_extra_data(vuln_data, ctx);
            let exploits: Vec<String> = vuln_data
                .get("exploits")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if !exploits.is_empty() {
                tags.push("exploitable".into());
            }
            // Python: low confidence when match_reason == "general_product_uncertain".
            let confidence: String = if vuln_data
                .get("match_reason")
                .and_then(|v| v.as_str())
                == Some("general_product_uncertain")
            {
                tags.push("uncertain".into());
                "low".into()
            } else {
                "high".into()
            };
            // Python `__post_init__`: derive severity from cvss_score when "unknown".
            let severity = if cvss_score > 0.0 {
                cvss_to_severity(cvss_score).to_string()
            } else {
                "unknown".into()
            };
            // Python parity: `runners.skip_cve_low_confidence` drops items that
            // search_vulns flagged "uncertain" (low confidence). Computed once
            // per CVE so all `matched_at` clones inherit the same decision.
            let skip_this = confidence == "low"
                && secator_config::get().runners.skip_cve_low_confidence;
            if !skip_this {
                for m in &matched_ats {
                    let mut v = Vulnerability {
                        id: cve_id.clone(),
                        name: cve_id.clone(),
                        description: description.clone(),
                        confidence: confidence.clone(),
                        severity: severity.clone(),
                        cvss_score,
                        references: references.clone(),
                        extra_data: extra_data.clone(),
                        tags: tags.clone(),
                        provider: "search_vulns".into(),
                        matched_at: m.clone(),
                        ..Default::default()
                    };
                    // Python `__post_init__`: `reference = references[0]` if any.
                    if let Some(r) = v.references.first() {
                        v.reference = r.clone();
                    }
                    out.push(OutputItem::Vulnerability(v));
                }
            }
            // Emit Exploits (max 3, like Python).
            let kept: Vec<&String> = exploits.iter().take(3).collect();
            if exploits.len() > 3 {
                out.push(OutputItem::Info(Info {
                    message: format!("{} exploits found. Keeping max 3", exploits.len()),
                    ..Default::default()
                }));
            }
            for exploit_url in kept {
                let (name, provider, exploit_id, e_tags, e_extra) =
                    build_exploit_meta(exploit_url, cve_id);
                for m in &matched_ats {
                    out.push(OutputItem::Exploit(Exploit {
                        name: name.clone(),
                        provider: provider.clone(),
                        id: exploit_id.clone(),
                        matched_at: m.clone(),
                        confidence: "high".into(),
                        reference: exploit_url.clone(),
                        cves: vec![cve_id.clone()],
                        tags: e_tags.clone(),
                        extra_data: e_extra.clone(),
                        ..Default::default()
                    }));
                }
            }
        }
    }
    out
}

/// Python `cvss_to_severity` — 0..<4 low, 4..<7 medium, 7..<9 high, ≥9 critical.
fn cvss_to_severity(c: f64) -> &'static str {
    if c < 4.0 { "low" } else if c < 7.0 { "medium" } else if c < 9.0 { "high" } else { "critical" }
}

/// Parse an exploit URL into the (name, provider, id, tags, extra_data) Python derives.
/// Github URLs get `user`/`repo` in `extra_data`; other providers get the hostname-based
/// provider name. Numeric tail of the URL becomes the id (e.g. exploit-db 50973).
fn build_exploit_meta(
    exploit_url: &str,
    cve_id: &str,
) -> (String, String, String, Vec<String>, Map) {
    // Python normalizes the URL (strip scheme + slash split) but we keep it simpler:
    // just parse out hostname / parts.
    let hostname = url_hostname(exploit_url);
    let is_github = hostname == "github.com";
    let provider = if is_github {
        "github".to_string()
    } else {
        hostname
            .rsplit('.')
            .nth(1)
            .unwrap_or(&hostname)
            .to_string()
    };
    let mut name = if is_github { "Github".into() } else { capitalize(&provider) };
    name.push_str(" exploit");
    let mut tags = vec![hostname.clone()];
    let mut extra = Map::new();
    if is_github {
        // Best-effort user/repo extraction from `github.com/<user>/<repo>/...`.
        let stripped = exploit_url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let parts: Vec<&str> = stripped.split('/').collect();
        if parts.len() >= 3 {
            extra.insert("user".into(), parts[1].into());
            extra.insert("repo".into(), parts[2].into());
        }
    }
    let last = exploit_url.rsplit('/').next().unwrap_or("");
    let id = if last.chars().all(|c| c.is_ascii_digit()) && !last.is_empty() {
        name.push_str(&format!(" {last}"));
        last.to_string()
    } else {
        format!("{cve_id}-exploit")
    };
    tags.push(provider.clone());
    (name, provider, id, tags, extra)
}

fn url_hostname(url: &str) -> String {
    let stripped = url.trim_start_matches("https://").trim_start_matches("http://");
    stripped.split('/').next().unwrap_or("").to_string()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn extract_tags(vuln_data: &Value) -> Vec<String> {
    let mut tags = Vec::new();
    if let Some(cwe) = vuln_data.get("cwe_id").and_then(|v| v.as_str()) {
        tags.push(cwe.to_string());
    }
    if vuln_data.get("cisa_known_exploited").and_then(|v| v.as_bool()).unwrap_or(false) {
        tags.push("actively-exploited".into());
    }
    tags
}

fn extract_references(vuln_data: &Value, cve_id: &str) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    if let Some(alias) = vuln_data
        .get("aliases")
        .and_then(|a| a.get(cve_id))
        .and_then(|v| v.as_str())
    {
        refs.push(alias.to_string());
    }
    if let Some(exploits) = vuln_data.get("exploits").and_then(|v| v.as_array()) {
        for e in exploits {
            if let Some(s) = e.as_str() {
                refs.push(s.to_string());
            }
        }
    }
    refs
}

fn extract_extra_data(vuln_data: &Value, ctx: &HookCtx) -> Map {
    let mut m = Map::new();
    if let Some(v) = vuln_data.get("published") { m.insert("published".into(), v.clone()); }
    if let Some(v) = vuln_data.get("cvss_ver") { m.insert("cvss_version".into(), v.clone()); }
    if let Some(v) = vuln_data.get("cwe_id") { m.insert("cwe_id".into(), v.clone()); }
    if let Some(v) = vuln_data.get("cisa_known_exploited") {
        m.insert("cisa_known_exploited".into(), v.clone());
    }
    if let Some(v) = vuln_data.get("product_ids") { m.insert("product_ids".into(), v.clone()); }
    if let Some(v) = vuln_data.get("match_reason") { m.insert("match_reason".into(), v.clone()); }
    if let Some(query) = ctx.state.get("search_vulns:query") {
        m.insert("service_name".into(), Value::String(query.clone()));
    }
    m
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema::default();
    // The HTTP/recon meta opts don't apply to this offline lookup tool.
    for k in ["header", "delay", "follow_redirect", "proxy", "rate_limit", "retries",
              "threads", "timeout", "user_agent"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![
        flag("ignore_general_product_vulns", "ignore-general-product-vulns",
             "Ignore vulnerabilities that only affect a general product"),
        flag("include_single_version_vulns", "include-single-version-vulns",
             "Include vulnerabilities that only affect one specific version"),
        flag("include_patched", "include-patched", "Include vulnerabilities reported as patched"),
    ];
    s.key_map.insert("ignore_general_product_vulns".into(),
                     KeyMap::Flag("ignore-general-product-vulns".into()));
    s.key_map.insert("include_single_version_vulns".into(),
                     KeyMap::Flag("include-single-version-vulns".into()));
    s.key_map.insert("include_patched".into(), KeyMap::Flag("include-patched".into()));
    s
}

const fn flag(name: &'static str, _flag: &'static str, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Bool,
        short: None,
        is_flag: true,
        default: None,
        help,
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner_with(inputs: Vec<String>) -> CommandRunner {
        CommandRunner::new(&SPEC, inputs)
    }

    #[test]
    fn before_init_splits_tilde_and_stashes_matched_at() {
        let mut ctx = HookCtx::default();
        let mut r = runner_with(vec!["82.66.157.114:53~dnsmasq 2.91".into()]);
        before_init_split_matched_at(&mut ctx, &mut r);
        assert_eq!(r.inputs, vec!["dnsmasq 2.91".to_string()]);
        assert_eq!(
            ctx.state.get("search_vulns:matched_at"),
            Some(&"82.66.157.114:53".to_string())
        );
        assert_eq!(ctx.state.get("search_vulns:query"), Some(&"dnsmasq 2.91".to_string()));
    }

    #[test]
    fn before_init_replaces_slashes_with_spaces() {
        let mut ctx = HookCtx::default();
        let mut r = runner_with(vec!["nginx/1.18.0".into()]);
        before_init_split_matched_at(&mut ctx, &mut r);
        assert_eq!(r.inputs, vec!["nginx 1.18.0".to_string()]);
        assert!(ctx.state.get("search_vulns:matched_at").is_none());
    }

    #[test]
    fn before_init_noop_when_more_than_one_input() {
        let mut ctx = HookCtx::default();
        let mut r = runner_with(vec!["a~b".into(), "c~d".into()]);
        before_init_split_matched_at(&mut ctx, &mut r);
        assert_eq!(r.inputs, vec!["a~b".to_string(), "c~d".to_string()]);
    }

    #[test]
    fn on_json_loaded_emits_vulnerability_per_cve_with_matched_at() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("search_vulns:matched_at".into(), "192.0.2.1:53,192.0.2.2:53".into());
        ctx.state.insert("search_vulns:query".into(), "dnsmasq 2.91".into());
        let line = r#"{"dnsmasq 2.91":{"vulns":{"CVE-2023-28450":{"description":"d","severity":{"CVSS":{"score":7.5}},"cwe_id":"CWE-770","aliases":{"CVE-2023-28450":"https://nvd.nist.gov/vuln/detail/CVE-2023-28450"}}}}}"#;
        let record: Map = serde_json::from_str(line).unwrap();
        let items = on_json_loaded(&mut ctx, record);
        // Expected: 1 Info ("Targets: …") + 2 Vulnerabilities (one per matched_at).
        let vulns: Vec<&Vulnerability> = items.iter().filter_map(|it| match it {
            OutputItem::Vulnerability(v) => Some(v), _ => None
        }).collect();
        assert_eq!(vulns.len(), 2, "one Vuln per matched_at");
        for v in &vulns {
            assert_eq!(v.id, "CVE-2023-28450");
            assert_eq!(v.cvss_score, 7.5);
            assert_eq!(v.severity, "high", "derived from cvss_score 7.5");
            assert!(v.references.iter().any(|r| r.contains("nvd.nist.gov")));
            assert_eq!(v.reference, v.references[0], "Python __post_init__ sets reference");
            assert!(v.tags.contains(&"CWE-770".to_string()));
        }
        let matched: Vec<&str> = vulns.iter().map(|v| v.matched_at.as_str()).collect();
        assert_eq!(matched, vec!["192.0.2.1:53", "192.0.2.2:53"]);
        // Info Targets line emitted exactly once.
        let infos = items.iter().filter(|it| matches!(it, OutputItem::Info(_))).count();
        assert_eq!(infos, 1);
    }

    #[test]
    fn on_json_loaded_emits_exploits_with_truncation() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("search_vulns:query".into(), "nginx 1.18.0".into());
        let line = r#"{"nginx 1.18.0":{"vulns":{"CVE-2021-23017":{"severity":{"CVSS":{"score":8.1}},"exploits":["https://github.com/a/b","https://github.com/c/d","https://github.com/e/f","https://github.com/g/h","https://www.exploit-db.com/50973"]}}}}"#;
        let record: Map = serde_json::from_str(line).unwrap();
        let items = on_json_loaded(&mut ctx, record);
        let n_exploits = items.iter().filter(|it| matches!(it, OutputItem::Exploit(_))).count();
        assert_eq!(n_exploits, 3, "Python keeps max 3 exploits");
        // One Info for "Targets" + one Info for "5 exploits found. Keeping max 3".
        let infos: Vec<&Info> = items.iter().filter_map(|it| match it {
            OutputItem::Info(i) => Some(i), _ => None
        }).collect();
        assert!(infos.iter().any(|i| i.message.contains("Targets:")));
        assert!(infos.iter().any(|i| i.message.contains("exploits found. Keeping max 3")));
        // Vuln picks up the exploitable tag.
        let v = items.iter().find_map(|it| match it { OutputItem::Vulnerability(v) => Some(v), _ => None }).unwrap();
        assert!(v.tags.contains(&"exploitable".to_string()));
    }
}
