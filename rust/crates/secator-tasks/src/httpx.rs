//! httpx — HTTP probe toolkit (Python `secator/tasks/httpx.py`).
//!
//! Output: one big JSON object per probed URL. `on_json_loaded` emits:
//!   * primary `Url` (with `url = final_url` when present + `response_headers` from
//!     the source `header` field),
//!   * `Technology` per `tech` entry (via [`crate::http_utils::get_techs`]),
//!   * `Tag(name=favicon_mmh3)` when httpx returned a favicon hash,
//!   * `Certificate` when `tls` is set, with subject + issuer + dates + fingerprint,
//!   * `Subdomain` per cert subject_cn / subject_an that is a subdomain of the URL's
//!     registered domain (Python `_create_subdomain_from_tls_cert`).

use secator_model::{Certificate, Map, OutputItem, Subdomain, Tag};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_parse::{convert_item, OutputMaps};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
#[allow(unused_imports)]
use secator_runner as _runner;
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "httpx",
    description: "Fast and multi-purpose HTTP toolkit.",
    cmd: "httpx-toolkit -irh",
    input_types: &["host", "host_port", "ip", "url", "string"],
    // Try-order from the Python class.
    output_types: &["url", "subdomain", "technology", "vulnerability", "tag", "certificate"],
    tags: &["url", "probe"],
    json_flag: Some("-json"),
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-l") },
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
        version: Some("v1.7.0"),
        cmd: Some("go install -v github.com/projectdiscovery/httpx/cmd/httpx@[install_version]"),
        github_handle: Some("projectdiscovery/httpx"),
        pre: &[("apk", &["chromium"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

/// Python `on_init` for httpx: if response-storage or screenshot is enabled, append
/// `-srd <reports_folder>/.outputs`. We run this in `on_cmd` (which fires after the
/// option engine has assembled the cmd) so we can check for `-sr`/`-ss` presence.
fn on_cmd_srd(ctx: &mut HookCtx, cmd: &mut String) {
    let folder = match ctx.state.get("reports_folder") {
        Some(f) if !f.is_empty() => f.clone(),
        _ => return,
    };
    let storing = has_flag(cmd, "-sr") || has_flag(cmd, "-ss");
    if !storing {
        return;
    }
    let outputs = format!("{folder}/.outputs");
    let quoted = shell_words::quote(&outputs).to_string();
    cmd.push_str(&format!(" -srd {quoted}"));
}

/// Whether the assembled cmd contains a bare flag (avoid substring matches like
/// `-sr` inside `-srt`).
fn has_flag(cmd: &str, flag: &str) -> bool {
    cmd.split_whitespace().any(|t| t == flag)
}

static HOOKS: HookRegistry = HookRegistry {
    on_cmd: &[on_cmd_srd],
    ..HookRegistry::EMPTY
};

/// Mirrors Python `tasks/httpx.py`. Currently a subset — extends to the full set as
/// httpx's secondary emissions (tls/favicon/tech) come online.
fn build_schema() -> OptSchema {
    let mut s = OptSchema::default(); // opt_prefix = "-"

    // Meta (shared HTTP) opts + key-map renames + config-derived defaults.
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for (canon, flag) in [
        ("header", "header"),
        ("delay", "delay"),
        ("follow_redirect", "follow-redirects"),
        ("method", "x"),
        ("proxy", "proxy"),
        ("rate_limit", "rate-limit"),
        ("retries", "retries"),
        ("threads", "threads"),
        ("timeout", "timeout"),
        ("data", "body"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    // user_agent is not exposed by httpx-toolkit directly; drop it.
    s.key_map.insert("user_agent".into(), KeyMap::NotSupported);

    // Task-specific renames to the actual httpx-toolkit flag names (Python parity).
    s.key_map.insert("store_responses".into(), KeyMap::Flag("sr".into()));
    s.key_map.insert("filter_duplicates".into(), KeyMap::Flag("fd".into()));

    // Task-specific opts: boolean flags + two int "response size" opts whose defaults
    // come from `CONFIG.http.response_max_size_bytes`.
    s.opts = vec![
        flag("tech_detect", "td", "Enable technology detection"),
        flag("asn", "asn", "ASN detection"),
        flag("cdn", "cdn", "CDN detection"),
        flag("favicon", "favicon", "Favicon hash"),
        flag("jarm", "jarm", "JARM TLS fingerprint"),
        flag("tls_grab", "tlsg", "Grab TLS certificate info"),
        flag("vhost", "vhost", "Probe for virtual hosts"),
        flag("screenshot", "ss", "Capture a screenshot of each response"),
        flag_default(
            "store_responses",
            "sr",
            "Save HTTP responses to disk",
            secator_config::get().http.store_responses,
        ),
        flag("filter_duplicates", "fd", "Filter duplicate responses"),
        int_opt("rstr", "Max response size to read (bytes)"),
        int_opt("rsts", "Max response size to save (bytes)"),
    ];
    meta_opts::apply_config_defaults(&mut s.opts);
    s
}

const fn int_opt(name: &'static str, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Int,
        short: None,
        is_flag: false,
        default: None,
        help,
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }
}

/// Boolean flag with a runtime-determined default (e.g. from `CONFIG.http.store_responses`).
fn flag_default(name: &'static str, short: &'static str, help: &'static str, default_true: bool) -> OptSpec {
    let mut o = flag(name, short, help);
    if default_true {
        o.default = Some("true");
    }
    o
}

const fn flag(name: &'static str, short: &'static str, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Bool,
        short: Some(short),
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

/// Python `tasks/httpx.py::on_json_loaded`. Applies `_preprocess_url` (substitute
/// `final_url`, rename `header`→`response_headers`) then converts to the primary
/// `Url` AND emits secondary items:
///   * `Technology` per `tech` entry (via [`crate::http_utils::get_techs`]),
///   * `Tag(name=favicon_mmh3)` when `favicon` is set,
///   * `Certificate` when `tls` is set (+ `Subdomain` per same-domain SAN).
pub fn on_json_loaded(_ctx: &mut HookCtx, mut record: Map) -> Vec<OutputItem> {
    let maps = OutputMaps::new();
    // Stash the secondary blocks before preprocess drops fields outside Url::fields().
    let favicon = record.get("favicon").cloned();
    let tls = record.get("tls").cloned();
    preprocess(&mut record);
    let item = convert_item(&record, SPEC.output_types, &maps, None);
    let mut out: Vec<OutputItem> = Vec::new();
    if let Some(OutputItem::Url(url)) = item {
        // Generate Technology items BEFORE moving the Url onto the output queue.
        for tech in get_techs(&url) {
            out.push(OutputItem::Technology(tech));
        }
        // Favicon hash → Tag(name=favicon_mmh3, category=info).
        if let Some(fav) = favicon {
            let value = match &fav {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !value.is_empty() && value != "null" {
                out.push(OutputItem::Tag(Tag {
                    name: "favicon_mmh3".into(),
                    value,
                    match_: url.url.clone(),
                    category: "info".into(),
                    ..Default::default()
                }));
            }
        }
        // TLS block → Certificate + same-domain Subdomain(s).
        if let Some(Value::Object(tls_obj)) = tls {
            if let Some(cert) = build_certificate(&tls_obj) {
                // Python uses the URL hostname (not the resolved IP). Parse the URL
                // string; httpx leaves `host` as the IP after DNS resolution.
                let url_hostname = url::Url::parse(&url.url)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_default();
                let url_domain = extract_registered_domain(&url_hostname);
                let mut sub_hosts: Vec<String> = Vec::new();
                if !cert.subject_cn.is_empty() {
                    sub_hosts.push(cert.subject_cn.clone());
                }
                sub_hosts.extend(cert.subject_an.iter().cloned());
                let cert_clone_host = cert.host.clone();
                out.push(OutputItem::Certificate(cert));
                let mut emitted_hosts: Vec<String> = Vec::new();
                for raw in sub_hosts {
                    let host = raw.trim_start_matches("*.").to_string();
                    if host.is_empty() || emitted_hosts.contains(&host) {
                        continue;
                    }
                    let in_url_domain = !url_domain.is_empty()
                        && (host == url_domain || host.ends_with(&format!(".{url_domain}")));
                    if in_url_domain || host == cert_clone_host {
                        emitted_hosts.push(host.clone());
                        out.push(OutputItem::Subdomain(Subdomain {
                            host: host.clone(),
                            domain: extract_registered_domain(&host),
                            verified: true,
                            sources: vec!["tls".into(), "certificate".into()],
                            ..Default::default()
                        }));
                    }
                }
            }
        }
        out.push(OutputItem::Url(url));
    }
    out
}

/// Best-effort port of Python `extract_domain_info(host, domain_only=True)`: the
/// last two labels of the host (`a.b.example.com` → `example.com`). Sufficient
/// for the cert SAN parity check.
fn extract_registered_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 | 1 => host.to_string(),
        n => parts[n.saturating_sub(2)..].join("."),
    }
}

/// Python `Certificate(**tls)` constructor. Pulls keys from httpx's `tls` block
/// and dumps non-shape data into `raw_value` only if present. Missing required
/// blob fields fall back to empty strings (Python defaults).
fn build_certificate(tls: &Map) -> Option<Certificate> {
    let host = tls.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let subject_cn = tls.get("subject_cn").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let subject_an: Vec<String> = tls
        .get("subject_an")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let issuer_dn = tls.get("issuer_dn").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let issuer_cn = tls.get("issuer_cn").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let issuer = tls
        .get("issuer_org")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let fingerprint_sha256 = tls
        .get("fingerprint_hash")
        .and_then(|v| v.get("sha256"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let not_before = tls.get("not_before").and_then(|v| v.as_str()).map(String::from);
    let not_after = tls.get("not_after").and_then(|v| v.as_str()).map(String::from);
    let serial_number = tls.get("serial_number").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let keysize = tls.get("keysize").and_then(|v| v.as_i64());
    let status = tls.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
    // Nothing useful → skip emitting a half-empty Certificate.
    if host.is_empty() && subject_cn.is_empty() && fingerprint_sha256.is_empty() {
        return None;
    }
    Some(Certificate {
        host,
        fingerprint_sha256,
        subject_cn,
        subject_an,
        issuer_dn,
        issuer_cn,
        issuer,
        not_before,
        not_after,
        serial_number,
        keysize,
        status,
        ..Default::default()
    })
}

// `get_techs` + `extract_software_and_version` live in `crate::http_utils` so
// other HTTP tasks (katana / ffuf) can reuse them.
use crate::http_utils::get_techs;

/// Python `_preprocess_url`: substitute final_url, rename header→response_headers.
/// (Time-string parsing into seconds is intentionally deferred — `time` is
/// `compare=false` so it doesn't affect dedup.)
fn preprocess(item: &mut Map) {
    if let Some(final_url) = item.get("final_url").cloned() {
        if !final_url.is_null() && final_url != Value::String(String::new()) {
            item.insert("url".into(), final_url);
        }
    }
    if let Some(h) = item.get("header").cloned() {
        item.insert("response_headers".into(), h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Technology, Url};
    use secator_runner::CommandRunner;

    const FIXTURE: &str = include_str!("../../../../tests/fixtures/httpx_output.json");

    /// The exact cmd string depends on CONFIG defaults (header / rstr / rsts / threads /
    /// store_responses). We assert presence of the key tokens rather than the full string
    /// so changes to default config don't flake this test.
    #[test]
    fn single_input_command_string() {
        let runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        let cmd = runner.build_cmd();
        assert!(cmd.starts_with("httpx-toolkit -irh"), "got: {cmd}");
        assert!(cmd.contains("-threads 50"));
        assert!(cmd.contains("-sr")); // store_responses default true
        assert!(cmd.contains("-rstr 100000") && cmd.contains("-rsts 100000"));
        assert!(cmd.contains("-header"));
        assert!(cmd.ends_with("-json -u example.com"));
    }

    #[test]
    fn many_inputs_command_string_uses_file_flag() {
        let mut runner = CommandRunner::new(&SPEC, vec!["a.com".into(), "b.com".into()]);
        runner.input_file = Some("/tmp/in.txt".into());
        let cmd = runner.build_cmd();
        assert!(cmd.contains("-threads 50"));
        assert!(cmd.ends_with("-json -l /tmp/in.txt"));
    }

    #[test]
    fn user_threads_override_default() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("threads".into(), "100".into());
        assert!(runner.build_cmd().contains("-threads 100"));
    }

    #[test]
    fn rate_limit_renames_to_kebab_case() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("rate_limit".into(), "50".into());
        assert!(runner.build_cmd().contains("-rate-limit 50"));
    }

    #[test]
    fn header_is_shlex_quoted() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("header".into(), "X-Test: hello world".into());
        let cmd = runner.build_cmd();
        assert!(cmd.contains("-header 'X-Test: hello world'"), "got: {cmd}");
    }

    #[test]
    fn boolean_flag_appears_when_true() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("tech_detect".into(), "true".into());
        assert!(runner.build_cmd().contains("-tech-detect"));
    }

    #[test]
    fn not_supported_flag_is_dropped() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        // user_agent is mapped to NotSupported, so even if set it shouldn't appear.
        runner.opts.insert("user_agent".into(), "X".into());
        assert!(!runner.build_cmd().contains("user_agent"));
        assert!(!runner.build_cmd().contains("user-agent"));
    }

    fn run_pipeline(line: &str) -> Vec<OutputItem> {
        use secator_parse::{JsonSerializer, Serializer};
        let mut ctx = HookCtx::default();
        JsonSerializer::new()
            .run(line)
            .into_iter()
            .flat_map(|rec| on_json_loaded(&mut ctx, rec))
            .collect()
    }

    #[test]
    fn parses_python_fixture_to_url_and_techs() {
        let items = run_pipeline(FIXTURE);
        // Fixture has 2 tech entries: HSTS, Nginx → 2 Technology items + 1 Url.
        assert_eq!(items.len(), 3, "expected 2 Technology + 1 Url, got {items:?}");
        let url = items.iter().find_map(|i| match i {
            OutputItem::Url(u) => Some(u), _ => None,
        }).expect("expected a Url");
        // url should be substituted with final_url (follow-redirects semantic).
        assert_eq!(url.url, "https://media.example.synology.me/web/index.html");
        assert_eq!(url.title, "Jellyfin");
        assert_eq!(url.status_code, 200);
        assert_eq!(url.webserver, "nginx");
        assert_eq!(url.content_type, "text/html");
        assert_eq!(url.content_length, 7442);
        assert_eq!(url.method, "GET");
        assert_eq!(url.tech, vec!["HSTS".to_string(), "Nginx".to_string()]);
        // httpx populates `host` with the resolved IP — match that (Python preserves it).
        assert_eq!(url.host, "82.61.151.800");
        assert_eq!(url.protocol, "https");
        assert!(url.verified); // high confidence + status_code != 0
        let techs: Vec<&Technology> = items.iter().filter_map(|i| match i {
            OutputItem::Technology(t) => Some(t), _ => None
        }).collect();
        assert_eq!(techs.len(), 2);
        for t in &techs {
            assert_eq!(t.match_, url.url);
        }
        assert!(techs.iter().any(|t| t.product == "HSTS"));
        assert!(techs.iter().any(|t| t.product == "Nginx"));
    }

    #[test]
    fn get_techs_extracts_product_and_version_from_versioned_strings() {
        let url = Url {
            url: "https://x".into(),
            tech: vec!["Nginx:1.28.3".into(), "HTTP/3".into(), "HSTS".into()],
            ..Default::default()
        };
        let techs = get_techs(&url);
        // "Nginx:1.28.3" → product "nginx", version "1.28.3"
        let nginx = techs.iter().find(|t| t.product == "nginx").expect("nginx tech");
        assert_eq!(nginx.version.as_deref(), Some("1.28.3"));
        assert_eq!(nginx.match_, "https://x");
        // "HTTP/3" has no parseable version → product stays as the original token.
        assert!(techs.iter().any(|t| t.product == "HTTP/3" && t.version.is_none()));
        // "HSTS" stays as-is.
        assert!(techs.iter().any(|t| t.product == "HSTS" && t.version.is_none()));
    }

    #[test]
    fn favicon_field_emits_tag() {
        let line = r#"{"url":"https://x.example.com","favicon":"abc12345","host":"1.2.3.4"}"#;
        let items = run_pipeline(line);
        let tag = items
            .iter()
            .find_map(|i| match i {
                OutputItem::Tag(t) if t.name == "favicon_mmh3" => Some(t),
                _ => None,
            })
            .expect("favicon tag");
        assert_eq!(tag.value, "abc12345");
        assert_eq!(tag.match_, "https://x.example.com");
        assert_eq!(tag.category, "info");
    }

    #[test]
    fn missing_favicon_emits_no_tag() {
        let line = r#"{"url":"https://x.example.com","host":"1.2.3.4"}"#;
        let items = run_pipeline(line);
        assert!(!items.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "favicon_mmh3")));
    }

    #[test]
    fn tls_block_emits_certificate_and_same_domain_subdomains() {
        let line = r#"{
            "url":"https://app.example.com",
            "host":"1.2.3.4",
            "tls":{
                "host":"app.example.com",
                "subject_cn":"app.example.com",
                "subject_an":["app.example.com","api.example.com","*.cdn.example.com","other.com"],
                "issuer_dn":"CN=Let's Encrypt",
                "issuer_cn":"R3",
                "issuer_org":["Let's Encrypt"],
                "fingerprint_hash":{"sha256":"abcdef"},
                "not_before":"2026-01-01T00:00:00Z",
                "not_after":"2026-12-31T23:59:59Z",
                "serial_number":"01:02:03",
                "keysize":2048,
                "status":"valid"
            }
        }"#;
        let items = run_pipeline(line);

        // Certificate emitted with the right fields.
        let cert = items
            .iter()
            .find_map(|i| match i {
                OutputItem::Certificate(c) => Some(c),
                _ => None,
            })
            .expect("certificate");
        assert_eq!(cert.subject_cn, "app.example.com");
        assert_eq!(cert.issuer, "Let's Encrypt");
        assert_eq!(cert.fingerprint_sha256, "abcdef");
        assert_eq!(cert.keysize, Some(2048));
        assert_eq!(cert.not_after.as_deref(), Some("2026-12-31T23:59:59Z"));

        // Subdomains: same-domain entries emit. `*.cdn.example.com` strips to
        // `cdn.example.com`. `other.com` is on a different registered domain and skipped.
        let subs: Vec<&Subdomain> = items
            .iter()
            .filter_map(|i| match i {
                OutputItem::Subdomain(s) => Some(s),
                _ => None,
            })
            .collect();
        let hosts: Vec<&str> = subs.iter().map(|s| s.host.as_str()).collect();
        assert!(hosts.contains(&"app.example.com"), "app.example.com missing: {hosts:?}");
        assert!(hosts.contains(&"api.example.com"), "api.example.com missing: {hosts:?}");
        assert!(hosts.contains(&"cdn.example.com"), "cdn.example.com missing: {hosts:?}");
        assert!(!hosts.contains(&"other.com"), "other.com should be filtered: {hosts:?}");
        for s in &subs {
            assert!(s.verified, "subdomain must be verified");
            assert!(s.sources.contains(&"tls".into()));
            assert!(s.sources.contains(&"certificate".into()));
        }
    }

    #[test]
    fn tls_block_without_meaningful_fields_emits_no_certificate() {
        let line = r#"{"url":"https://x.example.com","host":"1.2.3.4","tls":{}}"#;
        let items = run_pipeline(line);
        assert!(!items.iter().any(|i| matches!(i, OutputItem::Certificate(_))));
        assert!(!items.iter().any(|i| matches!(i, OutputItem::Subdomain(_))));
    }
}
