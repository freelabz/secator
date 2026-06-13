//! nuclei — template-driven vulnerability scanner (Python `secator/tasks/nuclei.py`).
//!
//! Output: one JSON object per finding (jsonl). Each line is dispatched through
//! `on_json_loaded`, which mirrors Python's `output_discriminator`:
//!   - record has `percent` (stats line with `-stats-json`) → `Progress`
//!   - `template-id` contains `-detect` → `Technology` (product/version extracted)
//!   - `info.severity == "info"` → `Tag`
//!   - otherwise → `Vulnerability`

use secator_model::{Map, OutputItem, Progress, Tag, Technology, Vulnerability};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode, ValueMap,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::http_utils::extract_software_and_version_postfix;
use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "nuclei",
    description: "Fast and customisable vulnerability scanner based on simple YAML based DSL.",
    cmd: "nuclei",
    input_types: &["host", "host_port", "ip", "url"],
    output_types: &["vulnerability", "tag", "technology", "progress"],
    tags: &["vuln", "scan"],
    json_flag: Some("-jsonl"),
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-l") },
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
        version: Some("v3.4.2"),
        cmd: Some("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@[install_version]"),
        github_handle: Some("projectdiscovery/nuclei"),
        pre: &[("*", &["git"])],
        post: &[("*", "nuclei -ut")],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

/// Python `tasks/nuclei.py::output_discriminator` + `output_map`. The severity in
/// `info.severity` decides whether a finding becomes a `Tag` (informational) or a
/// `Vulnerability` (anything else). Stats lines (`percent` key, emitted by
/// `-stats-json`) yield a `Progress`, and `-detect` templates upgrade to
/// `Technology` so downstream consumers can pivot on product/version.
pub fn on_json_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    if record.contains_key("percent") {
        return vec![OutputItem::Progress(build_progress(&record))];
    }
    let info = record.get("info").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let severity = info
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let template_id = string_field(&record, "template-id");
    if template_id.contains("-detect") {
        return vec![OutputItem::Technology(build_technology(&record))];
    }
    if severity == "info" {
        vec![OutputItem::Tag(build_tag(&record, &info))]
    } else {
        vec![OutputItem::Vulnerability(build_vulnerability(&record, &info, &severity))]
    }
}

fn build_progress(record: &Map) -> Progress {
    let mut p = Progress::default();
    p.percent = record.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mut extra = Map::new();
    for (k, v) in record {
        if k != "percent" {
            extra.insert(k.clone(), v.clone());
        }
    }
    p.extra_data = extra;
    p
}

/// Python `product_extractor` + `version_extractor`. `-detect` template ids
/// already encode the product name; otherwise we strip the suffix tokens
/// (`_`, `/`, `-detect`, `-version`, `generic`) and run the postfix-flavour
/// software/version regex.
fn build_technology(record: &Map) -> Technology {
    let tid = string_field(record, "template-id");
    let raw_value = tag_value(record);
    let normalized = raw_value
        .replace('_', " ")
        .replace('/', "")
        .replace("-detect", "")
        .replace("-version", "")
        .replace("generic", "");
    let normalized = normalized.trim().to_string();
    let (parsed_product, parsed_version) = extract_software_and_version_postfix(&normalized);
    let product = if tid.contains("-detect") {
        tid.replace("-detect", "")
    } else if let Some(p) = parsed_product.clone() {
        p
    } else {
        normalized.clone()
    };
    let version = parsed_version;

    let mut t = Technology::default();
    t.product = product;
    t.match_ = string_field(record, "matched-at");
    t.version = version;
    t.extra_data = extra_data(record, false);
    t.tags = string_list(
        &record.get("info").and_then(|v| v.as_object()).cloned().unwrap_or_default(),
        "tags",
    );
    t
}

fn build_vulnerability(record: &Map, info: &Map, severity: &str) -> Vulnerability {
    let mut v = Vulnerability::default();
    v.id = first_cve(info).unwrap_or_default();
    v.name = string_field(record, "template-id");
    v.description = string_field(info, "description");
    v.severity = if severity.is_empty() { "unknown".into() } else { severity.into() };
    v.confidence = "high".into();
    v.cvss_score = info
        .get("classification")
        .and_then(|c| c.get("cvss-score"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    v.matched_at = string_field(record, "matched-at");
    v.ip = string_field(record, "ip");
    v.tags = string_list(info, "tags");
    v.references = string_list(info, "reference");
    v.extra_data = extra_data(record, false);
    v.provider = "nuclei".into();
    v
}

fn build_tag(record: &Map, info: &Map) -> Tag {
    let mut t = Tag::default();
    t.name = string_field(record, "template-id");
    t.match_ = string_field(record, "matched-at");
    t.value = tag_value(record);
    t.category = "info".into();
    t.extra_data = extra_data(record, true);
    // Tags emit `info` tags from the template metadata (Python `with_tags=True`).
    t.tags = string_list(info, "tags");
    t
}

/// Python `value_extractor` — extracted-results joined, else matcher-name, else id.
fn tag_value(record: &Map) -> String {
    if let Some(arr) = record.get("extracted-results").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            let joined: Vec<String> =
                arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            if !joined.is_empty() {
                return joined.join("\n");
            }
        }
    }
    let matcher = string_field(record, "matcher-name");
    if !matcher.is_empty() {
        return matcher;
    }
    string_field(record, "template-id")
}

/// Python `id_extractor` — first CVE id from `info.classification.cve-id` (or empty).
fn first_cve(info: &Map) -> Option<String> {
    info.get("classification")?
        .get("cve-id")?
        .as_array()?
        .first()?
        .as_str()
        .map(String::from)
}

/// Python `extra_data_extractor`. `with_tags=true` adds the template `tags`.
fn extra_data(record: &Map, with_tags: bool) -> Map {
    let mut data = Map::new();
    let extracted = record
        .get("extracted-results")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    data.insert("data".into(), extracted);
    data.insert("type".into(), Value::String(string_field(record, "type")));
    data.insert("matcher_name".into(), Value::String(string_field(record, "matcher-name")));
    data.insert("template_id".into(), Value::String(string_field(record, "template-id")));
    // Python rewrites `template-url` (cloud.projectdiscovery.io → github raw URL) — skip
    // for MVP, the value is just informational.
    data.insert("template_url".into(), Value::String(string_field(record, "template-url")));
    if let Some(meta) = record.get("metadata").cloned() {
        data.insert("metadata".into(), meta);
    }
    if with_tags {
        data.insert(
            "tags".into(),
            record
                .get("info")
                .and_then(|v| v.get("tags"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new())),
        );
    }
    data
}

fn string_field(m: &Map, key: &str) -> String {
    m.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn string_list(m: &Map, key: &str) -> Vec<String> {
    match m.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Mirrors Python `tasks/nuclei.py` opts + `opt_key_map` + `opt_value_map`. MVP
/// subset — only the user-facing options templates / severity / tags / etc.
fn build_schema() -> OptSchema {
    let mut s = OptSchema::default(); // opt_prefix = "-"
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for (canon, flag) in [
        ("header", "header"),
        ("follow_redirect", "follow-redirects"),
        ("proxy", "proxy"),
        ("rate_limit", "rate-limit"),
        ("retries", "retries"),
        ("threads", "c"),
        ("timeout", "timeout"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    // Python: delay / user_agent are NOT_SUPPORTED.
    s.key_map.insert("delay".into(), KeyMap::NotSupported);
    s.key_map.insert("user_agent".into(), KeyMap::NotSupported);

    // Task-specific opts.
    s.opts = vec![
        str_opt("severity", Some("s"), "Templates to run by severity (info,low,medium,high,critical)"),
        str_opt("tags", None, "Template tags (comma-separated)"),
        str_opt("templates", Some("t"), "Templates to run (comma-separated)"),
        str_opt("template_id", Some("tid"), "Template id"),
        str_opt("exclude_severity", Some("es"), "Exclude severity"),
        str_opt("exclude_tags", Some("etags"), "Exclude tags (comma-separated)"),
        flag("automatic_scan", "as", "Wappalyzer-based automatic web scan"),
        flag("no_interactsh", "ni", "Disable InteractSH OAST testing"),
    ];
    s.key_map.insert("templates".into(), KeyMap::Flag("t".into()));
    s.key_map.insert("exclude_tags".into(), KeyMap::Flag("exclude-tags".into()));
    s.key_map.insert("exclude_severity".into(), KeyMap::Flag("exclude-severity".into()));

    // List → comma-joined string (Python `opt_value_map`).
    for k in ["tags", "templates", "exclude_tags", "severity", "exclude_severity"] {
        s.value_map.insert(k.into(), ValueMap::Func(meta_opts::LIST_JOIN_COMMA));
    }
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Str,
        short,
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

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{JsonSerializer, Serializer};

    const FIXTURE: &str = include_str!("../../../../tests/fixtures/nuclei_output.json");

    fn run_pipeline(line: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        JsonSerializer::new()
            .run(line)
            .into_iter()
            .flat_map(|rec| on_json_loaded(&mut ctx, rec))
            .collect()
    }

    #[test]
    fn info_severity_emits_tag() {
        // Fixture: severity "info" — discriminator picks Tag.
        let items = run_pipeline(FIXTURE);
        assert_eq!(items.len(), 1);
        match &items[0] {
            OutputItem::Tag(t) => {
                assert_eq!(t.name, "http-missing-security-headers");
                assert_eq!(t.match_, "https://example.synology.me");
                assert_eq!(t.value, "access-control-expose-headers");
                assert_eq!(t.category, "info");
                assert!(t.tags.contains(&"misconfig".into()));
            }
            other => panic!("expected Tag, got {other:?}"),
        }
    }

    #[test]
    fn non_info_severity_emits_vulnerability() {
        let line = r#"{"template-id":"cve-2021-1","info":{"name":"x","severity":"high","tags":["cve","rce"],"description":"d","reference":["https://r"],"classification":{"cve-id":["CVE-2021-1"],"cvss-score":9.8}},"matched-at":"https://t.com","ip":"1.2.3.4","matcher-name":"m"}"#;
        let items = run_pipeline(line);
        assert_eq!(items.len(), 1);
        let v = match &items[0] {
            OutputItem::Vulnerability(v) => v,
            other => panic!("expected Vulnerability, got {other:?}"),
        };
        assert_eq!(v.id, "CVE-2021-1");
        assert_eq!(v.name, "cve-2021-1");
        assert_eq!(v.severity, "high");
        assert_eq!(v.cvss_score, 9.8);
        assert_eq!(v.matched_at, "https://t.com");
        assert_eq!(v.provider, "nuclei");
        assert_eq!(v.references, vec!["https://r".to_string()]);
        assert_eq!(v.tags, vec!["cve".to_string(), "rce".to_string()]);
    }

    #[test]
    fn stats_line_emits_progress() {
        // `-stats-json` ships an object like {"duration":"...", "templates":N, "percent":42, ...}.
        let line = r#"{"duration":"1m","templates":1500,"hosts":1,"matched":3,"requests":120,"errors":0,"percent":42}"#;
        let items = run_pipeline(line);
        assert_eq!(items.len(), 1);
        let p = match &items[0] {
            OutputItem::Progress(p) => p,
            other => panic!("expected Progress, got {other:?}"),
        };
        assert_eq!(p.percent, 42.0);
        assert_eq!(p.extra_data.get("templates").and_then(|v| v.as_i64()), Some(1500));
        assert!(!p.extra_data.contains_key("percent"));
    }

    #[test]
    fn detect_template_emits_technology() {
        // `-detect` template id → product/version Technology.
        let line = r#"{"template-id":"apache-detect","info":{"severity":"info","tags":["tech","detect"]},"matched-at":"http://target","extracted-results":["Apache 2.4.49"]}"#;
        let items = run_pipeline(line);
        assert_eq!(items.len(), 1);
        let t = match &items[0] {
            OutputItem::Technology(t) => t,
            other => panic!("expected Technology, got {other:?}"),
        };
        assert_eq!(t.product, "apache");
        assert_eq!(t.match_, "http://target");
        assert_eq!(t.version.as_deref(), Some("2.4.49"));
        assert!(t.tags.contains(&"tech".into()));
    }

    #[test]
    fn detect_template_without_version_still_emits_technology() {
        let line = r#"{"template-id":"nginx-detect","info":{"severity":"info","tags":["tech"]},"matched-at":"http://t","matcher-name":"server-header"}"#;
        let items = run_pipeline(line);
        assert_eq!(items.len(), 1);
        let t = match &items[0] {
            OutputItem::Technology(t) => t,
            other => panic!("expected Technology, got {other:?}"),
        };
        assert_eq!(t.product, "nginx");
        assert!(t.version.is_none());
    }
}
