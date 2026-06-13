//! dalfox — XSS scanner (Python `secator/tasks/dalfox.py`).
//!
//! `dalfox --format jsonl` emits one JSON dict per finding. Each record carries
//! a `type` field: `G`=Grep XSS, `R`=Reflected XSS, `V`=Verified XSS. We map
//! that to `Vulnerability.name`, derive `matched_at` from the URL minus its
//! query string, and stash the raw record on `extra_data`. Verified XSS hits
//! ALSO emit a `Url(verified=true)` so downstream tasks can pivot on confirmed
//! exploitable endpoints (Python parity).

use secator_model::{Map, OutputItem, Url, Vulnerability};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, SingleMode, ValueMap,
};
use secator_runner::{
    empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "dalfox",
    description: "Powerful open-source XSS scanning tool.",
    cmd: "dalfox",
    input_types: &["url"],
    output_types: &["vulnerability", "url"],
    tags: &["url", "fuzz"],
    json_flag: Some("--format jsonl"),
    // dalfox subcommands: `dalfox url <url>` (single) or `dalfox file <list>`.
    input_wiring: InputWiring { single: SingleMode::Flag("url"), file: FileMode::Flag("file") },
    item_loaders: &[ItemLoader::Json],
    // Python `input_chunk_size = 20`.
    input_chunk_size: 20,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.11.0"),
        cmd: Some("go install -v github.com/hahwul/dalfox/v2@[install_version]"),
        github_handle: Some("hahwul/dalfox"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "ansi",
    ignore_return_code: true,
    requires_sudo: false,
};

/// Per-record translation: emit Vulnerability + (when verified) Url.
pub fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let ty = item.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let name = match ty.as_str() {
        "G" => "Grep XSS",
        "R" => "Reflected XSS",
        "V" => "Verified XSS",
        _ => return Vec::new(),
    };
    let url = item.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let matched_at = strip_query(&url);
    let cwe = item.get("cwe").and_then(|v| v.as_str()).unwrap_or("");
    let tags: Vec<String> = if cwe.is_empty() { Vec::new() } else { vec![cwe.into()] };
    let severity = item
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    // Python `extra_data_extractor`: drop `type, severity, cwe` from the dict.
    let mut extra = Map::new();
    for (k, v) in &item {
        if matches!(k.as_str(), "type" | "severity" | "cwe") { continue; }
        extra.insert(k.clone(), v.clone());
    }

    let mut out = Vec::new();
    // Verified hits ALSO yield a confirmed Url (Python `if item['type'] == 'V'`).
    if ty == "V" {
        let method = item.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut url_extra = Map::new();
        for (k, v) in &item {
            if matches!(k.as_str(), "type" | "severity" | "cwe" | "method" | "data") { continue; }
            url_extra.insert(k.clone(), v.clone());
        }
        out.push(OutputItem::Url(Url {
            url: url.clone(),
            method,
            verified: true,
            extra_data: url_extra,
            ..Default::default()
        }));
    }
    out.push(OutputItem::Vulnerability(Vulnerability {
        id: String::new(),
        name: name.into(),
        provider: "dalfox".into(),
        confidence: "high".into(),
        severity,
        matched_at,
        tags,
        extra_data: extra,
        ..Default::default()
    }));
    out
}

/// `urlparse(x['data'])._replace(query='').geturl()`. We use the `url` crate to
/// drop the query string; on parse failure we fall back to the raw URL.
fn strip_query(u: &str) -> String {
    match url::Url::parse(u) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.to_string()
        }
        Err(_) => u.to_string(),
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // HttpBase = OPTS_HTTP_BASE.
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for (canon, flag) in [
        ("header", "header"), ("delay", "delay"), ("follow_redirect", "follow-redirects"),
        ("data", "data"), ("method", "method"), ("proxy", "proxy"),
        ("threads", "worker"), ("timeout", "timeout"), ("user_agent", "user-agent"),
    ] {
        s.key_map.insert(canon.into(), KeyMap::Flag(flag.into()));
    }
    s.key_map.insert("rate_limit".into(), KeyMap::NotSupported);
    s.key_map.insert("retries".into(), KeyMap::NotSupported);
    // Python `opt_value_map[DATA] = lambda x: dalfox.format_data(x)` — accept a
    // JSON dict string and emit form-encoded `k=v&k=v`. We do the same here.
    s.value_map.insert("data".into(), ValueMap::Func(format_data));
    s
}

fn format_data(v: &str) -> Option<String> {
    // Try parsing the value as JSON; if it's a dict, encode k=v pairs joined
    // by `&`. Any other shape returns an empty string (Python `return ''`).
    let parsed: Value = match serde_json::from_str(v) {
        Ok(p) => p,
        Err(_) => return Some(String::new()),
    };
    let Value::Object(m) = parsed else { return Some(String::new()) };
    let pairs: Vec<String> = m
        .iter()
        .map(|(k, val)| {
            let v_str = match val {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                _ => val.to_string(),
            };
            format!("{k}={v_str}")
        })
        .collect();
    Some(pairs.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_hit_emits_url_and_vulnerability() {
        let mut ctx = HookCtx::default();
        let line = r#"{"type":"V","severity":"high","cwe":"CWE-79","data":"https://x.com/p?q=<script>","method":"GET"}"#;
        let item: Map = serde_json::from_str(line).unwrap();
        let out = on_json_loaded(&mut ctx, item);
        let n_url = out.iter().filter(|i| matches!(i, OutputItem::Url(_))).count();
        let n_vuln = out.iter().filter(|i| matches!(i, OutputItem::Vulnerability(_))).count();
        assert_eq!((n_url, n_vuln), (1, 1));
        let v = out.iter().find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None }).unwrap();
        assert_eq!(v.name, "Verified XSS");
        assert_eq!(v.severity, "high");
        assert_eq!(v.matched_at, "https://x.com/p");
        assert!(v.tags.contains(&"CWE-79".to_string()));
        let u = out.iter().find_map(|i| match i { OutputItem::Url(u) => Some(u), _ => None }).unwrap();
        assert!(u.verified);
        assert_eq!(u.method, "GET");
    }

    #[test]
    fn reflected_hit_only_emits_vulnerability() {
        let mut ctx = HookCtx::default();
        let line = r#"{"type":"R","severity":"medium","cwe":"","data":"https://x.com/?a=1"}"#;
        let item: Map = serde_json::from_str(line).unwrap();
        let out = on_json_loaded(&mut ctx, item);
        let n_url = out.iter().filter(|i| matches!(i, OutputItem::Url(_))).count();
        let n_vuln = out.iter().filter(|i| matches!(i, OutputItem::Vulnerability(_))).count();
        assert_eq!((n_url, n_vuln), (0, 1));
        let v = out.iter().find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None }).unwrap();
        assert_eq!(v.name, "Reflected XSS");
    }

    #[test]
    fn format_data_dict_to_form_encoded() {
        assert_eq!(
            format_data(r#"{"a":"1","b":"two"}"#).as_deref(),
            Some("a=1&b=two")
        );
    }

    #[test]
    fn format_data_invalid_returns_empty() {
        assert_eq!(format_data("not json").as_deref(), Some(""));
    }
}
