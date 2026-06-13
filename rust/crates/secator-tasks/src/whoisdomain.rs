//! whoisdomain — `whoisdomain` Python WHOIS wrapper (Python `secator/tasks/whoisdomain.py`).
//!
//! `whoisdomain --json -d <host>` emits a single JSON object per host with
//! registration metadata. `input_chunk_size = 1` so every host is its own
//! subprocess. Python emits one `Domain` per record with the email list stashed
//! under `extra_data.emails`.

use secator_model::{Domain, Map, OutputItem};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "whoisdomain",
    description: "Retrieve domain registration info (Python whoisdomain wrapper).",
    cmd: "whoisdomain",
    input_types: &["host"],
    output_types: &["domain"],
    tags: &["dns", "domain", "recon"],
    json_flag: Some("--json"),
    // Python `input_flag = '-d'` + `file_flag` unset ⇒ single positional via `-d`,
    // multi-input not supported (we chunk one per subprocess).
    input_wiring: InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Unsupported },
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
        version: Some("1.20230906.1"),
        cmd: Some("pipx install whoisdomain==[install_version] --force"),
        github_handle: Some("mboot-github/WhoisDomain"),
        github_bin: false,
        cmd_pre: &[("*", &["whois"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

/// Python `on_json_loaded` — straight map to `Domain` with emails in `extra_data`.
pub fn on_json_loaded(_ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() {
        return Vec::new();
    }
    let mut extra: Map = Map::new();
    let emails = item.get("emails").cloned().unwrap_or(Value::Array(Vec::new()));
    extra.insert("emails".into(), emails);
    vec![OutputItem::Domain(Domain {
        domain: name,
        creation_date: opt_str(&item, "creation_date"),
        expiration_date: opt_str(&item, "expiration_date"),
        registrar: get_str(&item, "registrar"),
        registrant: get_str(&item, "registrant"),
        extra_data: extra,
        ..Default::default()
    })]
}

fn opt_str(item: &Map, key: &str) -> Option<String> {
    match item.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn get_str(item: &Map, key: &str) -> String {
    item.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Python `opts = {}`. Drop the canonical HTTP/recon meta opts — `whoisdomain`
/// only accepts `-d` and `--json`.
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s
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
    fn parses_full_record() {
        let out = run(json!({
            "name": "example.com",
            "registrar": "RegistrarCo",
            "creation_date": "1995-08-14T00:00:00",
            "expiration_date": "2025-08-13T00:00:00",
            "registrant": "Example Org",
            "emails": ["admin@example.com", "tech@example.com"]
        }));
        assert_eq!(out.len(), 1);
        if let OutputItem::Domain(d) = &out[0] {
            assert_eq!(d.domain, "example.com");
            assert_eq!(d.registrar, "RegistrarCo");
            assert_eq!(d.registrant, "Example Org");
            assert_eq!(d.creation_date.as_deref(), Some("1995-08-14T00:00:00"));
            assert_eq!(d.expiration_date.as_deref(), Some("2025-08-13T00:00:00"));
            let emails = d.extra_data.get("emails").and_then(|v| v.as_array()).unwrap();
            assert_eq!(emails.len(), 2);
        } else { panic!("expected Domain") }
    }

    #[test]
    fn missing_name_yields_nothing() {
        assert!(run(json!({"registrar": "x"})).is_empty());
    }

    #[test]
    fn missing_optional_fields_become_none() {
        let out = run(json!({"name": "x.com"}));
        if let OutputItem::Domain(d) = &out[0] {
            assert_eq!(d.creation_date, None);
            assert_eq!(d.expiration_date, None);
            assert_eq!(d.registrar, "");
        } else { panic!() }
    }
}
