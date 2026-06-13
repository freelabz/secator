//! whois — likexian whois client (Python `secator/tasks/whois.py`).
//!
//! `whois-go -j` writes a single JSON object that may span many stdout lines.
//! Python collects the full stdout (`self.output`) and parses it inside
//! `on_cmd_done`. We mirror that by accumulating each stdout line in
//! `ctx.state["whois:stdout"]` (via `on_line`), then parsing in `on_cmd_done`.

use secator_model::{Domain, Map, OutputItem, Warning};
use secator_options::{FileMode, InputWiring, OptSchema, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "whois",
    description: "Retrieve domain registration information (likexian whois-go).",
    cmd: "whois-go -j",
    input_types: &["host"],
    output_types: &["domain"],
    tags: &["dns", "domain", "recon"],
    // `whois-go -j` is not a per-line JSON producer; we collect the full stdout
    // in `on_line` and parse it in `on_cmd_done` instead.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    item_loaders: &[],
    // Python `input_chunk_size = 1` — one host per subprocess. `FileMode::Unsupported`
    // would force this anyway, but we set it explicitly for clarity.
    input_chunk_size: 1,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.15.7"),
        cmd: Some("go install -v github.com/likexian/whois/cmd/whois@[install_version]"),
        github_handle: Some("likexian/whois"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    on_line: &[on_line_collect],
    on_cmd_done: &[on_cmd_done_parse],
    ..HookRegistry::EMPTY
};

/// Append every stdout line to `ctx.state["whois:stdout"]`. We don't yield
/// items per line; whois-go's JSON spans multiple lines so the parser runs
/// once at `on_cmd_done`.
fn on_line_collect(ctx: &mut HookCtx, line: &str) -> Option<String> {
    let buf = ctx.state.entry("whois:stdout".into()).or_default();
    buf.push_str(line);
    buf.push('\n');
    None
}

/// Mirrors Python `on_cmd_done`. Parse the collected stdout as JSON; if it
/// doesn't parse, emit a `Warning` carrying the cleaned-up text.
fn on_cmd_done_parse(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let raw = ctx.state.get("whois:stdout").cloned().unwrap_or_default();
    let trimmed = raw.trim();
    // `whois-go` sometimes prefixes with `whoisparser:` errors; find the JSON.
    let json_start = trimmed.find('{');
    let candidate = match json_start {
        Some(i) if i > 0 => &trimmed[i..],
        Some(_) => trimmed,
        None => {
            return vec![OutputItem::Warning(Warning {
                message: clean_error(trimmed),
                ..Default::default()
            })];
        }
    };
    let parsed: Value = match serde_json::from_str(candidate) {
        Ok(v) => v,
        Err(_) => {
            return vec![OutputItem::Warning(Warning {
                message: clean_error(trimmed),
                ..Default::default()
            })];
        }
    };
    let domain = build_domain(&parsed);
    vec![OutputItem::Domain(domain)]
}

fn clean_error(s: &str) -> String {
    s.trim().replace("whoisparser: ", "").trim().to_string()
}

fn build_domain(item: &Value) -> Domain {
    let domain_info = get_obj(item, "domain");
    let registrar_info = get_obj(item, "registrar");
    let registrant_info = get_obj(item, "registrant");
    let administrative_info = get_obj(item, "administrative");
    let technical_info = get_obj(item, "technical");
    let creation_date = get_str(&domain_info, "created_date");
    let expiration_date = get_str(&domain_info, "expiration_date");
    let updated_date = get_str(&domain_info, "updated_date");
    let statuses = get_str_list(&domain_info, "status");
    let mut extra_data = Map::new();
    extra_data.insert(
        "domain_id".into(),
        Value::String(get_str(&domain_info, "id").unwrap_or_default()),
    );
    extra_data.insert(
        "punycode".into(),
        Value::String(get_str(&domain_info, "punycode").unwrap_or_default()),
    );
    extra_data.insert(
        "whois_server".into(),
        Value::String(get_str(&domain_info, "whois_server").unwrap_or_default()),
    );
    extra_data.insert(
        "name_servers".into(),
        domain_info
            .get("name_servers")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    );
    Domain {
        domain: get_str(&domain_info, "domain").unwrap_or_default(),
        creation_date,
        expiration_date,
        updated_date,
        status: statuses,
        registrar: get_str(&registrar_info, "name").unwrap_or_default(),
        registrar_info,
        registrant: get_str(&registrant_info, "organization").unwrap_or_default(),
        registrant_info,
        administrative_info,
        technical_info,
        extra_data,
        ..Default::default()
    }
}

fn get_obj(v: &Value, key: &str) -> Map {
    v.get(key).and_then(|x| x.as_object()).cloned().unwrap_or_default()
}
fn get_str(m: &Map, k: &str) -> Option<String> {
    let s = m.get(k).and_then(|v| v.as_str()).unwrap_or("");
    if s.is_empty() { None } else { Some(s.to_string()) }
}
fn get_str_list(m: &Map, k: &str) -> Vec<String> {
    m.get(k)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// whois has no recon/http meta opts — the binary takes only `-j` (already in
/// cmd) and a positional host. No user-facing flags to surface.
fn build_schema() -> OptSchema {
    OptSchema { opt_prefix: "-", ..OptSchema::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_and_parse(stdout: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        for line in stdout.lines() {
            on_line_collect(&mut ctx, line);
        }
        on_cmd_done_parse(&mut ctx)
    }

    #[test]
    fn parses_domain_json() {
        let json = r#"{
            "domain": {
                "domain": "example.com",
                "created_date": "1995-08-14",
                "expiration_date": "2025-08-13",
                "updated_date": "2024-08-14",
                "status": ["client_transfer_prohibited"],
                "id": "ID-12345",
                "punycode": "example.com",
                "whois_server": "whois.example.com",
                "name_servers": ["ns1.example.com", "ns2.example.com"]
            },
            "registrar": {"name": "RegistrarCo"},
            "registrant": {"organization": "Example Org"},
            "administrative": {"email": "admin@example.com"},
            "technical": {"email": "tech@example.com"}
        }"#;
        let items = collect_and_parse(json);
        assert_eq!(items.len(), 1);
        let d = match &items[0] { OutputItem::Domain(d) => d, _ => panic!() };
        assert_eq!(d.domain, "example.com");
        assert_eq!(d.creation_date.as_deref(), Some("1995-08-14"));
        assert_eq!(d.registrar, "RegistrarCo");
        assert_eq!(d.registrant, "Example Org");
        assert_eq!(d.status, vec!["client_transfer_prohibited".to_string()]);
    }

    #[test]
    fn emits_warning_when_output_isnt_json() {
        let items = collect_and_parse("whoisparser: no whois data");
        assert_eq!(items.len(), 1);
        if let OutputItem::Warning(w) = &items[0] {
            assert!(w.message.contains("no whois data"));
        } else {
            panic!("expected Warning");
        }
    }
}
