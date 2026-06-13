//! subfinder — fast passive subdomain enumeration (Python `secator/tasks/subfinder.py`).
//!
//! Output: one JSON object per line, shape `{"host": ..., "input": <domain>, "sources": [...]}`.
//! `domain` on the resulting `Subdomain` is renamed from `input`. The `validate_item`
//! filter drops items where `input == "localhost"`; `on_item` tags results as `passive`.

use secator_model::{Map, OutputItem, OutputMap};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, SingleMode, ValueMap};
use secator_parse::{convert_item, OutputMaps};
use secator_runner::{HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "subfinder",
    description: "Fast passive subdomain enumeration tool.",
    cmd: "subfinder -cs",
    input_types: &["host"],
    output_types: &["subdomain"],
    tags: &["dns", "recon", "passive"],
    json_flag: Some("-json"),
    input_wiring: InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Flag("-dL") },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: build_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.7.0"),
        cmd: Some("go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@[install_version]"),
        github_handle: Some("projectdiscovery/subfinder"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps { proxychains: false, proxy_http: true, proxy_socks5: false },
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

/// Mirrors Python `tasks/subfinder.py`:
/// `meta_opts = OPTS_RECON` (delay/proxy/rate_limit/retries/threads/timeout);
/// `opt_key_map = {delay: NOT_SUPPORTED, retries: NOT_SUPPORTED,
///                 rate_limit: "rate-limit", threads: "t", timeout: "timeout"}`;
/// `opt_value_map = {proxy: strip http(s):// scheme}`.
fn build_schema() -> OptSchema {
    let mut s = OptSchema::default(); // opt_prefix = "-"
    s.meta_opts = meta_opts::opts_recon();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    s.key_map.insert("delay".into(), KeyMap::NotSupported);
    s.key_map.insert("retries".into(), KeyMap::NotSupported);
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("rate-limit".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("t".into()));
    s.value_map
        .insert("proxy".into(), ValueMap::Func(meta_opts::PROXY_STRIP));
    s
}

fn build_output_maps() -> OutputMaps {
    let mut maps = OutputMaps::new();
    let mut rename = OutputMap::new();
    rename.insert("domain".into(), "input".into());
    maps.insert("subdomain".into(), rename);
    maps
}

/// Python `tasks/subfinder.py::on_json_loaded` equivalent. Drops `input==localhost`
/// (Python `validate_item`), converts via the type schema, and tags survivors as
/// `passive` (Python `on_item` hook). Kept inside the loaded-callback so the
/// transform is colocated with the parsing logic — exactly how the Python class
/// reads.
pub fn on_json_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    if record.get("input").and_then(|v| v.as_str()) == Some("localhost") {
        return Vec::new();
    }
    let maps = build_output_maps();
    let Some(mut item) = convert_item(&record, SPEC.output_types, &maps, None) else {
        return Vec::new();
    };
    if let OutputItem::Subdomain(ref mut s) = item {
        s.tags = vec!["passive".into()];
    }
    vec![item]
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_runner::CommandRunner;

    /// Golden test: the real Python fixture must produce the expected Subdomain.
    const FIXTURE: &str = include_str!("../../../../tests/fixtures/subfinder_output.json");

    #[test]
    fn single_input_command_string() {
        let runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        // The schema's THREADS default ("50") flows through as `-t 50` (Python parity).
        assert_eq!(runner.build_cmd(), "subfinder -cs -t 50 -json -d example.com");
    }

    /// Run the fixture line through the JSON loader + on_json_loaded callback,
    /// just like `execute_with_hooks` does at runtime.
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
    fn parses_python_fixture_to_subdomain() {
        let items = run_pipeline(FIXTURE);
        assert_eq!(items.len(), 1, "expected one subdomain, got {items:?}");
        match &items[0] {
            OutputItem::Subdomain(s) => {
                assert_eq!(s.host, "git.example.synology.me");
                assert_eq!(s.domain, "example.synology.me");
                assert_eq!(s.sources, vec!["alienvault".to_string(), "crtsh".to_string()]);
                assert_eq!(s.tags, vec!["passive".to_string()]);
            }
            _ => panic!("expected Subdomain, got {:?}", items[0]),
        }
    }

    #[test]
    fn skips_localhost() {
        let items = run_pipeline(r#"{"host":"localhost","input":"localhost","sources":[]}"#);
        assert!(items.is_empty());
    }
}
