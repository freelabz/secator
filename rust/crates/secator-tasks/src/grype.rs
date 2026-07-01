//! grype — vulnerability scanner (Python `secator/tasks/grype.py`).
//!
//! grype's default output is a fixed-width text table (each column separated
//! by 2+ spaces). Python's `item_loader` splits each line on `'  '` and counts
//! 5 / 6 columns to handle both `version-fixed`-present and -absent cases. We
//! mirror that inside `on_line`: parse the columns, push a `Vulnerability` to
//! `ctx.extra_results`, and drop the raw line so it doesn't pollute output.

use secator_model::{OutputItem, Vulnerability};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "grype",
    description: "Anchore Grype — vulnerability scanner for images & filesystems.",
    cmd: "grype --quiet",
    input_types: &["path", "string"],
    output_types: &["vulnerability"],
    tags: &["vuln", "scan"],
    // Default text output; no JSON flag.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
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
        version: Some("v0.91.2"),
        cmd: Some("curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b $HOME/.local/bin"),
        github_handle: Some("anchore/grype"),
        cmd_pre: &[("*", &["curl"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_record_input],
    on_line: &[on_line_parse_row],
    ..HookRegistry::EMPTY
};

/// Stash the first input on `ctx.state` so `on_line` can include the right
/// `matched_at` on each emitted Vulnerability.
fn before_init_record_input(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(i) = runner.inputs.first() {
        ctx.state.insert("grype:input".into(), i.clone());
    }
}

/// Python `item_loader`: split each line on the two-space separator, count
/// columns, build a Vulnerability. We drop the row (return `None`) and push
/// items via `ctx.extra_results` so the regular item-dispatch path doesn't
/// also try to parse the line as JSON.
fn on_line_parse_row(ctx: &mut HookCtx, line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split("  ").filter(|p| !p.is_empty()).collect();
    // Python: 5 cols (no fixed-version) or 6 cols. Header line starts with "NAME".
    if !(parts.len() == 5 || parts.len() == 6) || parts[0].trim() == "NAME" {
        return None;
    }
    let (product, version, versions_fixed, product_type, vuln_id, severity) =
        if parts.len() == 5 {
            (parts[0].trim(), parts[1].trim(), None,
             parts[2].trim(), parts[3].trim(), parts[4].trim())
        } else {
            (parts[0].trim(), parts[1].trim(), Some(parts[2].trim()),
             parts[3].trim(), parts[4].trim(), parts[5].trim())
        };
    let matched_at = ctx.state.get("grype:input").cloned().unwrap_or_default();
    let mut extra = secator_model::Map::new();
    extra.insert("lang".into(), Value::String(product_type.to_string()));
    extra.insert("product".into(), Value::String(product.to_string()));
    extra.insert("version".into(), Value::String(version.to_string()));
    if let Some(vf) = versions_fixed {
        let fixed_list: Vec<Value> = vf
            .split(',')
            .map(|s| Value::String(s.trim().to_string()))
            .collect();
        extra.insert("versions_fixed".into(), Value::Array(fixed_list));
    }
    let provider = if vuln_id.starts_with("GHSA") { "github.com".to_string() } else { "grype".into() };
    let references = if vuln_id.starts_with("GHSA") {
        vec![format!("https://github.com/advisories/{vuln_id}")]
    } else {
        Vec::new()
    };
    ctx.extra_results.push(OutputItem::Vulnerability(Vulnerability {
        id: vuln_id.to_string(),
        name: vuln_id.to_string(),
        matched_at,
        confidence: "medium".into(),
        severity: severity.to_lowercase(),
        provider,
        references,
        extra_data: extra,
        ..Default::default()
    }));
    None
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // Python `VulnCode` → no HTTP meta opts; all OPT_NOT_SUPPORTED.
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.opts = vec![OptSpec {
        name: "mode",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: None,
        help: "Scan mode (internal; image/fs/repo auto-detected from input)",
        internal: true,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s.key_map.insert("mode".into(), KeyMap::NotSupported);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_5_column_row() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("grype:input".into(), "alpine:latest".into());
        let line = "openssl  3.1.0  binary  CVE-2024-0001  high";
        assert!(on_line_parse_row(&mut ctx, line).is_none());
        let v = ctx
            .extra_results
            .iter()
            .find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None })
            .expect("expected Vulnerability");
        assert_eq!(v.id, "CVE-2024-0001");
        assert_eq!(v.severity, "high");
        assert_eq!(v.matched_at, "alpine:latest");
        assert!(v.extra_data.get("versions_fixed").is_none());
    }

    #[test]
    fn parses_6_column_row_with_fixed_versions() {
        let mut ctx = HookCtx::default();
        let line = "openssl  3.1.0  3.1.1, 3.2.0  binary  CVE-2024-0002  critical";
        on_line_parse_row(&mut ctx, line);
        let v = ctx
            .extra_results
            .iter()
            .find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None })
            .unwrap();
        let fixed = v.extra_data.get("versions_fixed").unwrap().as_array().unwrap();
        assert_eq!(fixed.len(), 2);
        assert_eq!(fixed[0].as_str().unwrap(), "3.1.1");
    }

    #[test]
    fn skips_header_line() {
        let mut ctx = HookCtx::default();
        on_line_parse_row(&mut ctx, "NAME  INSTALLED  TYPE  VULNERABILITY  SEVERITY");
        assert!(ctx.extra_results.is_empty());
    }

    #[test]
    fn ghsa_id_sets_github_provider_and_reference() {
        let mut ctx = HookCtx::default();
        on_line_parse_row(&mut ctx, "lodash  4.17.10  java  GHSA-jf85-cpcp-j695  high");
        let v = ctx
            .extra_results
            .iter()
            .find_map(|i| match i { OutputItem::Vulnerability(v) => Some(v), _ => None })
            .unwrap();
        assert_eq!(v.provider, "github.com");
        assert!(v.references[0].contains("/advisories/GHSA-"));
    }
}
