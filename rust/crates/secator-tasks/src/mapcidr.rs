//! mapcidr — projectdiscovery's CIDR utility (Python `secator/tasks/mapcidr.py`).
//!
//! `mapcidr -cidr <range>` (or `-cl <file>`) prints one IP per line — that's the
//! whole protocol. Python's `on_line` validates each line as IPv4/IPv6 and emits
//! an `Ip(alive=false)`, optionally suppressed from the live display when the
//! `hide_ips` opt is set. We mirror the validation and emission; the
//! display-suppression bit is logged as a `tag` so downstream filters can hide
//! these IPs without us needing a print-only sink yet.

use std::net::{Ipv4Addr, Ipv6Addr};

use secator_model::{Ip, OutputItem};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ValidatorRegistry};

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "mapcidr",
    description: "Utility program to perform multiple operations on subnet/CIDR ranges.",
    cmd: "mapcidr",
    // Python `input_types = [CIDR_RANGE, IP, SLUG]`. SLUG ≈ `slug` on the Rust side.
    input_types: &["cidr_range", "ip", "slug"],
    output_types: &["ip"],
    tags: &["ip", "recon"],
    json_flag: None,
    // Python `input_flag = '-cidr'`, `file_flag = '-cl'`.
    input_wiring: InputWiring { single: SingleMode::Flag("-cidr"), file: FileMode::Flag("-cl") },
    item_loaders: &[],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.1.34"),
        cmd: Some("go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@[install_version]"),
        github_handle: Some("projectdiscovery/mapcidr"),
        pre: &[("apk", &["libc6-compat"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_capture_hide],
    on_line: &[on_line_emit_ip],
    ..HookRegistry::EMPTY
};

/// Stash the `hide_ips` opt in ctx so `on_line` can tag IPs with `hidden` without
/// having to read runner state per line.
fn before_init_capture_hide(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    let hide = matches!(runner.opts.get("hide_ips").map(String::as_str), Some("true") | Some("True") | Some("1"));
    if hide {
        ctx.state.insert("mapcidr:hide".into(), "1".into());
    }
}

/// Per-line validator: emit `Ip{alive=false}` for valid IPv4/IPv6, drop other
/// lines unmodified (Python's `yield line` at the bottom is the runner's default
/// pass-through — we keep the line by returning `Some(line)`).
fn on_line_emit_ip(ctx: &mut HookCtx, line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let is_v4 = trimmed.parse::<Ipv4Addr>().is_ok();
    let is_v6 = trimmed.parse::<Ipv6Addr>().is_ok();
    if !is_v4 && !is_v6 {
        // Not an IP — let the runner echo it through as-is (Python `yield line`).
        return Some(line.to_string());
    }
    let hidden = ctx.state.contains_key("mapcidr:hide");
    ctx.extra_results.push(OutputItem::Ip(Ip {
        ip: trimmed.to_string(),
        alive: false,
        protocol: if is_v6 { "IPv6".into() } else { "IPv4".into() },
        tags: if hidden { vec!["hidden".into()] } else { Vec::new() },
        ..Default::default()
    }));
    // Python yields the line too (after the Ip), so the operator still sees the
    // raw IP in the CLI stream.
    Some(line.to_string())
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    // Recon meta opts (Python `ReconIp`), all marked unsupported here per Python
    // `opt_key_map` — mapcidr exposes none of them.
    s.meta_opts = crate::meta_opts::opts_recon();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    for k in ["delay", "threads", "proxy", "rate_limit", "retries", "timeout"] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Task-specific: `hide_ips` is internal (never emitted as a flag), only used
    // by the on_line hook to tag rather than display.
    s.opts = vec![OptSpec {
        name: "hide_ips",
        ty: OptType::Bool,
        short: Some("hi"),
        is_flag: true,
        default: None,
        help: "Hide IP addresses from CLI output (too verbose)",
        // Not `internal` — the user must be able to toggle this via the CLI.
        // KeyMap::NotSupported below prevents emission to the cmd line.
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s.key_map.insert("hide_ips".into(), KeyMap::NotSupported);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_line(line: &str, hide: bool) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        if hide {
            ctx.state.insert("mapcidr:hide".into(), "1".into());
        }
        on_line_emit_ip(&mut ctx, line);
        ctx.extra_results
    }

    #[test]
    fn ipv4_emits_ip_with_alive_false() {
        let out = run_line("10.0.0.1", false);
        assert_eq!(out.len(), 1);
        if let OutputItem::Ip(ip) = &out[0] {
            assert_eq!(ip.ip, "10.0.0.1");
            assert!(!ip.alive);
            assert_eq!(ip.protocol, "IPv4");
            assert!(ip.tags.is_empty());
        } else { panic!() }
    }

    #[test]
    fn ipv6_emits_ip_with_ipv6_protocol() {
        let out = run_line("2001:db8::1", false);
        if let OutputItem::Ip(ip) = &out[0] {
            assert_eq!(ip.protocol, "IPv6");
        } else { panic!() }
    }

    #[test]
    fn non_ip_line_emits_nothing() {
        assert!(run_line("not-an-ip", false).is_empty());
    }

    #[test]
    fn hide_ips_tags_the_ip() {
        let out = run_line("8.8.8.8", true);
        if let OutputItem::Ip(ip) = &out[0] {
            assert_eq!(ip.tags, vec!["hidden".to_string()]);
        } else { panic!() }
    }

    #[test]
    fn hide_ips_captured_from_opts() {
        let mut runner = CommandRunner::new(&SPEC, vec!["10.0.0.0/24".into()]);
        runner.opts.insert("hide_ips".into(), "true".into());
        let mut ctx = HookCtx::default();
        before_init_capture_hide(&mut ctx, &mut runner);
        assert!(ctx.state.contains_key("mapcidr:hide"));
    }

    #[test]
    fn hide_ips_does_not_leak_to_cmd_line() {
        let mut runner = CommandRunner::new(&SPEC, vec!["10.0.0.0/30".into()]);
        runner.opts.insert("hide_ips".into(), "true".into());
        let cmd = runner.build_cmd();
        assert!(!cmd.contains("hide-ips"), "got: {cmd}");
        assert!(!cmd.contains("--hi"), "got: {cmd}");
    }
}
