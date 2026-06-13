//! arpscan — `arp-scan` wrapper for ARP host discovery (Python
//! `secator/tasks/arpscan.py`).
//!
//! Each line of stdout (in `--plain` + tab-delimited custom format) is:
//!   `<ip>\t<name>\t<mac>\t<vendor>`
//! Other lines may be `WARNING: …` (→ `Warning`) or `permission denied` errors
//! (→ `Error` with a CAP_NET_RAW hint). `before_init` switches to `--localnet`
//! when the runner has no inputs.

use secator_model::{Error, Info, Ip, Map, OutputItem, Warning};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "arpscan",
    description: "Scan a CIDR range for alive hosts using ARP.",
    cmd: r#"arp-scan --plain --resolve --format="${ip}\t${name}\t${mac}\t${vendor}""#,
    input_types: &["cidr_range", "ip", "host"],
    output_types: &["ip"],
    tags: &["ip", "recon"],
    json_flag: None,
    // Python `input_flag = None` + `file_flag = '-f'` ⇒ no per-input flag (multiple
    // targets land in the file path arg). Single target: positional.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Flag("-f") },
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
        github_handle: Some("royhills/arp-scan"),
        github_bin: false,
        pre: &[("*", &["arp-scan"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: true,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_localnet],
    on_line: &[on_line_emit],
    ..HookRegistry::EMPTY
};

/// Python `on_cmd`: when no inputs are supplied, append `--localnet` and emit
/// an `Info`. The Rust spec already supports `--localnet` as an opt; here we
/// mark the "no-input → localnet" path so `build_cmd` knows to skip the
/// missing-arg complaint and the user gets the expected behavior.
fn before_init_localnet(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if runner.inputs.is_empty() {
        // Append the flag via cmd_suffix so it lands after the schema-driven opts.
        if !runner.cmd_suffix.contains("--localnet") {
            if !runner.cmd_suffix.is_empty() && !runner.cmd_suffix.ends_with(' ') {
                runner.cmd_suffix.push(' ');
            }
            runner.cmd_suffix.push_str("--localnet");
        }
        ctx.extra_results.push(OutputItem::Info(Info {
            message: "No input passed to arpscan, scanning local network".into(),
            ..Default::default()
        }));
    }
}

/// Python `on_line`: route WARNING / permission lines to Warning/Error items,
/// otherwise parse the four-column tab record into an `Ip`. Lines are always
/// kept (Python `yield line`), so we return `Some(line)`.
fn on_line_emit(ctx: &mut HookCtx, line: &str) -> Option<String> {
    if line.contains("WARNING:") {
        if let Some((_, after)) = line.split_once("WARNING:") {
            ctx.extra_results.push(OutputItem::Warning(Warning {
                message: after.trim().to_string(),
                ..Default::default()
            }));
        }
        return Some(line.to_string());
    }
    if line.contains("permission") {
        let hint = "You must [bold]run this task as root[/bold] to scan the network, or use \
            [green]sudo setcap cap_net_raw=eip /usr/sbin/arp-scan[/green] to grant the \
            [bold]CAP_NET_RAW[/bold] capability to the [bold]arp-scan[/bold] binary.";
        ctx.extra_results.push(OutputItem::Error(Error {
            message: format!("{line}\n{hint}"),
            ..Default::default()
        }));
        return Some(line.to_string());
    }
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() == 4 {
        let mut extra: Map = Map::new();
        extra.insert("mac".into(), Value::String(parts[2].into()));
        extra.insert("vendor".into(), Value::String(parts[3].into()));
        ctx.extra_results.push(OutputItem::Ip(Ip {
            ip: parts[0].trim().into(),
            host: parts[1].trim().into(),
            alive: true,
            tags: vec!["arp".into(), "internal".into()],
            extra_data: extra,
            ..Default::default()
        }));
    }
    Some(line.to_string())
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.opts = vec![
        flag("resolve", Some("r"), "Resolve IP addresses to hostnames"),
        str_opt("interface", Some("i"), "Interface to use"),
        flag("localnet", Some("l"), "Scan local network"),
        str_opt("ouifile", Some("o"), "Use IEEE registry vendor mapping file."),
        str_opt("macfile", Some("m"), "Use custom vendor mapping file."),
    ];
    // arp-scan exposes none of the recon meta opts; drop the canonical set.
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s
}

const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emit(line: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        on_line_emit(&mut ctx, line);
        ctx.extra_results
    }

    #[test]
    fn parses_four_column_ip_line() {
        let items = emit("192.168.1.10\thost.lan\taa:bb:cc:dd:ee:ff\tCisco");
        assert_eq!(items.len(), 1);
        if let OutputItem::Ip(ip) = &items[0] {
            assert_eq!(ip.ip, "192.168.1.10");
            assert_eq!(ip.host, "host.lan");
            assert!(ip.alive);
            assert_eq!(
                ip.extra_data.get("mac").and_then(|v| v.as_str()),
                Some("aa:bb:cc:dd:ee:ff")
            );
            assert_eq!(ip.extra_data.get("vendor").and_then(|v| v.as_str()), Some("Cisco"));
        } else { panic!() }
    }

    #[test]
    fn warning_line_emits_warning() {
        let items = emit("WARNING: spoofed reply");
        assert_eq!(items.len(), 1);
        if let OutputItem::Warning(w) = &items[0] {
            assert_eq!(w.message, "spoofed reply");
        } else { panic!() }
    }

    #[test]
    fn permission_line_emits_error_with_capnetraw_hint() {
        let items = emit("arp-scan: pcap_open_live: permission denied");
        assert_eq!(items.len(), 1);
        if let OutputItem::Error(e) = &items[0] {
            assert!(e.message.contains("permission denied"));
            assert!(e.message.contains("CAP_NET_RAW"));
        } else { panic!() }
    }

    #[test]
    fn before_init_appends_localnet_when_no_inputs() {
        let mut runner = CommandRunner::new(&SPEC, Vec::new());
        let mut ctx = HookCtx::default();
        before_init_localnet(&mut ctx, &mut runner);
        assert!(runner.cmd_suffix.contains("--localnet"));
        assert!(ctx
            .extra_results
            .iter()
            .any(|i| matches!(i, OutputItem::Info(_))));
    }

    #[test]
    fn before_init_leaves_cmd_alone_when_inputs_present() {
        let mut runner = CommandRunner::new(&SPEC, vec!["10.0.0.0/24".into()]);
        let mut ctx = HookCtx::default();
        before_init_localnet(&mut ctx, &mut runner);
        assert!(!runner.cmd_suffix.contains("--localnet"));
        assert!(ctx.extra_results.is_empty());
    }
}
