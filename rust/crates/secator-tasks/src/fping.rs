//! fping — ICMP echo probes (Python `secator/tasks/fping.py`).
//!
//! Output format depends on flags:
//!   * `-a -A` (default): one `<ip>` per alive host.
//!   * `-a -A -n` (`show_name=true`): `<hostname> (<ip>)`.
//!   * `-a -A -c <n>`: appends `: <stats>` after the IP — we strip it.
//!
//! Python `before_init` switches to `-g <cidr>` mode when any input looks like a
//! CIDR range; the rest of the time inputs come through `-f <file>` (multi) or
//! positional (single). Python also drops "Unreachable" stderr lines via `on_line`.

use secator_model::{Ip, Map, OutputItem};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode, Transform,
};
use secator_runner::{
    empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "fping",
    description: "Send ICMP echo probes to network hosts (multi-target ping).",
    cmd: "fping -a -A",
    input_types: &["ip", "host", "cidr_range"],
    output_types: &["ip"],
    tags: &["ip", "recon"],
    json_flag: None,
    // Default: positional for single input, `-f <file>` for many. CIDR detection
    // in `before_init` swaps to `-g <cidr>` (single CIDR per subprocess run).
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Flag("-f") },
    // Regex pattern matches either `host (ip)` or bare `ip`. We parse with two
    // named groups; the empty `host` capture for the bare-ip case becomes "".
    item_loaders: &[ItemLoader::Regex {
        pattern: r"^(?:(?P<host>[A-Za-z0-9.\-]+)\s+\()?(?P<ip>[0-9A-Fa-f.:]+)\)?",
        fields: &["host", "ip"],
    }],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: Some(on_regex_loaded),
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v5.1"),
        github_handle: Some("schweikert/fping"),
        github_bin: false,
        pre: &[("*", &["fping"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: true,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_cidr_mode],
    on_line: &[on_line_filter_unreachable],
    ..HookRegistry::EMPTY
};

/// Python `tasks/fping.py::before_init`. If any input parses as a CIDR
/// (`a.b.c.d/n` or `::/n`), switch to `-g <cidr>` single-input mode so fping
/// generates the range itself instead of expecting a file.
fn before_init_cidr_mode(_ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if runner.inputs.iter().any(|s| looks_like_cidr(s)) {
        runner.input_wiring_override = Some(InputWiring {
            single: SingleMode::Flag("-g"),
            file: FileMode::Unsupported,
        });
    }
}

fn looks_like_cidr(s: &str) -> bool {
    let Some((ip_part, mask_part)) = s.rsplit_once('/') else { return false };
    mask_part.parse::<u8>().is_ok()
        && (ip_part.parse::<std::net::Ipv4Addr>().is_ok()
            || ip_part.parse::<std::net::Ipv6Addr>().is_ok())
}

/// Python `on_line`: yield empty string when the line contains 'Unreachable'
/// (so the parser drops it). Our `on_line` returns `None` to drop entirely,
/// which is functionally equivalent.
fn on_line_filter_unreachable(_ctx: &mut HookCtx, line: &str) -> Option<String> {
    if line.contains("Unreachable") {
        None
    } else {
        Some(line.to_string())
    }
}

/// Build an `Ip(alive=true, ip, host?)` from the regex captures. Lines without
/// a valid IP capture are skipped.
pub fn on_regex_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let raw_ip = record
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_end_matches(')')
        // Strip the trailing `: <stats>` from `-c` mode.
        .split(':').next().unwrap_or("")
        .trim()
        .to_string();
    if raw_ip.is_empty() {
        return Vec::new();
    }
    let is_v4 = raw_ip.parse::<std::net::Ipv4Addr>().is_ok();
    let is_v6 = raw_ip.parse::<std::net::Ipv6Addr>().is_ok();
    if !is_v4 && !is_v6 {
        return Vec::new();
    }
    // Host: only keep it if it's not itself a literal IP (regex sometimes
    // captures `1.2.3.4` into the host slot when format is just the bare IP).
    let mut host = record
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        host = String::new();
    }
    vec![OutputItem::Ip(Ip {
        ip: raw_ip,
        host,
        alive: true,
        protocol: if is_v6 { "IPv6".into() } else { "IPv4".into() },
        tags: vec!["icmp".into()],
        ..Default::default()
    })]
}

/// Python `tasks/fping.py::opts` + `opt_key_map` + `opt_value_map`. fping uses
/// `--opt` for long opts; short opts come through the explicit map below.
fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // ReconIp = OPTS_RECON (delay/proxy/rate_limit/retries/threads/timeout).
    s.meta_opts = meta_opts::opts_recon();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python: delay/period in ms, timeout/timeout in ms (seconds → ms).
    s.key_map.insert("delay".into(), KeyMap::Flag("period".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retry".into()));
    s.key_map.insert("proxy".into(), KeyMap::NotSupported);
    s.key_map.insert("rate_limit".into(), KeyMap::NotSupported);
    s.key_map.insert("threads".into(), KeyMap::NotSupported);
    // Python `opt_value_map[DELAY/TIMEOUT] = lambda x: int(x) * 1000` (s → ms).
    s.value_map.insert("delay".into(), secator_options::ValueMap::Func(s_to_ms));
    s.value_map.insert("timeout".into(), secator_options::ValueMap::Func(s_to_ms));
    s.opts = vec![
        int_opt("count", Some("c"), "Number of request packets to send to each target"),
        flag("show_name", Some("n"), "Show network addresses as well as hostnames"),
        flag("use_dns", Some("d"), "Force reverse-DNS lookup for hostnames"),
        flag("summary", Some("s"), "Print cumulative statistics upon exit"),
    ];
    // fping's short flags don't match the long names — map explicitly.
    s.key_map.insert("count".into(), KeyMap::Flag("-c".into()));
    s.key_map.insert("show_name".into(), KeyMap::Flag("-n".into()));
    s.key_map.insert("use_dns".into(), KeyMap::Flag("-d".into()));
    s.key_map.insert("summary".into(), KeyMap::Flag("-s".into()));
    s
}

fn s_to_ms(v: &str) -> Option<String> {
    v.parse::<f64>().ok().map(|s| ((s * 1000.0) as i64).to_string())
}

const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn int_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Int, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

// `Transform` re-export for the assertion compiler check.
const _T: Transform = s_to_ms;

#[cfg(test)]
mod tests {
    use super::*;

    fn run(line: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        // Drive through both the on_line filter AND the regex loader.
        let kept = on_line_filter_unreachable(&mut ctx, line);
        let Some(kept_line) = kept else { return Vec::new() };
        // Use the spec's regex loader directly.
        let mut out = Vec::new();
        for loader in SPEC.item_loaders {
            for record in loader_records(loader, &kept_line) {
                out.extend(on_regex_loaded(&mut ctx, record));
            }
        }
        out
    }

    fn loader_records(loader: &ItemLoader, line: &str) -> Vec<Map> {
        use secator_parse::{RegexSerializer, Serializer};
        let ItemLoader::Regex { pattern, fields } = loader else { return Vec::new() };
        let fs: Vec<String> = fields.iter().map(|s| (*s).to_string()).collect();
        RegexSerializer::new(pattern, fs).map(|s| s.run(line)).unwrap_or_default()
    }

    #[test]
    fn parses_bare_ip_line() {
        let items = run("1.2.3.4");
        assert_eq!(items.len(), 1);
        if let OutputItem::Ip(ip) = &items[0] {
            assert_eq!(ip.ip, "1.2.3.4");
            assert!(ip.alive);
            assert_eq!(ip.protocol, "IPv4");
            assert_eq!(ip.host, "");
        } else { panic!() }
    }

    #[test]
    fn parses_host_paren_ip_line() {
        let items = run("foo.example.com (5.6.7.8)");
        assert_eq!(items.len(), 1);
        if let OutputItem::Ip(ip) = &items[0] {
            assert_eq!(ip.host, "foo.example.com");
            assert_eq!(ip.ip, "5.6.7.8");
        } else { panic!() }
    }

    #[test]
    fn drops_unreachable_lines() {
        assert!(run("Host 1.2.3.4 Unreachable").is_empty());
    }

    #[test]
    fn before_init_detects_cidr_and_switches_wiring() {
        let mut runner = CommandRunner::new(&SPEC, vec!["10.0.0.0/24".into()]);
        let mut ctx = HookCtx::default();
        before_init_cidr_mode(&mut ctx, &mut runner);
        assert!(runner.input_wiring_override.is_some());
    }

    #[test]
    fn before_init_keeps_default_wiring_for_host_inputs() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into(), "1.2.3.4".into()]);
        let mut ctx = HookCtx::default();
        before_init_cidr_mode(&mut ctx, &mut runner);
        assert!(runner.input_wiring_override.is_none());
    }
}
