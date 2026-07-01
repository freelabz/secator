//! dnsx — DNS toolkit (Python `secator/tasks/dnsx.py`).
//!
//! Two operating modes (Python `before_init` switches between them):
//!   1. **Resolve mode** (default): hosts are piped into dnsx on stdin
//!      (`echo <host> | dnsx ...`). Mirrors `input_flag = OPT_PIPE_INPUT`.
//!   2. **Wordlist / brute-force mode**: when `--wordlist` is set, dnsx receives
//!      each target via `-d <host>` and reads the wordlist from `-w <file>`.
//!      Python also injects `-rc noerror` if no return-code filter is given.
//!
//! Per-line output: one JSON record per response. `on_json_loaded` emits:
//!   * `Subdomain` when the record resolves cleanly (status=NOERROR) and the host
//!     is not an IP (we re-tag `sources=['dns']`, `verified=true`).
//!   * `Ip` for each A / AAAA / PTR record value.
//!   * `Record` for every record-type entry (Python `record_types`).
//!
//! Deferred from Python: the `validate_input` DNS-resolution pre-flight (drops
//! targets that return false-positive A records); needs a DNS resolver crate.

use secator_model::{Ip, Map, OutputItem, Record, Subdomain};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{
    empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};
use serde_json::Value;

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "dnsx",
    description:
        "Fast and multi-purpose DNS toolkit (resolve, probe, bruteforce).",
    cmd: "dnsx -resp -recon",
    input_types: &["host", "cidr_range", "ip"],
    output_types: &["record", "ip", "subdomain"],
    tags: &["dns", "fuzz"],
    json_flag: Some("-json"),
    // Python `input_flag = OPT_PIPE_INPUT`, `file_flag = OPT_PIPE_INPUT`. Switched
    // to `-d` mode by `before_init_wordlist_mode` when `wordlist` is set.
    input_wiring: InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe },
    item_loaders: &[ItemLoader::Json],
    // Python `input_chunk_size = -1` → no chunking. We use 0 (no chunking).
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.2.2"),
        cmd: Some("go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@[install_version]"),
        github_handle: Some("projectdiscovery/dnsx"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_wordlist_mode],
    ..HookRegistry::EMPTY
};

/// Python `tasks/dnsx.py::before_init`. When a wordlist is set, switch from
/// stdin-pipe input to `-d <host>` flag input (so dnsx can pair each host with
/// the wordlist's words) and default the return-code filter to `noerror` when
/// the user didn't supply one. Mirrors Python's mutation of `self.input_flag`,
/// `self.file_flag`, and `self.cmd`.
fn before_init_wordlist_mode(_ctx: &mut HookCtx, runner: &mut CommandRunner) {
    let wordlist = runner.opts.get("wordlist").cloned().unwrap_or_default();
    if wordlist.is_empty() {
        return;
    }
    runner.input_wiring_override = Some(InputWiring {
        single: SingleMode::Flag("-d"),
        file: FileMode::Flag("-d"),
    });
    let has_rc = runner.opts.get("rc").map(|s| !s.is_empty()).unwrap_or(false);
    if !has_rc {
        runner.cmd_suffix.push_str(" -rc noerror");
    }
}

/// Mirrors Python `on_json_loaded`. One JSON object per record. Emits at most
/// one Subdomain (if status=NOERROR and host isn't an IP) + one Ip per A/AAAA/
/// PTR value + one Record per record-type entry.
pub fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let host = item.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if host.is_empty() {
        return Vec::new();
    }
    let status_code = item.get("status_code").and_then(|v| v.as_str()).unwrap_or("");
    let is_ip = is_ip_v4(&host) || is_ip_v6(&host);
    let mut out: Vec<OutputItem> = Vec::new();
    if status_code == "NOERROR" && !is_ip {
        out.push(OutputItem::Subdomain(Subdomain {
            host: host.clone(),
            domain: extract_domain(&host),
            verified: true,
            sources: vec!["dns".into()],
            tags: vec!["dns".into()],
            ..Default::default()
        }));
    }
    let subdomains_only = ctx
        .state
        .get("dnsx:subdomains_only")
        .map(|s| s == "1")
        .unwrap_or(false);
    if subdomains_only {
        return out;
    }
    for &(record_kind, ip_proto, ip_tag) in &[
        ("a", Some("IPv4"), "a"),
        ("aaaa", Some("IPv6"), "aaaa"),
        ("cname", None, ""),
        ("mx", None, ""),
        ("ns", None, ""),
        ("txt", None, ""),
        ("srv", None, ""),
        ("ptr", Some("IPv4"), "ptr"),
        ("soa", None, ""),
        ("axfr", None, ""),
        ("caa", None, ""),
    ] {
        let values = match item.get(record_kind) {
            Some(Value::Array(a)) => a.clone(),
            Some(other) => vec![other.clone()],
            None => continue,
        };
        for value in values {
            let (name, extra) = parse_value(&value, &host);
            if name.is_empty() {
                continue;
            }
            // Ip emission for A/AAAA/PTR.
            if let Some(proto) = ip_proto {
                out.push(OutputItem::Ip(Ip {
                    host: host.clone(),
                    ip: name.clone(),
                    protocol: proto.into(),
                    alive: false,
                    tags: vec!["dns".into(), ip_tag.into()],
                    ..Default::default()
                }));
            }
            // Always emit the Record.
            out.push(OutputItem::Record(Record {
                host: host.clone(),
                name: name.clone(),
                type_: record_kind.to_uppercase(),
                extra_data: extra,
                tags: vec!["dns".into()],
                ..Default::default()
            }));
        }
    }
    out
}

/// Parse a DNS-record JSON value. Strings become `(value, {})`; objects use
/// their `name` field as the value and stash the rest under `extra_data`.
fn parse_value(v: &Value, fallback_host: &str) -> (String, Map) {
    match v {
        Value::String(s) => (s.clone(), Map::new()),
        Value::Object(m) => {
            let name = m
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or(fallback_host)
                .to_string();
            let mut extra = Map::new();
            for (k, val) in m {
                if k != "name" && k != "host" {
                    extra.insert(k.clone(), val.clone());
                }
            }
            (name, extra)
        }
        _ => (String::new(), Map::new()),
    }
}

fn is_ip_v4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}
fn is_ip_v6(s: &str) -> bool {
    s.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Mirrors Python `extract_domain_info(s, domain_only=True)` — best-effort:
/// return everything from the second-to-last label onward (a.b.example.com → example.com).
fn extract_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 | 1 => host.to_string(),
        2 => host.to_string(),
        n => parts[n - 2..].join("."),
    }
}

/// Python `opts` block + `opt_key_map` for dnsx.
fn build_schema() -> OptSchema {
    let mut s = OptSchema::default();
    // Meta opts: ReconDns = OPTS_RECON (delay/proxy/rate_limit/retries/threads/timeout).
    s.meta_opts = meta_opts::opts_recon();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python key_map.
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("rate-limit".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retry".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("threads".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("delay".into(), KeyMap::NotSupported);
    s.key_map.insert("timeout".into(), KeyMap::NotSupported);
    s.opts = vec![
        flag("trace", None, "Perform dns tracing"),
        str_opt("resolver", Some("r"), "List of resolvers to use (file or comma separated)"),
        str_opt("wildcard_domain", Some("wd"), "Domain name for wildcard filtering"),
        str_opt(
            "rc",
            Some("rc"),
            "DNS return code to filter (noerror, formerr, servfail, nxdomain, notimp, refused, yxdomain, xrrset, notauth, notzone)",
        ),
        flag("subdomains_only", Some("so"), "Only return subdomains"),
        str_opt("wordlist", Some("w"), "Wordlist to use (host bruteforce mode)"),
    ];
    s.key_map.insert("subdomains_only".into(), KeyMap::Flag("so".into()));
    s.key_map.insert("wordlist".into(), KeyMap::Flag("w".into()));
    s.key_map.insert("resolver".into(), KeyMap::Flag("r".into()));
    s.key_map.insert("wildcard_domain".into(), KeyMap::Flag("wd".into()));
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{JsonSerializer, Serializer};

    fn run_pipeline(line: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        JsonSerializer::new()
            .run(line)
            .into_iter()
            .flat_map(|rec| on_json_loaded(&mut ctx, rec))
            .collect()
    }

    #[test]
    fn parses_noerror_subdomain_with_a_records() {
        let line = r#"{"host":"git.example.com","status_code":"NOERROR","a":["1.2.3.4","5.6.7.8"]}"#;
        let items = run_pipeline(line);
        let subs: Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Subdomain(s) => Some(s), _ => None }).collect();
        let ips:  Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Ip(p) => Some(p), _ => None }).collect();
        let recs: Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Record(r) => Some(r), _ => None }).collect();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].host, "git.example.com");
        assert_eq!(subs[0].domain, "example.com");
        assert!(subs[0].verified);
        assert_eq!(ips.len(), 2);
        assert!(ips.iter().all(|p| p.protocol == "IPv4"));
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.type_ == "A"));
    }

    #[test]
    fn skips_subdomain_when_host_is_ip() {
        let line = r#"{"host":"1.2.3.4","status_code":"NOERROR","a":["1.2.3.4"]}"#;
        let items = run_pipeline(line);
        assert!(items.iter().all(|i| !matches!(i, OutputItem::Subdomain(_))));
    }

    #[test]
    fn subdomains_only_drops_other_records() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("dnsx:subdomains_only".into(), "1".into());
        let line = r#"{"host":"x.example.com","status_code":"NOERROR","a":["1.2.3.4"]}"#;
        let records = JsonSerializer::new().run(line);
        let items: Vec<OutputItem> = records
            .into_iter()
            .flat_map(|r| on_json_loaded(&mut ctx, r))
            .collect();
        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], OutputItem::Subdomain(_)));
    }

    #[test]
    fn before_init_switches_wiring_when_wordlist_set() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("wordlist".into(), "/tmp/words.txt".into());
        let mut ctx = HookCtx::default();
        before_init_wordlist_mode(&mut ctx, &mut runner);
        assert!(runner.input_wiring_override.is_some());
        assert!(runner.cmd_suffix.contains("-rc noerror"));
    }
}
