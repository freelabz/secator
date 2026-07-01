//! arp — display the system ARP cache (Python `secator/tasks/arp.py`).
//!
//! `arp -a` prints one line per neighbor:
//!   `? (172.18.0.4) at 02:42:ac:12:00:04 [ether] on br-781c859806d7`
//!   `_gateway (192.168.59.254) at 00:50:56:f5:67:e7 [ether] on ens33`
//! We parse each line with a named-group regex and emit an `Ip` with the MAC,
//! physical type, and interface stashed in `extra_data`. Host is "" when the
//! name column is `?`. Tags = `["arp", "internal"]`.

use std::net::{Ipv4Addr, Ipv6Addr};

use secator_model::{Ip, Map, OutputItem};
use secator_options::{FileMode, InputWiring, OptSchema, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "arp",
    description: "Display the system ARP cache.",
    cmd: "arp -a",
    // Python `input_types` is unset and `default_inputs = ''` — task ignores inputs.
    input_types: &[],
    output_types: &["ip"],
    tags: &["ip", "recon"],
    json_flag: None,
    // No input wiring — `arp -a` reads the kernel ARP table.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    // Python uses a custom `item_loader` that runs once per stdout line; we model
    // it as a Regex serializer + `on_regex_loaded` callback.
    item_loaders: &[ItemLoader::Regex {
        pattern: r"^(?P<name>.+?)\s+\((?P<ip>[0-9.]+)\)\s+at\s+(?P<mac>[0-9a-f:]+)\s+\[(?P<physical>\w+)\]\s+on\s+(?P<interface>\S+)$",
        fields: &["name", "ip", "mac", "physical", "interface"],
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
        pre: &[("*", &["net-tools"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: true,
    default_inputs: Some(""),
};

static HOOKS: HookRegistry = HookRegistry { ..HookRegistry::EMPTY };

/// Build the `Ip` record from one regex match. Skips lines whose IP doesn't
/// validate (Python `validators.ipv4 or validators.ipv6`).
pub fn on_regex_loaded(_ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let ip = record
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if ip.is_empty() {
        return Vec::new();
    }
    let is_v4 = ip.parse::<Ipv4Addr>().is_ok();
    let is_v6 = ip.parse::<Ipv6Addr>().is_ok();
    if !is_v4 && !is_v6 {
        return Vec::new();
    }
    let raw_name = record.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
    let host = if raw_name == "?" { String::new() } else { raw_name.to_string() };
    let mac = record.get("mac").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let physical = record.get("physical").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let interface = record.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut extra: Map = Map::new();
    extra.insert("mac".into(), Value::String(mac));
    extra.insert("physical".into(), Value::String(physical));
    extra.insert("interface".into(), Value::String(interface));

    vec![OutputItem::Ip(Ip {
        ip,
        host,
        alive: true,
        protocol: if is_v6 { "IPv6".into() } else { "IPv4".into() },
        tags: vec!["arp".into(), "internal".into()],
        extra_data: extra,
        ..Default::default()
    })]
}

/// Python `opts = {}` — no user-facing flags. `requires_sudo = True` is a Python
/// runtime hint (the spec layer doesn't model it yet); operators run with sudo.
fn build_schema() -> OptSchema {
    OptSchema { opt_prefix: "-", ..OptSchema::default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{RegexSerializer, Serializer};

    fn parse(line: &str) -> Vec<OutputItem> {
        let mut ctx = HookCtx::default();
        let ItemLoader::Regex { pattern, fields } = SPEC.item_loaders[0] else { unreachable!() };
        let fs: Vec<String> = fields.iter().map(|s| (*s).to_string()).collect();
        let ser = RegexSerializer::new(pattern, fs).unwrap();
        ser.run(line)
            .into_iter()
            .flat_map(|m| on_regex_loaded(&mut ctx, m))
            .collect()
    }

    #[test]
    fn parses_named_neighbor() {
        let items = parse("_gateway (192.168.59.254) at 00:50:56:f5:67:e7 [ether] on ens33");
        assert_eq!(items.len(), 1);
        if let OutputItem::Ip(ip) = &items[0] {
            assert_eq!(ip.ip, "192.168.59.254");
            assert_eq!(ip.host, "_gateway");
            assert!(ip.alive);
            assert_eq!(ip.tags, vec!["arp".to_string(), "internal".into()]);
            assert_eq!(
                ip.extra_data.get("mac").and_then(|v| v.as_str()),
                Some("00:50:56:f5:67:e7")
            );
            assert_eq!(ip.extra_data.get("interface").and_then(|v| v.as_str()), Some("ens33"));
        } else { panic!() }
    }

    #[test]
    fn anonymous_neighbor_drops_host() {
        let items = parse("? (172.18.0.4) at 02:42:ac:12:00:04 [ether] on br-781c859806d7");
        assert_eq!(items.len(), 1);
        if let OutputItem::Ip(ip) = &items[0] {
            assert_eq!(ip.ip, "172.18.0.4");
            assert_eq!(ip.host, "");
        } else { panic!() }
    }

    #[test]
    fn skips_non_matching_lines() {
        assert!(parse("garbage line").is_empty());
    }
}
