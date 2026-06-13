//! netdetect — discover local network CIDR ranges (Python
//! `secator/tasks/netdetect.py`).
//!
//! Walks every non-loopback network interface, emits:
//!   * `Tag(info, name=net_interface, match=localhost, value=<iface name>)` per interface
//!   * `Ip(ip=<addr>, host=localhost, alive=true)` per IPv4 address
//!   * `Tag(info, name=net_cidr, match=localhost, value=<network/prefix>)` per IPv4 CIDR
//!
//! Tags carry `["internal"]`. Inputs are ignored — netdetect always inspects the
//! local machine.

use std::net::Ipv4Addr;

use secator_model::{Ip, OutputItem, Tag};
use secator_options::{OptSchema, RunOpts};
use secator_runner::{HookRegistry, NativeSpec, ValidatorRegistry};

pub static SPEC: NativeSpec = NativeSpec {
    name: "netdetect",
    description: "Detect local network CIDR ranges.",
    input_types: &[],
    output_types: &["ip", "tag"],
    tags: &["network", "recon"],
    run,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec::EMPTY,
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

fn run(_inputs: &[String], _opts: &RunOpts) -> Vec<OutputItem> {
    let mut out: Vec<OutputItem> = Vec::new();
    let adapters = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return out,
    };
    // Python `netdetect` walks adapters (each adapter has many IPs). `if-addrs`
    // returns one entry per IP — group by interface name so we emit one
    // `net_interface` tag per interface, then one `net_cidr` per IPv4 net.
    let mut seen_iface: std::collections::BTreeSet<String> = Default::default();
    for iface in adapters {
        let name = iface.name.clone();
        if name == "lo" || name.to_lowercase().starts_with("loopback") {
            continue;
        }
        if seen_iface.insert(name.clone()) {
            out.push(OutputItem::Tag(Tag {
                name: "net_interface".into(),
                match_: "localhost".into(),
                value: name.clone(),
                category: "info".into(),
                tags: vec!["internal".into()],
                ..Default::default()
            }));
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            let ip = v4.ip;
            let prefix = prefix_from_netmask_v4(v4.netmask);
            let cidr = match v4_network_str(ip, prefix) {
                Some(s) => s,
                None => continue,
            };
            out.push(OutputItem::Ip(Ip {
                ip: ip.to_string(),
                host: "localhost".into(),
                alive: true,
                tags: vec!["internal".into()],
                ..Default::default()
            }));
            out.push(OutputItem::Tag(Tag {
                name: "net_cidr".into(),
                match_: "localhost".into(),
                value: cidr,
                category: "info".into(),
                tags: vec!["internal".into()],
                ..Default::default()
            }));
        }
    }
    out
}

fn prefix_from_netmask_v4(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    bits.count_ones() as u8
}

/// Compute the CIDR network string for `<ip>/<prefix>` (e.g. `192.168.1.42/24`
/// → `192.168.1.0/24`). Returns `None` when the prefix is > 32.
fn v4_network_str(ip: Ipv4Addr, prefix: u8) -> Option<String> {
    if prefix > 32 {
        return None;
    }
    let ip_u = u32::from(ip);
    let mask = if prefix == 0 { 0u32 } else { u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0) };
    let net = ip_u & mask;
    Some(format!("{}/{prefix}", Ipv4Addr::from(net)))
}

fn build_schema() -> OptSchema {
    OptSchema { opt_prefix: "--", ..OptSchema::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_from_classful_masks() {
        assert_eq!(prefix_from_netmask_v4(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_from_netmask_v4(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(prefix_from_netmask_v4(Ipv4Addr::new(255, 255, 255, 128)), 25);
        assert_eq!(prefix_from_netmask_v4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn network_str_zeros_host_bits() {
        assert_eq!(
            v4_network_str(Ipv4Addr::new(192, 168, 1, 42), 24).unwrap(),
            "192.168.1.0/24"
        );
        assert_eq!(
            v4_network_str(Ipv4Addr::new(10, 0, 0, 5), 8).unwrap(),
            "10.0.0.0/8"
        );
        assert_eq!(
            v4_network_str(Ipv4Addr::new(172, 18, 0, 9), 12).unwrap(),
            "172.16.0.0/12"
        );
    }

    #[test]
    fn loopback_is_filtered_when_present() {
        // We can't easily fabricate adapters without if-addrs cooperation, so we
        // just smoke-test that `run` returns *something* without panicking. CI
        // boxes always have at least one non-loopback interface.
        let items = run(&[], &Default::default());
        // Every emitted Ip should be non-127.0.0.1 (loopback filtered).
        for item in &items {
            if let OutputItem::Ip(ip) = item {
                assert_ne!(ip.ip, "127.0.0.1");
            }
        }
    }
}
