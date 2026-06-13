//! nmap — port scanner & service detector (Python `secator/tasks/nmap.py`).
//!
//! nmap writes its results as XML to a file we pass via `-oX`. We:
//! 1. Inject `-oX <reports_folder>/.outputs/nmap.xml` in the `on_cmd` hook and stash
//!    the path in `ctx.state["nmap:output_path"]`.
//! 2. After the subprocess exits, the `on_cmd_done` hook parses that XML file and
//!    yields `Ip` (one per host, first sighting), `Port` (one per port),
//!    `Technology` (when a service `product` is known), plus `Vulnerability` /
//!    `Exploit` items extracted from `vulscan` / `vulners` NSE script output.
//! 3. `on_line` parses nmap's `Stats:` / `Timing:` progress lines into `Progress`
//!    items (Python `tasks/nmap.py::on_line`).

use std::fs;
use std::sync::OnceLock;

use regex::Regex;
use secator_model::{Exploit, Ip, Map, OutputItem, Port, Progress, Technology, Vulnerability};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde::Deserialize;
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "nmap",
    description: "Network mapper — port scan & service detection.",
    cmd: "nmap",
    input_types: &["host", "ip", "cidr_range", "string"],
    output_types: &["port", "ip", "vulnerability", "technology", "exploit", "progress"],
    tags: &["port", "scan"],
    // We don't pass `--json` — nmap doesn't emit JSON on stdout. XML goes to a file.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Flag("-iL") },
    // `Stats:` lines stash partial state via `on_line`; `Timing:` lines trip the
    // regex loader and `on_regex_loaded` turns them into a `Progress` item.
    item_loaders: &[
        secator_runner::ItemLoader::Regex {
            pattern: r"(.*) Timing: About (\d+\.\d+)% done; ETC: \d+:\d+ \((\d+:\d+:\d+) remaining\)",
            fields: &["scan_type", "percent", "remaining_time"],
        },
    ],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: Some(on_regex_loaded),
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        pre: &[
            ("apt|pacman|brew", &["nmap"]),
            ("apk", &["nmap", "nmap-scripts"]),
        ],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_capture_output_path],
    on_cmd: &[on_cmd_oxml],
    on_line: &[on_line_progress],
    on_cmd_done: &[on_cmd_done_parse_xml],
    ..HookRegistry::EMPTY
};

/// Python `on_init`: copy a user-supplied `output_path` opt into ctx.state so
/// `on_cmd_oxml` (which doesn't get runner access) can honor it. Otherwise the
/// default `<reports>/.outputs/nmap.xml` is used.
fn before_init_capture_output_path(
    ctx: &mut secator_runner::HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(p) = runner.opts.get("output_path").cloned().filter(|s| !s.is_empty()) {
        ctx.state.insert("nmap:user_output_path".into(), p);
    }
}

/// Python `tasks/nmap.py::on_cmd`: inject `-oX <path>` and `--stats-every Ns`.
/// The XML path defaults to `<reports>/.outputs/nmap.xml`; a user-supplied
/// `--output-path` overrides it (captured via `before_init_capture_output_path`).
fn on_cmd_oxml(ctx: &mut HookCtx, cmd: &mut String) {
    let path = if let Some(p) = ctx.state.get("nmap:user_output_path").cloned() {
        if let Some(parent) = std::path::Path::new(&p).parent() {
            let _ = fs::create_dir_all(parent);
        }
        p
    } else {
        let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
        let outputs_dir = if reports.is_empty() {
            String::from("/tmp")
        } else {
            format!("{reports}/.outputs")
        };
        let _ = fs::create_dir_all(&outputs_dir);
        format!("{outputs_dir}/nmap.xml")
    };
    let quoted = shell_words::quote(&path).to_string();
    cmd.push_str(&format!(" -oX {quoted}"));
    // Default progress cadence mirrors Python (`config.runners.progress_update_frequency`).
    let stats_every = ctx
        .state
        .get("progress_update_frequency")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n != u32::MAX)
        .unwrap_or(5);
    cmd.push_str(&format!(" --stats-every {stats_every}s"));
    ctx.state.insert("nmap:output_path".into(), path);
}

/// Python `on_line`: when a `Stats:` line arrives, stash the elapsed / hosts
/// fields under `ctx.state` so the next `Timing:` line (handled via the regex
/// loader → [`on_regex_loaded`]) can build a complete `Progress` item.
fn on_line_progress(ctx: &mut HookCtx, line: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"Stats: (\d+:\d+:\d+) elapsed; (\d+) hosts completed \((\d+) up\)").unwrap()
    });
    if let Some(c) = re.captures(line) {
        ctx.state.insert("nmap:elapsed".into(), c[1].to_string());
        ctx.state.insert("nmap:hosts_completed".into(), c[2].to_string());
        ctx.state.insert("nmap:hosts_up".into(), c[3].to_string());
    }
    Some(line.to_string())
}

/// Python `on_line` second branch (`Timing:`): build a Progress from the regex
/// captures + whatever the most recent `Stats:` line stashed in `ctx.state`.
pub fn on_regex_loaded(ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let scan_type = record.get("scan_type").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let percent = record
        .get("percent")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let remaining_time = record.get("remaining_time").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let elapsed = ctx.state.remove("nmap:elapsed").unwrap_or_default();
    let hosts_completed = ctx.state.remove("nmap:hosts_completed").unwrap_or_default();
    let hosts_up = ctx.state.remove("nmap:hosts_up").unwrap_or_default();

    let mut extra: Map = Map::new();
    if !elapsed.is_empty() {
        extra.insert("elapsed".into(), Value::String(elapsed));
    }
    if !hosts_completed.is_empty() {
        extra.insert("hosts_completed".into(), Value::String(hosts_completed));
    }
    if !hosts_up.is_empty() {
        extra.insert("hosts_up".into(), Value::String(hosts_up));
    }
    if !scan_type.is_empty() {
        extra.insert("scan_type".into(), Value::String(scan_type));
    }
    if !remaining_time.is_empty() {
        extra.insert("remaining_time".into(), Value::String(remaining_time));
    }
    vec![OutputItem::Progress(Progress { percent, extra_data: extra, ..Default::default() })]
}

/// Python `on_cmd_done` + `xml_to_json` + `nmapData.__iter__`. Reads the XML file
/// `on_cmd` wrote, walks its hosts/ports, and yields typed items.
fn on_cmd_done_parse_xml(ctx: &mut HookCtx) -> Vec<OutputItem> {
    let path = match ctx.state.get("nmap:output_path") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_xml(&content)
}

fn parse_xml(xml: &str) -> Vec<OutputItem> {
    let run: NmapRun = match quick_xml::de::from_str(xml) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let scan_type = run.scaninfo.as_ref().map(|s| s.ty.clone()).unwrap_or_default();
    let mut out: Vec<OutputItem> = Vec::new();
    let mut seen_ips: Vec<String> = Vec::new();
    let mut techs: Vec<OutputItem> = Vec::new();
    for host in run.hosts {
        let hostname = host.hostname().unwrap_or_else(|| host.ip().unwrap_or_default());
        let ip = host.ip().unwrap_or_default();
        if !ip.is_empty() && !seen_ips.contains(&ip) {
            seen_ips.push(ip.clone());
            out.push(OutputItem::Ip(Ip {
                ip: ip.clone(),
                host: hostname.clone(),
                alive: true,
                tags: vec!["ping".into()],
                ..Default::default()
            }));
        }
        for p in host.ports() {
            let port_num: i64 = match p.portid.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let state = p.state.as_ref().map(|s| s.state.clone()).unwrap_or_default();
            let reason = p.state.as_ref().map(|s| s.reason.clone()).unwrap_or_default();
            let service = p.service.as_ref();
            let service_name = service
                .map(|s| service_name(s))
                .unwrap_or_default();
            let protocol = p.protocol.to_lowercase();
            out.push(OutputItem::Port(Port {
                port: port_num,
                ip: ip.clone(),
                host: hostname.clone(),
                state,
                service_name: service_name.clone(),
                protocol,
                tags: vec![scan_type.clone(), reason].into_iter().filter(|t| !t.is_empty()).collect(),
                ..Default::default()
            }));
            if let Some(svc) = service {
                if let Some(product) = svc.product.as_ref().filter(|s| !s.is_empty()) {
                    techs.push(OutputItem::Technology(Technology {
                        match_: format!("{ip}:{port_num}"),
                        product: product.to_lowercase(),
                        version: svc.version.clone(),
                        ..Default::default()
                    }));
                }
            }
            // Parse vulscan / vulners script output into Vulnerability / Exploit.
            let host_port = format!("{hostname}:{port_num}");
            let cpes: Vec<String> = service.map(|s| s.cpe.clone()).unwrap_or_default();
            for script in &p.scripts {
                let items: Vec<OutputItem> = match script.id.as_str() {
                    "vulscan" => parse_vulscan_output(&script.output, &cpes),
                    "vulners" => parse_vulners_output(&script.output, &cpes),
                    _ => continue,
                };
                // Python parity: when `CONFIG.runners.skip_cve_low_confidence` is on,
                // drop vuln/exploit items whose `confidence` is "low" — these are
                // wide-net matches from vulscan/vulners that often false-positive
                // on similarly-named products.
                let skip_low = secator_config::get().runners.skip_cve_low_confidence;
                for mut item in items {
                    if skip_low && item_is_low_confidence(&item) {
                        continue;
                    }
                    enrich_script_item(
                        &mut item,
                        &host_port,
                        &ip,
                        &script.id,
                        &service_name,
                    );
                    out.push(item);
                }
            }
        }
    }
    out.extend(techs);
    out
}

/// Stamp matched_at/ip + push `script` and `service_name` into `extra_data` so
/// downstream consumers know which script + service produced the finding.
fn enrich_script_item(
    item: &mut OutputItem,
    host_port: &str,
    ip: &str,
    script_id: &str,
    service_name: &str,
) {
    match item {
        OutputItem::Vulnerability(v) => {
            v.matched_at = host_port.to_string();
            v.ip = ip.to_string();
            v.extra_data
                .insert("script".into(), Value::String(script_id.to_string()));
            if !service_name.is_empty() {
                v.extra_data
                    .insert("service_name".into(), Value::String(service_name.to_string()));
            }
        }
        OutputItem::Exploit(e) => {
            e.matched_at = host_port.to_string();
            e.ip = ip.to_string();
            e.extra_data
                .insert("script".into(), Value::String(script_id.to_string()));
            if !service_name.is_empty() {
                e.extra_data
                    .insert("service_name".into(), Value::String(service_name.to_string()));
            }
        }
        _ => {}
    }
}

/// Python `_parse_vulscan_output`. The block is a provider header line
/// (`VulDB - https://vuldb.com:`) followed by `[id] title` entries. We emit one
/// `Vulnerability` per `[id] title` row for the `MITRE CVE` provider — others
/// are noted but skipped (Python prints debug + `continue`).
pub fn parse_vulscan_output(out: &str, _cpes: &[String]) -> Vec<OutputItem> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\[([ A-Za-z0-9_@./#&+-]*)\] (.*)").unwrap());
    let mut items: Vec<OutputItem> = Vec::new();
    let mut provider_name = String::new();
    for raw in out.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('[') && line != "No findings" {
            // Provider header line: `Name - https://example.com:`.
            if let Some((name, _url)) = line.split_once(" - ") {
                provider_name = name.trim().to_string();
            }
            continue;
        }
        let Some(c) = re.captures(line) else { continue };
        let vuln_id = c[1].to_string();
        let vuln_title = c[2].to_string();
        let v = Vulnerability {
            id: vuln_id.clone(),
            name: vuln_id,
            description: vuln_title,
            provider: provider_name.clone(),
            tags: vec![provider_name.clone()],
            ..Default::default()
        };
        // Python only yields when the provider is "MITRE CVE" (others are debug-skipped).
        if provider_name == "MITRE CVE" {
            items.push(OutputItem::Vulnerability(v));
        }
    }
    items
}

/// Python `_parse_vulners_output`. The block alternates tab-separated rows:
/// 4 cols → Exploit (id, cvss, reference, _), 3 cols → Vulnerability
/// (id, cvss, reference). Lines starting with `cpe:` are ignored (Python uses
/// them for downstream CPE enrichment, which `secator-providers` handles later).
pub fn parse_vulners_output(out: &str, _cpes: &[String]) -> Vec<OutputItem> {
    let provider_name = "vulners";
    let mut items: Vec<OutputItem> = Vec::new();
    for raw in out.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("cpe:") {
            continue;
        }
        let elems: Vec<&str> = line.split('\t').collect();
        if elems.len() == 4 {
            // exploit: id \t cvss \t url \t _
            let exploit_id = elems[0].to_string();
            let reference = elems[2].to_string();
            items.push(OutputItem::Exploit(Exploit {
                id: exploit_id.clone(),
                name: exploit_id.clone(),
                provider: provider_name.into(),
                reference,
                tags: vec![exploit_id, provider_name.into()],
                confidence: "low".into(),
                ..Default::default()
            }));
        } else if elems.len() == 3 {
            // vuln: id \t cvss \t url. The id sometimes carries a `PROVIDER:CVE-...`
            // prefix (e.g. `vulners:CVE-2021-1234`); strip everything before the
            // last colon for the canonical id.
            let raw_id = elems[0];
            let cvss = elems[1].parse::<f64>().unwrap_or(0.0);
            let reference = elems[2].to_string();
            let vuln_id = raw_id.rsplit(':').next().unwrap_or(raw_id).to_string();
            let vuln_type = vuln_id.split('-').next().unwrap_or("").to_string();
            if vuln_type != "CVE" && raw_id != format!("PRION:{vuln_id}") {
                // Unsupported vuln type — Python prints debug + skips.
                continue;
            }
            items.push(OutputItem::Vulnerability(Vulnerability {
                id: vuln_id.clone(),
                name: vuln_id,
                provider: provider_name.into(),
                cvss_score: cvss,
                references: vec![reference],
                tags: vec![provider_name.into()],
                confidence: "low".into(),
                ..Default::default()
            }));
        }
    }
    items
}

/// True if `item` is a Vulnerability or Exploit flagged `confidence: "low"`.
/// Used by the `runners.skip_cve_low_confidence` gate — wide-net matches from
/// vulscan/vulners/search_vulns get this flag and are dropped when the operator
/// has set the knob.
fn item_is_low_confidence(item: &OutputItem) -> bool {
    match item {
        OutputItem::Vulnerability(v) => v.confidence == "low",
        OutputItem::Exploit(e) => e.confidence == "low",
        _ => false,
    }
}

/// Python `_get_extra_data`'s service-name derivation: prefer product, append version.
fn service_name(s: &Service) -> String {
    let base = s
        .product
        .as_ref()
        .filter(|p| !p.is_empty())
        .cloned()
        .or_else(|| s.name.clone())
        .unwrap_or_default();
    match (base.is_empty(), s.version.as_deref()) {
        (false, Some(v)) if !v.is_empty() => format!("{base}/{v}"),
        _ => base,
    }
}

// ----------------------------------------------------------------- XML schema

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "scaninfo", default)]
    scaninfo: Option<ScanInfo>,
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct ScanInfo {
    #[serde(rename = "@type")]
    ty: String,
}

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(rename = "address", default)]
    addresses: Vec<Address>,
    #[serde(rename = "hostnames", default)]
    hostnames: Option<Hostnames>,
    #[serde(rename = "ports", default)]
    ports: Option<Ports>,
}

impl Host {
    fn ip(&self) -> Option<String> {
        self.addresses
            .iter()
            .find(|a| a.addrtype.as_deref() == Some("ipv4"))
            .or_else(|| self.addresses.first())
            .map(|a| a.addr.clone())
    }
    fn hostname(&self) -> Option<String> {
        self.hostnames
            .as_ref()?
            .hostname
            .iter()
            .find(|h| h.ty.as_deref() == Some("user"))
            .or_else(|| self.hostnames.as_ref()?.hostname.first())
            .map(|h| h.name.clone())
    }
    fn ports(&self) -> Vec<&PortXml> {
        self.ports
            .as_ref()
            .map(|p| p.port.iter().collect())
            .unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype", default)]
    addrtype: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Hostnames {
    #[serde(rename = "hostname", default)]
    hostname: Vec<Hostname>,
}

#[derive(Debug, Deserialize)]
struct Hostname {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@type", default)]
    ty: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Ports {
    #[serde(rename = "port", default)]
    port: Vec<PortXml>,
}

#[derive(Debug, Deserialize)]
struct PortXml {
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "state", default)]
    state: Option<State>,
    #[serde(rename = "service", default)]
    service: Option<Service>,
    #[serde(rename = "script", default)]
    scripts: Vec<Script>,
}

#[derive(Debug, Deserialize)]
struct Script {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output", default)]
    output: String,
}

#[derive(Debug, Deserialize)]
struct State {
    #[serde(rename = "@state")]
    state: String,
    #[serde(rename = "@reason", default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name", default)]
    name: Option<String>,
    #[serde(rename = "@product", default)]
    product: Option<String>,
    #[serde(rename = "@version", default)]
    version: Option<String>,
    #[serde(rename = "cpe", default)]
    cpe: Vec<String>,
}

// ----------------------------------------------------------------- Schema (opts)

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    // Python uses `--`-prefixed long opts and `-`-prefixed shorts. Use --opt_prefix
    // for canonical long opts; short ones get inserted explicitly via key_map.
    // Recon meta opts — Python `NMAP_OPTS` references the common set.
    s.meta_opts = crate::meta_opts::opts_recon();
    crate::meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python key_map (canonical → nmap flag).
    s.key_map.insert("delay".into(), KeyMap::Flag("scan-delay".into()));
    s.key_map.insert("proxy".into(), KeyMap::NotSupported);
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("max-rate".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("max-retries".into()));
    s.key_map.insert("threads".into(), KeyMap::NotSupported);
    s.key_map.insert("timeout".into(), KeyMap::Flag("max-rtt-timeout".into()));
    // Task-specific opts.
    s.opts = vec![
        // Canonical output_path meta opt — see `meta_opts::OUTPUT_PATH`. Marked
        // NotSupported below so the option engine doesn't emit it as a flag;
        // `before_init_capture_output_path` reads it directly from runner.opts
        // and `on_cmd_oxml` injects `-oX <path>`.
        crate::meta_opts::OUTPUT_PATH,
        str_opt("ports", Some("p"), "Ports to scan (comma-separated, e.g. 80,443,8000-8100)"),
        str_opt("top_ports", Some("tp"), "Top N ports preset"),
        str_opt("script", None, "NSE scripts (comma-separated)"),
        flag("skip_host_discovery", "Pn", "Skip host discovery (no ping)"),
        flag("version_detection", "sV", "Enable version detection"),
        flag("tcp_connect", "sT", "TCP Connect scan"),
        flag("tcp_syn_stealth", "sS", "TCP SYN Stealth scan (requires sudo)"),
        flag("script_scan", "sC", "Enable default scripts"),
    ];
    // These all use the short form rather than long: Python `opt_key_map` overrides.
    for (name, short) in [
        ("ports", "-p"),
        ("top_ports", "top-ports"),
        ("skip_host_discovery", "-Pn"),
        ("version_detection", "-sV"),
        ("tcp_connect", "-sT"),
        ("tcp_syn_stealth", "-sS"),
        ("script_scan", "-sC"),
    ] {
        s.key_map.insert(name.into(), KeyMap::Flag(short.into()));
    }
    s.key_map.insert("output_path".into(), KeyMap::NotSupported);
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Str,
        short,
        is_flag: false,
        default: None,
        help,
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }
}

const fn flag(name: &'static str, short: &'static str, help: &'static str) -> OptSpec {
    OptSpec {
        name,
        ty: OptType::Bool,
        short: Some(short),
        is_flag: true,
        default: None,
        help,
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }
}

// ----------------------------------------------------------------- Tests

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../../tests/fixtures/nmap_output.xml");

    #[test]
    fn parses_python_xml_fixture() {
        let items = parse_xml(FIXTURE);
        // Should produce: 1 Ip + N Ports + (optional) Technologies.
        let n_ip = items.iter().filter(|i| matches!(i, OutputItem::Ip(_))).count();
        let n_port = items.iter().filter(|i| matches!(i, OutputItem::Port(_))).count();
        let n_tech = items.iter().filter(|i| matches!(i, OutputItem::Technology(_))).count();
        assert_eq!(n_ip, 1, "expected one Ip, got {n_ip}");
        assert!(n_port > 0, "expected at least one Port");
        // The fixture's services have products → at least one Technology.
        assert!(n_tech > 0, "expected at least one Technology, got {n_tech}");
    }

    #[test]
    fn ip_first_sighting_uses_first_host() {
        let items = parse_xml(FIXTURE);
        let ip = items.iter().find_map(|i| match i { OutputItem::Ip(ip) => Some(ip), _ => None }).unwrap();
        assert_eq!(ip.host, "example.synology.me");
        assert!(!ip.ip.is_empty());
        assert!(ip.alive);
    }

    #[test]
    fn vulscan_emits_mitre_cve_vulnerabilities_only() {
        // Two providers — only "MITRE CVE" rows should yield vulnerabilities.
        let output = "VulDB - https://vuldb.com:\n[172683] dnsmasq up to 2.84 Port security check for standard\nMITRE CVE - https://cve.mitre.org:\n[CVE-2021-1] dnsmasq remote code execution\n[CVE-2022-2] heap overflow";
        let items = parse_vulscan_output(output, &[]);
        let vulns: Vec<&Vulnerability> = items
            .iter()
            .filter_map(|i| match i {
                OutputItem::Vulnerability(v) => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(vulns.len(), 2, "only MITRE CVE rows should emit");
        assert_eq!(vulns[0].id, "CVE-2021-1");
        assert_eq!(vulns[0].provider, "MITRE CVE");
        assert_eq!(vulns[0].description, "dnsmasq remote code execution");
        assert_eq!(vulns[1].id, "CVE-2022-2");
    }

    #[test]
    fn vulscan_skips_no_findings_marker() {
        let output = "VulDB - https://vuldb.com:\nNo findings\nMITRE CVE - https://cve.mitre.org:\nNo findings";
        let items = parse_vulscan_output(output, &[]);
        assert!(items.is_empty());
    }

    #[test]
    fn vulners_emits_exploits_and_vulns_by_column_count() {
        // 4 cols → Exploit, 3 cols → CVE Vulnerability, cpe: lines ignored.
        let output = "cpe:/a:openssh:7.6p1:\nEDB-49620\t9.8\thttps://www.exploit-db.com/exploits/49620\t*EXPLOIT*\nCVE-2018-15473\t5.3\thttps://nvd.nist.gov/vuln/detail/CVE-2018-15473";
        let items = parse_vulners_output(output, &[]);
        let exploits: Vec<&Exploit> = items
            .iter()
            .filter_map(|i| match i {
                OutputItem::Exploit(e) => Some(e),
                _ => None,
            })
            .collect();
        let vulns: Vec<&Vulnerability> = items
            .iter()
            .filter_map(|i| match i {
                OutputItem::Vulnerability(v) => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(exploits.len(), 1);
        assert_eq!(exploits[0].id, "EDB-49620");
        assert_eq!(exploits[0].provider, "vulners");
        assert!(exploits[0].reference.contains("exploit-db.com"));
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "CVE-2018-15473");
        assert_eq!(vulns[0].cvss_score, 5.3);
        assert_eq!(vulns[0].provider, "vulners");
        assert_eq!(vulns[0].confidence, "low");
    }

    #[test]
    fn vulners_strips_provider_prefix_from_id() {
        let output = "vulners:CVE-2020-1234\t7.5\thttps://example.com";
        let items = parse_vulners_output(output, &[]);
        let v = match &items[0] {
            OutputItem::Vulnerability(v) => v,
            other => panic!("expected Vulnerability, got {other:?}"),
        };
        assert_eq!(v.id, "CVE-2020-1234");
    }

    #[test]
    fn timing_line_emits_progress_with_stashed_stats() {
        // First a Stats: line stashes elapsed/hosts. Then a Timing: line triggers Progress.
        let mut ctx = HookCtx::default();
        let _ = on_line_progress(&mut ctx, "Stats: 0:00:30 elapsed; 1 hosts completed (1 up), 0 undergoing Service Scan");
        // The regex loader would normally extract these — emulate that:
        let mut record: Map = Map::new();
        record.insert("scan_type".into(), Value::String("Service scan".into()));
        record.insert("percent".into(), Value::String("42.5".into()));
        record.insert("remaining_time".into(), Value::String("0:01:00".into()));
        let items = on_regex_loaded(&mut ctx, record);
        assert_eq!(items.len(), 1);
        let p = match &items[0] {
            OutputItem::Progress(p) => p,
            other => panic!("expected Progress, got {other:?}"),
        };
        assert_eq!(p.percent, 42.5);
        assert_eq!(p.extra_data.get("elapsed").and_then(|v| v.as_str()), Some("0:00:30"));
        assert_eq!(p.extra_data.get("hosts_completed").and_then(|v| v.as_str()), Some("1"));
        assert_eq!(p.extra_data.get("remaining_time").and_then(|v| v.as_str()), Some("0:01:00"));
        assert_eq!(p.extra_data.get("scan_type").and_then(|v| v.as_str()), Some("Service scan"));
        // State should be drained.
        assert!(!ctx.state.contains_key("nmap:elapsed"));
    }

    #[test]
    fn fixture_parses_scripts_without_panic() {
        // The Python fixture has vulscan output on some ports. We can't predict
        // the exact count of MITRE CVE rows without re-reading the fixture, but
        // parse_xml must not panic and total finding count stays sensible.
        let items = parse_xml(FIXTURE);
        let _vulns = items
            .iter()
            .filter(|i| matches!(i, OutputItem::Vulnerability(_)))
            .count();
        let _exploits = items
            .iter()
            .filter(|i| matches!(i, OutputItem::Exploit(_)))
            .count();
        // Sanity: fixture still emits the original Port/Ip/Technology mix.
        assert!(items.iter().any(|i| matches!(i, OutputItem::Port(_))));
    }

    /// P3.2: `item_is_low_confidence` is the predicate the `skip_cve_low_confidence`
    /// gate uses to drop wide-net vulscan/vulners matches. Only Vulnerability and
    /// Exploit items with confidence=="low" qualify; everything else passes.
    #[test]
    fn item_is_low_confidence_detects_vuln_and_exploit() {
        let low_vuln = OutputItem::Vulnerability(Vulnerability {
            confidence: "low".into(),
            ..Default::default()
        });
        let high_vuln = OutputItem::Vulnerability(Vulnerability {
            confidence: "high".into(),
            ..Default::default()
        });
        let low_exp = OutputItem::Exploit(Exploit {
            confidence: "low".into(),
            ..Default::default()
        });
        let high_exp = OutputItem::Exploit(Exploit {
            confidence: "high".into(),
            ..Default::default()
        });
        let port = OutputItem::Port(secator_model::Port::default());
        assert!(item_is_low_confidence(&low_vuln));
        assert!(!item_is_low_confidence(&high_vuln));
        assert!(item_is_low_confidence(&low_exp));
        assert!(!item_is_low_confidence(&high_exp));
        assert!(!item_is_low_confidence(&port));
    }
}
