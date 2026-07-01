//! naabu — fast port scanner (Python `secator/tasks/naabu.py`).
//!
//! Output: one JSON object per line, shape `{"ip": "...", "port": 80, "host": "..."}`.
//! Emits one `Ip` (the first time we see a host) + one `Port` per record.

use secator_model::{Ip, Map, OutputItem, Port};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "naabu",
    description: "Port scanning tool written in Go.",
    cmd: "naabu",
    input_types: &["host", "ip"],
    output_types: &["port", "ip"],
    tags: &["port", "scan"],
    json_flag: Some("-json"),
    input_wiring: InputWiring {
        single: SingleMode::Flag("-host"),
        file: FileMode::Flag("-list"),
    },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v2.3.7"),
        cmd: Some("go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@[install_version]"),
        github_handle: Some("projectdiscovery/naabu"),
        pre: &[
            ("apt", &["libpcap-dev"]),
            ("apk", &["libpcap-dev", "libc6-compat"]),
            ("pacman|brew", &["libpcap"]),
        ],
        post: &[("arch|alpine|cachyos", "sudo ln -sf /usr/lib/libpcap.so /usr/lib/libpcap.so.0.8")],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps { proxychains: false, proxy_http: false, proxy_socks5: true },
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

fn build_schema() -> OptSchema {
    let mut s = OptSchema::default();
    // Recon meta opts (rate_limit/threads/timeout/proxy/...).
    s.meta_opts = meta_opts::opts_recon();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python key_map renames (canonical → naabu flag).
    s.key_map.insert("delay".into(), KeyMap::NotSupported);
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("rate".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retries".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("c".into()));
    // Task-specific opts.
    s.opts = vec![
        OptSpec {
            name: "ports",
            ty: OptType::Str,
            short: Some("p"),
            is_flag: false,
            default: None,
            help: "Ports to scan (comma-separated or ranges, e.g. \"80,443,8000-8100\")",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "top_ports",
            ty: OptType::Str,
            short: Some("tp"),
            is_flag: false,
            default: None,
            help: "Top N ports preset (e.g. \"100\", \"1000\", \"full\")",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "scan_type",
            ty: OptType::Str,
            short: Some("st"),
            is_flag: false,
            default: None,
            help: "Scan type (\"s\" SYN, \"c\" CONNECT)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    s.key_map.insert("ports".into(), KeyMap::Flag("port".into()));
    s.key_map.insert("top_ports".into(), KeyMap::Flag("top-ports".into()));
    s.key_map.insert("scan_type".into(), KeyMap::Flag("s".into()));
    s
}

/// Python `tasks/naabu.py::on_json_loaded` equivalent. Each record is `{ip, port,
/// host}`. Emit an `Ip` only on the **first** sighting of a host within this run,
/// then a `Port` for every record. Python keeps `self.hosts = []` (initialized in
/// `before_init`) and gates `yield Ip()` on `if host not in self.hosts`; the
/// per-run [`HookCtx::state`] is the equivalent scratchpad.
pub fn on_json_loaded(ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    let ip = record.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let port = record.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
    if ip.is_empty() || port == 0 {
        return Vec::new();
    }
    let raw_host = record.get("host").and_then(|v| v.as_str()).unwrap_or(&ip).to_string();
    let host = if raw_host == "127.0.0.1" { "localhost".to_string() } else { raw_host };
    let mut out = Vec::new();
    let seen_key = format!("naabu:seen-host:{host}");
    if !ctx.state.contains_key(&seen_key) {
        ctx.state.insert(seen_key, "1".into());
        out.push(OutputItem::Ip(Ip {
            ip: ip.clone(),
            host: host.clone(),
            alive: true,
            tags: vec!["ping".into()],
            ..Default::default()
        }));
    }
    out.push(OutputItem::Port(Port {
        ip,
        port,
        host,
        state: "open".into(),
        tags: vec!["connect".into()],
        ..Default::default()
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{JsonSerializer, Serializer};
    use secator_runner::CommandRunner;

    /// Drive a JSON line through the same path the runner uses at runtime.
    fn run_pipeline(line: &str, ctx: &mut HookCtx) -> Vec<OutputItem> {
        JsonSerializer::new()
            .run(line)
            .into_iter()
            .flat_map(|rec| on_json_loaded(ctx, rec))
            .collect()
    }

    #[test]
    fn parses_naabu_json_line() {
        let line = r#"{"ip":"93.184.216.34","port":443,"host":"example.com"}"#;
        let items = run_pipeline(line, &mut HookCtx::default());
        assert_eq!(items.len(), 2);
        match (&items[0], &items[1]) {
            (OutputItem::Ip(ip), OutputItem::Port(p)) => {
                assert_eq!(ip.ip, "93.184.216.34");
                assert_eq!(ip.host, "example.com");
                assert!(ip.alive);
                assert_eq!(p.port, 443);
                assert_eq!(p.host, "example.com");
                assert_eq!(p.state, "open");
            }
            _ => panic!("expected Ip then Port"),
        }
    }

    #[test]
    fn host_falls_back_to_ip_when_missing() {
        let line = r#"{"ip":"1.2.3.4","port":80}"#;
        let items = run_pipeline(line, &mut HookCtx::default());
        assert_eq!(items.len(), 2);
        if let OutputItem::Port(p) = &items[1] {
            assert_eq!(p.host, "1.2.3.4");
        }
    }

    #[test]
    fn localhost_normalization() {
        let line = r#"{"ip":"127.0.0.1","port":22,"host":"127.0.0.1"}"#;
        let items = run_pipeline(line, &mut HookCtx::default());
        if let OutputItem::Port(p) = &items[1] {
            assert_eq!(p.host, "localhost");
        }
    }

    #[test]
    fn ip_emitted_only_on_first_sighting() {
        // Same host, two records ⇒ 1 Ip + 2 Ports.
        let mut ctx = HookCtx::default();
        let mut out = run_pipeline(r#"{"ip":"1.1.1.1","port":80,"host":"a.com"}"#, &mut ctx);
        out.extend(run_pipeline(
            r#"{"ip":"1.1.1.1","port":443,"host":"a.com"}"#,
            &mut ctx,
        ));
        let n_ip = out.iter().filter(|i| matches!(i, OutputItem::Ip(_))).count();
        let n_port = out.iter().filter(|i| matches!(i, OutputItem::Port(_))).count();
        assert_eq!((n_ip, n_port), (1, 2));
    }

    #[test]
    fn schema_renames_threads_to_c() {
        let mut runner = CommandRunner::new(&SPEC, vec!["example.com".into()]);
        runner.opts.insert("threads".into(), "200".into());
        let cmd = runner.build_cmd();
        assert!(cmd.contains("-c 200"), "got: {cmd}");
        assert!(!cmd.contains("-threads"), "got: {cmd}");
    }
}
