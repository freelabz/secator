//! Built-in workflow registry. YAML files from `secator/configs/workflows/` are
//! embedded at compile time so the binary stays self-contained.

/// (name, raw yaml) pairs. Add new built-ins by referencing the upstream YAML.
pub const BUILT_IN: &[(&str, &str)] = &[
    (
        "cidr_recon",
        include_str!("../../../../secator/configs/workflows/cidr_recon.yaml"),
    ),
    (
        "code_scan",
        include_str!("../../../../secator/configs/workflows/code_scan.yaml"),
    ),
    (
        "domain_recon",
        include_str!("../../../../secator/configs/workflows/domain_recon.yaml"),
    ),
    (
        "host_recon",
        include_str!("../../../../secator/configs/workflows/host_recon.yaml"),
    ),
    (
        "subdomain_recon",
        include_str!("../../../../secator/configs/workflows/subdomain_recon.yaml"),
    ),
    (
        "url_bypass",
        include_str!("../../../../secator/configs/workflows/url_bypass.yaml"),
    ),
    (
        "url_crawl",
        include_str!("../../../../secator/configs/workflows/url_crawl.yaml"),
    ),
    (
        "url_dirsearch",
        include_str!("../../../../secator/configs/workflows/url_dirsearch.yaml"),
    ),
    (
        "url_fuzz",
        include_str!("../../../../secator/configs/workflows/url_fuzz.yaml"),
    ),
    (
        "url_params_fuzz",
        include_str!("../../../../secator/configs/workflows/url_params_fuzz.yaml"),
    ),
    (
        "url_secrets_hunt",
        include_str!("../../../../secator/configs/workflows/url_secrets_hunt.yaml"),
    ),
    (
        "url_vuln",
        include_str!("../../../../secator/configs/workflows/url_vuln.yaml"),
    ),
    (
        "user_hunt",
        include_str!("../../../../secator/configs/workflows/user_hunt.yaml"),
    ),
    (
        "wordpress",
        include_str!("../../../../secator/configs/workflows/wordpress.yaml"),
    ),
];

/// Lookup a workflow by name. Checks user-supplied YAML in
/// `~/.secator/templates/` first (when `init_user_templates` has run, which
/// `main.rs` does before building the CLI), then falls back to the static
/// `BUILT_IN` table. Returns the raw YAML body.
pub fn get(name: &str) -> Option<&'static str> {
    secator_templates::registry::workflows::get(name)
        .or_else(|| BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, yaml)| *yaml))
}

/// All known workflow names (user overlay merged with built-ins; user names
/// appear first so any clap subcommand iteration sees them at the top of the
/// `--help` output).
pub fn names() -> Vec<&'static str> {
    secator_templates::registry::workflows::names()
}
