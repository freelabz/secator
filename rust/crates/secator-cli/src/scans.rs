//! Built-in scan registry. Scans compose one or more workflows; only workflows
//! whose names are present in [`super::workflows::BUILT_IN`] can be referenced.
//! Mirrors Python's `secator/configs/scans/*.yaml`.

pub const BUILT_IN: &[(&str, &str)] = &[
    (
        "domain",
        include_str!("../../../../secator/configs/scans/domain.yaml"),
    ),
    (
        "host",
        include_str!("../../../../secator/configs/scans/host.yaml"),
    ),
    (
        "network",
        include_str!("../../../../secator/configs/scans/network.yaml"),
    ),
    (
        "subdomain",
        include_str!("../../../../secator/configs/scans/subdomain.yaml"),
    ),
    (
        "url",
        include_str!("../../../../secator/configs/scans/url.yaml"),
    ),
];

/// Lookup a scan by name. Checks user-supplied YAML in `~/.secator/templates/`
/// first (when `init_user_templates` has run), then the static `BUILT_IN`.
pub fn get(name: &str) -> Option<&'static str> {
    secator_templates::registry::scans::get(name)
        .or_else(|| BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, yaml)| *yaml))
}

/// All known scan names (user overlay merged with built-ins, user names first).
pub fn names() -> Vec<&'static str> {
    secator_templates::registry::scans::names()
}
