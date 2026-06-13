//! Built-in profile registry. Profiles are YAML files in
//! `secator/configs/profiles/` embedded at compile time; each declares a set of
//! opts (and an optional `enforce: true` flag) that get merged into the run's
//! `initial_opts` after CLI parsing. Mirrors Python's `Runner.resolve_profiles`.

use secator_templates::{load_from_str, ProfileDef, Template};

/// (name, raw yaml) pairs — every supported profile lives here.
pub const BUILT_IN: &[(&str, &str)] = &[
    ("active",        include_str!("../../../../secator/configs/profiles/active.yaml")),
    ("aggressive",    include_str!("../../../../secator/configs/profiles/aggressive.yaml")),
    ("all_ports",     include_str!("../../../../secator/configs/profiles/all_ports.yaml")),
    ("full",          include_str!("../../../../secator/configs/profiles/full.yaml")),
    ("http_headless", include_str!("../../../../secator/configs/profiles/http_headless.yaml")),
    ("http_record",   include_str!("../../../../secator/configs/profiles/http_record.yaml")),
    ("hunt_secrets",  include_str!("../../../../secator/configs/profiles/hunt_secrets.yaml")),
    ("insane",        include_str!("../../../../secator/configs/profiles/insane.yaml")),
    ("paranoid",      include_str!("../../../../secator/configs/profiles/paranoid.yaml")),
    ("passive",       include_str!("../../../../secator/configs/profiles/passive.yaml")),
    ("polite",        include_str!("../../../../secator/configs/profiles/polite.yaml")),
    ("sneaky",        include_str!("../../../../secator/configs/profiles/sneaky.yaml")),
    ("stealth",       include_str!("../../../../secator/configs/profiles/stealth.yaml")),
    ("tor",           include_str!("../../../../secator/configs/profiles/tor.yaml")),
];

pub fn names() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = secator_templates::registry::profiles::names();
    for (n, _) in BUILT_IN {
        if !out.contains(n) {
            out.push(*n);
        }
    }
    out
}

pub fn get(name: &str) -> Option<&'static str> {
    // User-supplied profiles in `~/.secator/templates/` win over built-ins.
    secator_templates::registry::profiles::get(name)
        .or_else(|| BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, y)| *y))
}

/// Load a parsed `ProfileDef` by name, or `None` if unknown / unparseable.
pub fn load(name: &str) -> Option<ProfileDef> {
    let yaml = get(name)?;
    match load_from_str(yaml).ok()? {
        Template::Profile(p) => Some(p),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_in_parses() {
        for (name, _) in BUILT_IN {
            let p = load(name).unwrap_or_else(|| panic!("profile {name} failed to parse"));
            assert_eq!(p.name, *name);
        }
    }

    #[test]
    fn aggressive_has_speed_opts() {
        let p = load("aggressive").unwrap();
        assert!(!p.enforce);
        assert!(p.opts.get(serde_yaml::Value::String("rate_limit".into())).is_some());
        assert!(p.opts.get(serde_yaml::Value::String("delay".into())).is_some());
    }

    #[test]
    fn passive_is_enforced() {
        let p = load("passive").unwrap();
        assert!(p.enforce);
    }
}
