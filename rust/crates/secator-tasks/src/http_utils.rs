//! Helpers shared between HTTP-flavoured tasks (httpx, katana, ffuf, ...).

use secator_model::{Technology, Url};

/// Mirrors Python `Url.get_techs()`. Each tech entry is normalized (strip
/// `_/():` punctuation → spaces) and split into `(product, version)` via the
/// `VERSION_SIMPLE` regex. Tokens without a parseable version still emit a
/// `Technology` with `product = <raw>` and no version.
pub fn get_techs(url: &Url) -> Vec<Technology> {
    url.tech
        .iter()
        .map(|raw| {
            let normalized: String = raw
                .chars()
                .map(|c| if matches!(c, '_' | '/' | '(' | ')' | ':') { ' ' } else { c })
                .collect();
            let (product, version) = extract_software_and_version(normalized.trim());
            Technology {
                match_: url.url.clone(),
                product: product.unwrap_or_else(|| raw.clone()),
                version,
                ..Default::default()
            }
        })
        .collect()
}

/// Mirrors Python `cve.extract_software_and_version` (non-postfix flavour):
/// regex `(NAME)\s+(VERSION)` where NAME = letters/spaces, VERSION = `N.N(.N)*`.
pub fn extract_software_and_version(s: &str) -> (Option<String>, Option<String>) {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"([a-zA-Z][a-zA-Z\s]*?)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*)").unwrap()
    });
    if let Some(caps) = re.captures(s) {
        let name = caps.get(1).map(|m| m.as_str().trim().to_lowercase());
        let version = caps.get(2).map(|m| m.as_str().trim().to_string());
        if let (Some(n), v) = (name, version) {
            return (Some(n), v);
        }
    }
    (None, None)
}

/// Postfix flavour of `extract_software_and_version` — accepts versions
/// trailing a single-letter+digit suffix (e.g. `7.6p1`). Mirrors Python
/// `cve.extract_software_and_version(..., postfix=True)`.
pub fn extract_software_and_version_postfix(s: &str) -> (Option<String>, Option<String>) {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"([a-zA-Z][a-zA-Z\s]*?)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:[a-zA-Z][0-9])*)")
            .unwrap()
    });
    if let Some(caps) = re.captures(s) {
        let name = caps.get(1).map(|m| m.as_str().trim().to_lowercase());
        let version = caps.get(2).map(|m| m.as_str().trim().to_string());
        if let (Some(n), v) = (name, version) {
            return (Some(n), v);
        }
    }
    (None, None)
}
