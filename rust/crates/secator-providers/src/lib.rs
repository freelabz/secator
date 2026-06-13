//! CVE / GHSA enrichment (Python `secator/providers/`).
//!
//! Looks up a CVE id against a remote provider (Circl by default, GHSA via the
//! GitHub Advisory API), maps the response into [`Vulnerability`] fields
//! (`cvss_score`, `cvss_vec`, `severity`, `description`, `references`, affected
//! CPEs in `extra_data.cpes`), and caches the result under
//! `<data_dir>/cves/<cve_id>.json` so subsequent runs are offline.

pub mod cache;
pub mod circl;
pub mod exploitdb;
pub mod ghsa;
pub mod vulners;

use async_trait::async_trait;

use secator_model::Vulnerability;

pub use cache::{ExploitCache, LocalCache};
pub use circl::CirclProvider;
pub use exploitdb::ExploitDbProvider;
pub use ghsa::GhsaProvider;
pub use vulners::VulnersProvider;

#[derive(Debug, Clone)]
pub enum LookupError {
    /// Network / transport failure.
    Transport(String),
    /// Upstream returned non-2xx.
    Http(u16),
    /// Provider returned malformed JSON / unexpected shape.
    Decode(String),
    /// Returned 200 but no useful data (Circl returns `{}` for unknown CVEs).
    Empty,
    /// Cache I/O failed.
    Cache(String),
    /// Offline mode is on; remote queries are skipped.
    Offline,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Transport(s) => write!(f, "transport: {s}"),
            LookupError::Http(c) => write!(f, "http {c}"),
            LookupError::Decode(s) => write!(f, "decode: {s}"),
            LookupError::Empty => write!(f, "empty response"),
            LookupError::Cache(s) => write!(f, "cache: {s}"),
            LookupError::Offline => write!(f, "offline mode"),
        }
    }
}
impl std::error::Error for LookupError {}

/// A source that can resolve a CVE/GHSA id into a [`Vulnerability`].
#[async_trait]
pub trait CveProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Resolve a `CVE-YYYY-NNNN` / `GHSA-xxxx-xxxx-xxxx` id. Implementations may
    /// translate GHSA → CVE → fall back to the configured CVE provider.
    async fn lookup_cve(&self, id: &str) -> Result<Vulnerability, LookupError>;
}

/// A source that can fetch raw data for an exploit id (e.g. `EDB-NNNN`).
/// Python parity: the on-disk cache stores the upstream HTML page so downstream
/// consumers can grep it without re-hitting the network.
#[async_trait]
pub trait ExploitProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Resolve an exploit id (e.g. `EDB-49620`) to its upstream representation.
    /// Implementations return the raw page bytes; callers cache & post-process.
    async fn lookup_exploit(&self, id: &str) -> Result<String, LookupError>;
}

/// Cache + provider chain for exploit ids. Mirrors [`enrich_one`] but stores
/// strings (HTML) instead of Vulnerability objects.
pub async fn enrich_one_exploit(
    id: &str,
    cache: &ExploitCache,
    providers: &[Box<dyn ExploitProvider>],
) -> Option<String> {
    if let Ok(Some(s)) = cache.get(id) {
        secator_debug::debug!("exploit.cache", "{id}: cache hit");
        return Some(s);
    }
    for p in providers {
        match p.lookup_exploit(id).await {
            Ok(s) => {
                secator_debug::debug!("exploit", "{id}: enriched via {}", p.name());
                let _ = cache.put(id, &s);
                return Some(s);
            }
            Err(LookupError::Offline) => {
                secator_debug::debug!("exploit", "{id}: offline, skipping {}", p.name());
                return None;
            }
            Err(e) => {
                secator_debug::debug!("exploit", "{id}: {} failed ({e})", p.name());
            }
        }
    }
    None
}

/// Compose an ordered chain of providers + local cache. Returns the first hit.
/// Mirrors Python `Vuln.lookup_cve(cve_id)` which checks local first, then external.
pub async fn enrich_one(
    id: &str,
    cache: &LocalCache,
    providers: &[Box<dyn CveProvider>],
) -> Option<Vulnerability> {
    if let Ok(Some(v)) = cache.get(id) {
        secator_debug::debug!("cve.cache", "{id}: cache hit");
        return Some(v);
    }
    for p in providers {
        match p.lookup_cve(id).await {
            Ok(v) => {
                secator_debug::debug!("cve", "{id}: enriched via {}", p.name());
                let _ = cache.put(id, &v);
                return Some(v);
            }
            Err(LookupError::Offline) => {
                secator_debug::debug!("cve", "{id}: offline, skipping {}", p.name());
                return None;
            }
            Err(e) => {
                secator_debug::debug!("cve", "{id}: {} failed ({e})", p.name());
            }
        }
    }
    None
}

/// Merge enriched data INTO the in-place Vulnerability (overlay non-empty fields).
/// Python parity: cache hit fills cvss/severity/description/references but doesn't
/// clobber a higher-confidence local value (e.g. nuclei's preferred description).
pub fn merge_into(target: &mut Vulnerability, src: &Vulnerability) {
    if target.severity.is_empty() || target.severity == "unknown" {
        target.severity = src.severity.clone();
    }
    if target.cvss_score == 0.0 && src.cvss_score > 0.0 {
        target.cvss_score = src.cvss_score;
    }
    if target.cvss_vec.is_empty() {
        target.cvss_vec = src.cvss_vec.clone();
    }
    if target.epss_score == 0.0 && src.epss_score > 0.0 {
        target.epss_score = src.epss_score;
    }
    if target.description.is_empty() {
        target.description = src.description.clone();
    }
    if target.references.is_empty() {
        target.references = src.references.clone();
    }
    if target.reference.is_empty() {
        target.reference = src.reference.clone();
    }
    for t in &src.tags {
        if !target.tags.contains(t) {
            target.tags.push(t.clone());
        }
    }
    // Merge CPEs without overwriting existing extra_data fields.
    if let Some(src_cpes) = src.extra_data.get("cpes").cloned() {
        target.extra_data.entry("cpes".to_string()).or_insert(src_cpes);
    }
    target.post_init_via_serde();
}

// `post_init` is private on the trait; expose a small helper on Vulnerability via
// re-deriving the severity_nb / confidence_nb fields that depend on severity.
trait PostInitExt {
    fn post_init_via_serde(&mut self);
}
impl PostInitExt for Vulnerability {
    fn post_init_via_serde(&mut self) {
        use secator_model::OutputType;
        // Round-trip through to_map → load to fire post_init().
        let map = self.to_map();
        if let Some(refreshed) =
            Vulnerability::load(&map, &secator_model::OutputMap::new())
        {
            *self = refreshed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::Map;

    #[test]
    fn merge_fills_empty_fields_but_doesnt_clobber() {
        let mut target = Vulnerability {
            id: "CVE-2024-0001".into(),
            severity: "unknown".into(),
            description: String::new(),
            ..Default::default()
        };
        let src = Vulnerability {
            severity: "high".into(),
            cvss_score: 8.5,
            description: "Bad bug".into(),
            references: vec!["https://example.com/cve".into()],
            ..Default::default()
        };
        merge_into(&mut target, &src);
        assert_eq!(target.severity, "high");
        assert_eq!(target.cvss_score, 8.5);
        assert_eq!(target.description, "Bad bug");
        assert_eq!(target.references.len(), 1);
        // post_init re-derived severity_nb from "high".
        assert_eq!(target.severity_nb, 1);
    }

    #[test]
    fn merge_skips_when_target_has_value() {
        let mut target = Vulnerability {
            severity: "critical".into(),
            description: "local".into(),
            cvss_score: 9.5,
            ..Default::default()
        };
        let src = Vulnerability {
            severity: "low".into(),
            description: "remote".into(),
            cvss_score: 2.0,
            ..Default::default()
        };
        merge_into(&mut target, &src);
        // Existing critical wins.
        assert_eq!(target.severity, "critical");
        assert_eq!(target.cvss_score, 9.5);
        assert_eq!(target.description, "local");
    }

    #[test]
    fn merge_preserves_existing_cpes() {
        let mut target = Vulnerability::default();
        let mut existing_extra = Map::new();
        existing_extra.insert(
            "cpes".into(),
            serde_json::json!(["cpe:/a:vendor:app:1.0"]),
        );
        target.extra_data = existing_extra;
        let mut src = Vulnerability::default();
        src.extra_data.insert(
            "cpes".into(),
            serde_json::json!(["cpe:/a:other:lib:2.0"]),
        );
        merge_into(&mut target, &src);
        // Original CPE list kept; src's NOT appended (entry().or_insert).
        let cpes = target.extra_data.get("cpes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(cpes.len(), 1);
        assert_eq!(cpes[0], serde_json::json!("cpe:/a:vendor:app:1.0"));
    }
}
