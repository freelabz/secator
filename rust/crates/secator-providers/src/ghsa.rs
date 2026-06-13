//! GHSA → CVE → Circl chain (Python `secator/providers/ghsa.py`, minus the HTML
//! scraping). Uses GitHub's REST `advisories` endpoint:
//! `https://api.github.com/advisories/<GHSA_ID>`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

use secator_model::{Map, Vulnerability};

use crate::{CveProvider, LookupError};

pub struct GhsaProvider {
    client: Client,
    base_url: String,
    fallback: Option<Arc<dyn CveProvider>>,
    offline: bool,
}

impl GhsaProvider {
    pub fn new() -> Self {
        Self::with_base("https://api.github.com")
    }

    pub fn with_base(base: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("secator-rs/0.1")
            .build()
            .unwrap_or_else(|_| Client::new());
        GhsaProvider { client, base_url: base.into(), fallback: None, offline: false }
    }

    /// When set, GHSA → CVE id → fall back to this provider for the heavy fields
    /// (matching Python `ghsa.lookup_cve` which calls `CVEProvider.lookup_external_cve`).
    pub fn with_fallback(mut self, p: Arc<dyn CveProvider>) -> Self {
        self.fallback = Some(p);
        self
    }

    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }
}

impl Default for GhsaProvider {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl CveProvider for GhsaProvider {
    fn name(&self) -> &'static str { "ghsa" }

    async fn lookup_cve(&self, id: &str) -> Result<Vulnerability, LookupError> {
        if self.offline {
            return Err(LookupError::Offline);
        }
        if !id.starts_with("GHSA-") {
            return Err(LookupError::Decode(format!("not a GHSA id: {id}")));
        }
        let url = format!("{}/advisories/{id}", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| LookupError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(LookupError::Http(status.as_u16()));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| LookupError::Decode(e.to_string()))?;
        let mut vuln = parse_ghsa(&json);
        // Tag so callers can spot enrichments coming from this provider.
        if !vuln.tags.iter().any(|t| t == "ghsa") {
            vuln.tags.push("ghsa".into());
        }
        // Optional: hydrate the CVE side via the configured fallback when we
        // got a CVE id back. Mirrors Python's GHSA → external CVE delegation.
        if !vuln.id.is_empty() && vuln.id.starts_with("CVE-") {
            if let Some(p) = &self.fallback {
                if let Ok(cve_vuln) = p.lookup_cve(&vuln.id).await {
                    crate::merge_into(&mut vuln, &cve_vuln);
                }
            }
        }
        Ok(vuln)
    }
}

/// Map a GH advisory response into a `Vulnerability`. Field shape:
/// `{ghsa_id, cve_id, summary, severity, cvss: {score, vector_string},
///   identifiers, references[].url, vulnerabilities[].package, ...}`.
pub fn parse_ghsa(v: &Value) -> Vulnerability {
    let ghsa_id = v.get("ghsa_id").and_then(|x| x.as_str()).unwrap_or("");
    let cve_id = v.get("cve_id").and_then(|x| x.as_str()).unwrap_or("");
    let name = v
        .get("summary")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| ghsa_id.to_string());
    let description = v
        .get("description")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let severity = v
        .get("severity")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_lowercase();
    let cvss_score = v
        .get("cvss")
        .and_then(|x| x.get("score"))
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0);
    let cvss_vec = v
        .get("cvss")
        .and_then(|x| x.get("vector_string"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut references: Vec<String> = Vec::new();
    references.push(format!("https://github.com/advisories/{ghsa_id}"));
    if let Some(arr) = v.get("references").and_then(|x| x.as_array()) {
        for r in arr {
            if let Some(s) = r.get("url").and_then(|x| x.as_str()) {
                if !s.is_empty() && !references.contains(&s.to_string()) {
                    references.push(s.into());
                }
            }
        }
    }
    let reference = references.first().cloned().unwrap_or_default();

    // Collect affected package coordinates as informal "cpes" (pkg:ecosystem/name)
    // — Python does the same so downstream `match_cpes` can correlate.
    let mut cpes: Vec<Value> = Vec::new();
    if let Some(arr) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
        for entry in arr {
            let pkg = entry.get("package").and_then(|x| x.as_object());
            let (Some(eco), Some(nm)) = (
                pkg.and_then(|m| m.get("ecosystem").and_then(|v| v.as_str())),
                pkg.and_then(|m| m.get("name").and_then(|v| v.as_str())),
            ) else { continue };
            cpes.push(Value::String(format!("pkg:{eco}/{nm}")));
        }
    }

    let mut extra: Map = Map::new();
    extra.insert("cpes".into(), Value::Array(cpes));
    if !ghsa_id.is_empty() {
        extra.insert("ghsa_id".into(), Value::String(ghsa_id.into()));
    }

    Vulnerability {
        name,
        provider: "github-advisory".into(),
        // Prefer CVE id when available so cache key + Vulnerability.id align with
        // every other path through the system.
        id: if !cve_id.is_empty() { cve_id.into() } else { ghsa_id.into() },
        severity,
        cvss_score,
        cvss_vec,
        epss_score: 0.0,
        tags: Vec::new(),
        extra_data: extra,
        description,
        references,
        reference,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_advisory_response() {
        let v = json!({
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2024-0001",
            "summary": "Heap overflow",
            "severity": "HIGH",
            "cvss": {"score": 8.7, "vector_string": "CVSS:3.1/.../X"},
            "references": [{"url": "https://example.com/advisory"}],
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "lodash"}},
                {"package": {"ecosystem": "pypi", "name": "django"}}
            ]
        });
        let vuln = parse_ghsa(&v);
        assert_eq!(vuln.id, "CVE-2024-0001");
        assert_eq!(vuln.severity, "high");
        assert_eq!(vuln.cvss_score, 8.7);
        assert_eq!(vuln.name, "Heap overflow");
        assert_eq!(vuln.references.len(), 2);
        let cpes = vuln.extra_data.get("cpes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(cpes.len(), 2);
        assert_eq!(cpes[0], json!("pkg:npm/lodash"));
        assert_eq!(vuln.provider, "github-advisory");
        assert_eq!(
            vuln.extra_data.get("ghsa_id").and_then(|v| v.as_str()),
            Some("GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn falls_back_to_ghsa_id_when_no_cve() {
        let v = json!({
            "ghsa_id": "GHSA-only-no-cve",
            "summary": "Lonely advisory",
            "severity": "medium"
        });
        let vuln = parse_ghsa(&v);
        assert_eq!(vuln.id, "GHSA-only-no-cve");
        assert_eq!(vuln.severity, "medium");
    }
}
