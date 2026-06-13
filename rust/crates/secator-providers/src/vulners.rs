//! Vulners CVE provider — Python `providers/vulners.py`.
//!
//! Paid API at `https://vulners.com/api/v3/search/id`. POSTs the CVE id and
//! maps the response into [`Vulnerability`] fields. Gated on
//! `addons.vulners.api_key`; returns `LookupError::Offline` when no key is
//! configured so the provider chain falls through to the next entry.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

use secator_config::VulnersAddon;
use secator_model::{Map, Vulnerability};

use crate::{CveProvider, LookupError};

pub struct VulnersProvider {
    client: Client,
    base_url: String,
    api_key: String,
    enabled: bool,
}

impl VulnersProvider {
    pub fn new() -> Self {
        Self::with_base("https://vulners.com")
    }

    pub fn with_base(base: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("secator-rs/0.1")
            .build()
            .unwrap_or_else(|_| Client::new());
        VulnersProvider {
            client,
            base_url: base.into(),
            api_key: String::new(),
            enabled: false,
        }
    }

    pub fn from_config(cfg: VulnersAddon) -> Self {
        let mut p = Self::new();
        p.api_key = cfg.api_key;
        p.enabled = cfg.enabled;
        p
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = key.into();
        self.enabled = true;
        self
    }
}

impl Default for VulnersProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CveProvider for VulnersProvider {
    fn name(&self) -> &'static str {
        "vulners"
    }

    async fn lookup_cve(&self, id: &str) -> Result<Vulnerability, LookupError> {
        if !self.enabled || self.api_key.is_empty() {
            // Treat "no key configured" as offline so the chain falls through
            // cleanly to the next provider instead of surfacing a hard error.
            return Err(LookupError::Offline);
        }
        let url = format!(
            "{}/api/v3/search/id",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "id": id,
            "fields": ["*"],
            "apiKey": self.api_key,
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
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
        // Vulners wraps the document in `data.documents.<id>`.
        let doc = json
            .get("data")
            .and_then(|d| d.get("documents"))
            .and_then(|d| d.get(id))
            .ok_or(LookupError::Empty)?;
        Ok(map_document(id, doc))
    }
}

/// Map a Vulners bulletin document to our `Vulnerability`. The Vulners shape
/// varies between products (cve/exploitdb/seebug/...); we read the common
/// fields and stash the rest on `extra_data.cpes` so it's still queryable.
fn map_document(id: &str, doc: &Value) -> Vulnerability {
    let mut v = Vulnerability::default();
    v.id = id.into();
    v.name = id.into();
    v.provider = "vulners".into();
    if let Some(title) = doc.get("title").and_then(|x| x.as_str()) {
        v.name = title.into();
    }
    if let Some(desc) = doc.get("description").and_then(|x| x.as_str()) {
        v.description = desc.into();
    }
    if let Some(score) = doc.get("cvss").and_then(|c| c.get("score")).and_then(|x| x.as_f64()) {
        v.cvss_score = score;
    }
    if let Some(vec) = doc.get("cvss").and_then(|c| c.get("vector")).and_then(|x| x.as_str()) {
        v.cvss_vec = vec.into();
    }
    if let Some(severity) = doc.get("cvss").and_then(|c| c.get("severity")).and_then(|x| x.as_str()) {
        v.severity = severity.to_lowercase();
    }
    if let Some(epss) = doc.get("epss").and_then(|e| e.get("score")).and_then(|x| x.as_f64()) {
        v.epss_score = epss;
    }
    if let Some(refs) = doc.get("references").and_then(|x| x.as_array()) {
        v.references = refs
            .iter()
            .filter_map(|r| r.as_str().map(String::from))
            .collect();
        if let Some(first) = v.references.first() {
            v.reference = first.clone();
        }
    }
    // CPEs (Python parity: `extra_data.cpes`).
    if let Some(cpes) = doc.get("cpe").and_then(|x| x.as_array()) {
        let mut ed: Map = Map::new();
        ed.insert("cpes".into(), Value::Array(cpes.clone()));
        v.extra_data = ed;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_key_returns_offline() {
        let p = VulnersProvider::new(); // enabled=false, key=""
        assert!(matches!(p.lookup_cve("CVE-2024-1").await, Err(LookupError::Offline)));
    }

    #[tokio::test]
    async fn empty_key_with_enabled_addon_still_offline() {
        // from_config: enabled=true, key="" → treat as offline (Python returns
        // None on the same path).
        let cfg = VulnersAddon { enabled: true, api_key: String::new() };
        let p = VulnersProvider::from_config(cfg);
        assert!(matches!(p.lookup_cve("CVE-2024-1").await, Err(LookupError::Offline)));
    }

    #[tokio::test]
    async fn successful_lookup_maps_cvss_and_refs() {
        use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/search/id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "documents": {
                        "CVE-2021-44228": {
                            "title": "log4j RCE",
                            "description": "Apache Log4j2 vulnerability",
                            "cvss": {"score": 10.0, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"},
                            "epss": {"score": 0.97},
                            "references": ["https://nvd.nist.gov/x", "https://example.com/y"],
                            "cpe": ["cpe:2.3:a:apache:log4j:*"]
                        }
                    }
                }
            })))
            .mount(&server)
            .await;
        let p = VulnersProvider::with_base(server.uri()).with_key("test-key");
        let v = p.lookup_cve("CVE-2021-44228").await.expect("ok");
        assert_eq!(v.id, "CVE-2021-44228");
        assert_eq!(v.name, "log4j RCE");
        assert_eq!(v.cvss_score, 10.0);
        assert_eq!(v.severity, "critical");
        assert_eq!(v.cvss_vec, "CVSS:3.1/AV:N");
        assert_eq!(v.epss_score, 0.97);
        assert_eq!(v.references.len(), 2);
        assert_eq!(v.reference, "https://nvd.nist.gov/x");
        assert_eq!(v.provider, "vulners");
        // CPEs stashed on extra_data.
        let cpes = v.extra_data.get("cpes").and_then(|x| x.as_array()).unwrap();
        assert_eq!(cpes.len(), 1);
    }

    #[tokio::test]
    async fn missing_document_yields_empty() {
        use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/search/id"))
            // 200 OK but no `data.documents.<id>` entry — Vulners returns this
            // shape for unknown CVE ids.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"documents": {}}
            })))
            .mount(&server)
            .await;
        let p = VulnersProvider::with_base(server.uri()).with_key("test-key");
        assert!(matches!(p.lookup_cve("CVE-9999-0").await, Err(LookupError::Empty)));
    }

    #[tokio::test]
    async fn http_error_propagates() {
        use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let p = VulnersProvider::with_base(server.uri()).with_key("test-key");
        assert!(matches!(p.lookup_cve("CVE-2024-1").await, Err(LookupError::Http(403))));
    }
}
