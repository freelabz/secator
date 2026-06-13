//! Circl CVE provider (Python `secator/providers/circl.py`).
//!
//! Endpoint: `https://vulnerability.circl.lu/api/cve/<cve_id>`. Returns the
//! CVE record v5.1 shape with `cveMetadata`/`containers.cna`/`containers.adp`.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

use secator_model::{Map, Vulnerability};

use crate::{CveProvider, LookupError};

pub struct CirclProvider {
    client: Client,
    base_url: String,
    offline: bool,
}

impl CirclProvider {
    pub fn new() -> Self {
        Self::with_base("https://vulnerability.circl.lu")
    }

    pub fn with_base(base: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("secator-rs/0.1")
            .build()
            .unwrap_or_else(|_| Client::new());
        CirclProvider { client, base_url: base.into(), offline: false }
    }

    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }
}

impl Default for CirclProvider {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl CveProvider for CirclProvider {
    fn name(&self) -> &'static str { "circl" }

    async fn lookup_cve(&self, id: &str) -> Result<Vulnerability, LookupError> {
        if self.offline {
            return Err(LookupError::Offline);
        }
        let url = format!("{}/api/cve/{id}", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
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
        if !json.is_object() || json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            return Err(LookupError::Empty);
        }
        Ok(parse_circl(&json, id))
    }
}

/// Map a CVE 5.1 record into a Secator `Vulnerability`. Pure / no I/O so it's
/// easy to test against captured JSON fixtures.
pub fn parse_circl(value: &Value, cve_id: &str) -> Vulnerability {
    let cve_meta = value.get("cveMetadata").and_then(|v| v.as_object());
    let resolved_id = cve_meta
        .and_then(|m| m.get("cveId"))
        .and_then(|v| v.as_str())
        .unwrap_or(cve_id)
        .to_string();
    let containers = value.get("containers").and_then(|v| v.as_object());
    let cna = containers.and_then(|m| m.get("cna")).and_then(|v| v.as_object());
    let adp = containers
        .and_then(|m| m.get("adp"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let cna_v: Value = match cna {
        Some(o) => Value::Object(o.clone()),
        None => Value::Null,
    };

    // Title → name; "other" treated as missing (Python parity).
    let title = cna_v.get("title").and_then(|v| v.as_str()).unwrap_or("");
    let name = if title.is_empty() || title.eq_ignore_ascii_case("other") {
        resolved_id.clone()
    } else {
        title.to_string()
    };

    // First description; strip the CVE id prefix if present.
    let raw_desc = cna_v
        .get("descriptions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let description = raw_desc.replace(&resolved_id, "").trim().to_string();

    // CWE id from the first problem-type → first descriptor.
    let cwe = cna_v
        .get("problemTypes")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.get("descriptions"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|d| d.get("cweId"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let mut tags: Vec<String> = Vec::new();
    if let Some(c) = cwe {
        tags.push(c);
    }

    // CVSS pick: walk cna.metrics first, then adp[*].metrics (Python parity —
    // last one wins).
    let mut cvss_score: f64 = 0.0;
    let mut cvss_vec: String = String::new();
    let mut severity: String = String::new();
    if let Some(m) = cna_v.get("metrics").and_then(|v| v.as_array()) {
        scan_metrics(m, &mut cvss_score, &mut cvss_vec, &mut severity);
    }
    for adp_n in &adp {
        if let Some(m) = adp_n.get("metrics").and_then(|v| v.as_array()) {
            scan_metrics(m, &mut cvss_score, &mut cvss_vec, &mut severity);
        }
    }

    // Affected CPEs from cna.affected[*].cpes + adp[*].affected[*].cpes.
    let mut cpes: Vec<Value> = Vec::new();
    if let Some(affected) = cna_v.get("affected").and_then(|v| v.as_array()) {
        for product in affected {
            if let Some(arr) = product.get("cpes").and_then(|v| v.as_array()) {
                cpes.extend(arr.iter().cloned());
            }
        }
    }
    for adp_n in &adp {
        if let Some(affected) = adp_n.get("affected").and_then(|v| v.as_array()) {
            for product in affected {
                if let Some(arr) = product.get("cpes").and_then(|v| v.as_array()) {
                    cpes.extend(arr.iter().cloned());
                }
            }
        }
    }

    // References — keep urls only.
    let mut references: Vec<String> = vec![format!("https://vulnerability.circl.lu/cve/{resolved_id}")];
    if let Some(arr) = cna_v.get("references").and_then(|v| v.as_array()) {
        for r in arr {
            if let Some(u) = r.get("url").and_then(|v| v.as_str()) {
                if !u.is_empty() && !references.contains(&u.to_string()) {
                    references.push(u.to_string());
                }
            }
        }
    }

    let mut extra: Map = Map::new();
    extra.insert("cpes".into(), Value::Array(cpes));
    let reference = references.first().cloned().unwrap_or_default();
    Vulnerability {
        name,
        provider: "vulnerability.circl.lu".into(),
        id: resolved_id,
        severity: severity.trim().to_string(),
        cvss_score,
        cvss_vec,
        epss_score: 0.0,
        tags,
        extra_data: extra,
        description,
        references,
        reference,
        ..Default::default()
    }
}

fn scan_metrics(metrics: &[Value], score: &mut f64, vec_str: &mut String, sev: &mut String) {
    for metric in metrics {
        let obj = match metric.as_object() {
            Some(o) => o,
            None => continue,
        };
        for (mname, mvalue) in obj {
            if !mname.to_lowercase().contains("cvss") {
                continue;
            }
            let mo = match mvalue.as_object() {
                Some(o) => o,
                None => continue,
            };
            if let Some(s) = mo.get("baseScore").and_then(|v| v.as_f64()) {
                *score = s;
            }
            if let Some(s) = mo.get("baseSeverity").and_then(|v| v.as_str()) {
                *sev = s.to_lowercase();
            }
            if let Some(v) = mo.get("vectorString").and_then(|v| v.as_str()) {
                *vec_str = v.to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_cve_response() {
        let v = json!({
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {"cna": {
                "title": "Demo bug",
                "descriptions": [{"value": "CVE-2024-0001 - this is broken"}],
                "metrics": [{
                    "cvssV3_1": {
                        "baseScore": 8.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }],
                "affected": [{"cpes": ["cpe:/a:vendor:app:1.0"]}],
                "references": [{"url": "https://example.com/cve"}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}]
            }}
        });
        let vuln = parse_circl(&v, "CVE-2024-0001");
        assert_eq!(vuln.id, "CVE-2024-0001");
        assert_eq!(vuln.name, "Demo bug");
        assert_eq!(vuln.severity, "high");
        assert_eq!(vuln.cvss_score, 8.5);
        assert!(vuln.cvss_vec.starts_with("CVSS:3.1"));
        assert!(vuln.description.contains("this is broken"));
        assert!(!vuln.description.contains("CVE-2024-0001"));
        assert_eq!(vuln.tags, vec!["CWE-79".to_string()]);
        assert_eq!(vuln.references.len(), 2);
        // First ref is the Circl detail URL.
        assert!(vuln.references[0].contains("circl.lu"));
        let cpes = vuln.extra_data.get("cpes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(cpes.len(), 1);
    }

    #[test]
    fn name_other_falls_back_to_cve_id() {
        let v = json!({
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {"cna": {
                "title": "other",
                "descriptions": [{"value": "x"}]
            }}
        });
        let vuln = parse_circl(&v, "CVE-2024-0001");
        assert_eq!(vuln.name, "CVE-2024-0001");
    }

    #[test]
    fn adp_metrics_override_cna_metrics() {
        let v = json!({
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {
                "cna": {"metrics": [{"cvssV3_1": {
                    "baseScore": 5.0, "baseSeverity": "medium", "vectorString": "cna"}}]},
                "adp": [{"metrics": [{"cvssV3_1": {
                    "baseScore": 9.5, "baseSeverity": "critical", "vectorString": "adp"}}]}]
            }
        });
        let vuln = parse_circl(&v, "CVE-2024-0001");
        // ADP wins (last-write).
        assert_eq!(vuln.cvss_score, 9.5);
        assert_eq!(vuln.severity, "critical");
        assert_eq!(vuln.cvss_vec, "adp");
    }
}
