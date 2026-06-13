//! Finding output types (the security-relevant results).
//!
//! Maps to the finding dataclasses in Python `secator/output_types/`. Each `compare_key`
//! reproduces that type's `compare=True` field set EXACTLY (see
//! `../docs/rewrite/03-data-model.md` §3). `match`/`type` are Rust keywords, so the Rust
//! fields are `match_`/`type_` with `#[serde(rename)]`.

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::key::{CompareKey, KeyPart};
use crate::meta::Meta;
use crate::output_type::{keyed, OutputType};

type Obj = JsonMap<String, Value>;

// --------------------------------------------------------------------------- Subdomain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Subdomain {
    pub host: String,
    pub domain: String,
    pub verified: bool,
    pub sources: Vec<String>,
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Subdomain {
    fn type_name() -> &'static str { "subdomain" }
    fn data_fields() -> &'static [&'static str] {
        &["host", "domain", "verified", "sources", "extra_data", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("subdomain", vec![KeyPart::str(&self.host), KeyPart::str(&self.domain)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ---------------------------------------------------------------------------------- Ip
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Ip {
    pub ip: String,
    pub host: String,
    pub alive: bool,
    pub protocol: String, // IPv4 | IPv6
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Ip {
    fn default() -> Self {
        Ip {
            ip: String::new(), host: String::new(), alive: false, protocol: "IPv4".into(),
            extra_data: Obj::new(), is_false_positive: false, is_acknowledged: false,
            tags: Vec::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Ip {
    fn type_name() -> &'static str { "ip" }
    fn data_fields() -> &'static [&'static str] {
        &["ip", "host", "alive", "protocol", "extra_data", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("ip", vec![KeyPart::str(&self.ip), KeyPart::Bool(self.alive), KeyPart::str(&self.protocol)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// -------------------------------------------------------------------------------- Port
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Port {
    pub port: i64,
    pub ip: String,
    pub state: String,
    pub service_name: String,
    pub cpes: Vec<String>,
    pub host: String,
    pub protocol: String,
    pub extra_data: Obj,
    pub confidence: String,
    pub service_confidence: String,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Port {
    fn default() -> Self {
        Port {
            port: 0, ip: String::new(), state: "UNKNOWN".into(), service_name: String::new(),
            cpes: Vec::new(), host: String::new(), protocol: "tcp".into(), extra_data: Obj::new(),
            confidence: "low".into(), service_confidence: "low".into(), is_false_positive: false,
            is_acknowledged: false, tags: Vec::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Port {
    fn type_name() -> &'static str { "port" }
    fn data_fields() -> &'static [&'static str] {
        &["port", "ip", "state", "service_name", "cpes", "host", "protocol", "extra_data",
          "confidence", "service_confidence", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("port", vec![KeyPart::Int(self.port), KeyPart::str(&self.ip), KeyPart::str(&self.state)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// --------------------------------------------------------------------------------- Url
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Url {
    pub url: String,
    pub host: String,
    pub verified: bool,
    pub status_code: i64,
    pub title: String,
    pub protocol: String,
    pub webserver: String,
    pub tech: Vec<String>,
    pub content_type: String,
    pub content_length: i64,
    pub time: String,
    pub method: String,
    pub words: i64,
    pub lines: i64,
    pub screenshot_path: String,
    pub stored_response_path: String,
    pub confidence: String,
    pub response_headers: Obj,
    pub request_headers: Obj,
    pub extra_data: Obj,
    pub is_directory: bool,
    pub is_root: bool,
    pub is_redirect: bool,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Url {
    fn default() -> Self {
        Url {
            url: String::new(), host: String::new(), verified: false, status_code: 0,
            title: String::new(), protocol: String::new(), webserver: String::new(), tech: Vec::new(),
            content_type: String::new(), content_length: 0, time: String::new(), method: String::new(),
            words: 0, lines: 0, screenshot_path: String::new(), stored_response_path: String::new(),
            confidence: "high".into(), response_headers: Obj::new(), request_headers: Obj::new(),
            extra_data: Obj::new(), is_directory: false, is_root: false, is_redirect: false,
            is_false_positive: false, is_acknowledged: false, tags: Vec::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Url {
    fn type_name() -> &'static str { "url" }
    fn data_fields() -> &'static [&'static str] {
        &["url", "host", "verified", "status_code", "title", "protocol", "webserver", "tech",
          "content_type", "content_length", "time", "method", "words", "lines", "screenshot_path",
          "stored_response_path", "confidence", "response_headers", "request_headers", "extra_data",
          "is_directory", "is_root", "is_redirect", "is_false_positive", "is_acknowledged", "tags"]
    }
    /// Dedup key is the URL only (everything else is `compare=False`).
    fn compare_key(&self) -> CompareKey {
        keyed("url", vec![KeyPart::str(&self.url)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        if self.host.is_empty() {
            self.host = url_host(&self.url);
        }
        self.protocol = if self.url.starts_with("https://") { "https".into() } else { "http".into() };
        if self.confidence == "high" && self.status_code != 0 {
            self.verified = true;
        }
        if self.title.contains("Index of") {
            self.is_directory = true;
        }
        let root = if self.url.starts_with("https://") {
            format!("https://{}", self.host)
        } else {
            format!("http://{}", self.host)
        };
        if !self.is_root && self.url.trim_end_matches('/') == root {
            self.is_root = true;
        }
        // Extract webserver/content_type/content_length from response headers (case-insensitive).
        for (k, v) in self.response_headers.clone() {
            let nk = k.to_lowercase().replace('-', "_");
            let vs = v.as_str().unwrap_or("");
            match nk.as_str() {
                "server" => self.webserver = vs.to_string(),
                "content_type" => self.content_type = vs.split(';').next().unwrap_or("").to_string(),
                "content_length" => self.content_length = vs.parse().unwrap_or(self.content_length),
                _ => {}
            }
        }
        if !self.webserver.is_empty() && self.tech.is_empty() {
            self.tech.push(self.webserver.clone());
        }
    }
}

/// Minimal host extraction (real impl uses a URL parser). `https://h:443/p?q` -> `h:443`.
fn url_host(url: &str) -> String {
    let after_scheme = url.splitn(2, "://").nth(1).unwrap_or(url);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}

// --------------------------------------------------------------------------------- Tag
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Tag {
    pub name: String,
    pub value: String,
    #[serde(rename = "match")]
    pub match_: String,
    pub category: String,
    pub extra_data: Obj,
    pub stored_response_path: String,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Tag {
    fn default() -> Self {
        Tag {
            name: String::new(), value: String::new(), match_: String::new(), category: "general".into(),
            extra_data: Obj::new(), stored_response_path: String::new(), is_false_positive: false,
            is_acknowledged: false, tags: Vec::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Tag {
    fn type_name() -> &'static str { "tag" }
    fn data_fields() -> &'static [&'static str] {
        &["name", "value", "match", "category", "extra_data", "stored_response_path",
          "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("tag", vec![KeyPart::str(&self.name), KeyPart::str(&self.value),
                          KeyPart::str(&self.match_), KeyPart::str(&self.category)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ----------------------------------------------------------------------------- Exploit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Exploit {
    pub name: String,
    pub provider: String,
    pub id: String,
    pub matched_at: String,
    pub ip: String,
    pub confidence: String,
    pub reference: String,
    pub cves: Vec<String>,
    pub tags: Vec<String>,
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Exploit {
    fn default() -> Self {
        Exploit {
            name: String::new(), provider: String::new(), id: String::new(), matched_at: String::new(),
            ip: String::new(), confidence: "low".into(), reference: String::new(), cves: Vec::new(),
            tags: Vec::new(), extra_data: Obj::new(), is_false_positive: false, is_acknowledged: false,
            meta: Meta::default(),
        }
    }
}
impl OutputType for Exploit {
    fn type_name() -> &'static str { "exploit" }
    fn data_fields() -> &'static [&'static str] {
        &["name", "provider", "id", "matched_at", "ip", "confidence", "reference", "cves",
          "tags", "extra_data", "is_false_positive", "is_acknowledged"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("exploit", vec![KeyPart::str(&self.name), KeyPart::str(&self.provider),
                              KeyPart::str(&self.id), KeyPart::str(&self.matched_at),
                              KeyPart::str(&self.ip), KeyPart::str(&self.confidence)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ------------------------------------------------------------------------- UserAccount
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct UserAccount {
    pub username: String,
    pub url: String,
    pub email: String,
    pub site_name: String,
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for UserAccount {
    fn type_name() -> &'static str { "user_account" }
    fn data_fields() -> &'static [&'static str] {
        &["username", "url", "email", "site_name", "extra_data", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("user_account", vec![KeyPart::str(&self.username), KeyPart::str(&self.url),
                                   KeyPart::str(&self.email), KeyPart::str(&self.site_name)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ----------------------------------------------------------------------- Vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Vulnerability {
    pub name: String,
    pub provider: String,
    pub id: String,
    pub matched_at: String,
    pub ip: String,
    pub confidence: String,
    pub severity: String,
    pub cvss_score: f64,
    pub cvss_vec: String,
    pub epss_score: f64,
    pub extra_data: Obj,
    pub description: String,
    pub references: Vec<String>,
    pub reference: String,
    pub confidence_nb: i64,
    pub severity_nb: i64,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Vulnerability {
    fn default() -> Self {
        Vulnerability {
            name: String::new(), provider: String::new(), id: String::new(), matched_at: String::new(),
            ip: String::new(), confidence: "low".into(), severity: "unknown".into(), cvss_score: 0.0,
            cvss_vec: String::new(), epss_score: 0.0, extra_data: Obj::new(), description: String::new(),
            references: Vec::new(), reference: String::new(), confidence_nb: 0, severity_nb: 0,
            is_false_positive: false, is_acknowledged: false, tags: Vec::new(), meta: Meta::default(),
        }
    }
}
/// Ordinal scale shared by severity and confidence (Python `severity_map`).
fn severity_ordinal(s: &str) -> i64 {
    match s {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "info" => 4, "unknown" => 5,
        _ => 6,
    }
}
fn cvss_to_severity(cvss: f64) -> &'static str {
    if cvss < 4.0 { "low" } else if cvss < 7.0 { "medium" } else if cvss < 9.0 { "high" } else { "critical" }
}
impl OutputType for Vulnerability {
    fn type_name() -> &'static str { "vulnerability" }
    fn data_fields() -> &'static [&'static str] {
        &["name", "provider", "id", "matched_at", "ip", "confidence", "severity", "cvss_score",
          "cvss_vec", "epss_score", "extra_data", "description", "references", "reference",
          "confidence_nb", "severity_nb", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("vulnerability", vec![
            KeyPart::str(&self.name), KeyPart::str(&self.provider), KeyPart::str(&self.id),
            KeyPart::str(&self.matched_at), KeyPart::str(&self.confidence), KeyPart::str(&self.severity),
            KeyPart::float(self.cvss_score), KeyPart::str(&self.cvss_vec), KeyPart::float(self.epss_score),
            KeyPart::Int(self.confidence_nb), KeyPart::Int(self.severity_nb),
        ])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        if !self.references.is_empty() {
            self.reference = self.references[0].clone();
        }
        if self.cvss_score > 0.0 && self.severity == "unknown" {
            self.severity = cvss_to_severity(self.cvss_score).to_string();
        }
        self.severity = self.severity.to_lowercase();
        self.severity_nb = severity_ordinal(&self.severity);
        self.confidence_nb = severity_ordinal(&self.confidence);
    }
}

// ------------------------------------------------------------------------- Certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Certificate {
    pub host: String,
    pub fingerprint_sha256: String,
    pub ip: String,
    pub raw_value: String,
    pub subject_cn: String,
    pub subject_an: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub issuer_dn: String,
    pub issuer_cn: String,
    pub issuer: String,
    pub self_signed: bool,
    pub trusted: bool,
    pub status: String,
    pub keysize: Option<i64>,
    pub serial_number: String,
    pub ciphers: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            host: String::new(), fingerprint_sha256: String::new(), ip: String::new(),
            raw_value: String::new(), subject_cn: String::new(), subject_an: Vec::new(),
            not_before: None, not_after: None, issuer_dn: String::new(), issuer_cn: String::new(),
            issuer: String::new(), self_signed: true, trusted: false, status: "Unknown".into(),
            keysize: None, serial_number: String::new(), ciphers: Vec::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Certificate {
    fn type_name() -> &'static str { "certificate" }
    fn data_fields() -> &'static [&'static str] {
        &["host", "fingerprint_sha256", "ip", "raw_value", "subject_cn", "subject_an", "not_before",
          "not_after", "issuer_dn", "issuer_cn", "issuer", "self_signed", "trusted", "status",
          "keysize", "serial_number", "ciphers"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("certificate", vec![KeyPart::str(&self.host), KeyPart::str(&self.fingerprint_sha256)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ------------------------------------------------------------------------------ Record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Record {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub host: String,
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Record {
    fn type_name() -> &'static str { "record" }
    fn data_fields() -> &'static [&'static str] {
        &["name", "type", "host", "extra_data", "is_false_positive", "is_acknowledged", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("record", vec![KeyPart::str(&self.name), KeyPart::str(&self.type_), KeyPart::str(&self.host)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ------------------------------------------------------------------------------ Domain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Domain {
    pub domain: String,
    pub alive: bool,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub status: Vec<String>,
    pub registrar: String,
    pub registrar_info: Obj,
    pub registrant: String,
    pub registrant_info: Obj,
    pub administrative_info: Obj,
    pub technical_info: Obj,
    pub extra_data: Obj,
    pub is_false_positive: bool,
    pub is_acknowledged: bool,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Domain {
    fn type_name() -> &'static str { "domain" }
    fn data_fields() -> &'static [&'static str] {
        &["domain", "alive", "creation_date", "expiration_date", "updated_date", "status",
          "registrar", "registrar_info", "registrant", "registrant_info", "administrative_info",
          "technical_info", "extra_data", "is_false_positive", "is_acknowledged", "tags"]
    }
    /// NOTE: `_source` is part of Domain's dedup key in Python (unusual — see 03 §3.11).
    fn compare_key(&self) -> CompareKey {
        keyed("domain", vec![KeyPart::str(&self.domain), KeyPart::Bool(self.alive),
                             KeyPart::str(&self.meta.source)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        if !self.alive && !self.status.is_empty() {
            self.alive = self.status.iter().any(|s| s.to_lowercase().contains("active"));
        }
    }
}

// -------------------------------------------------------------------------- Technology
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Technology {
    pub product: String,
    #[serde(rename = "match")]
    pub match_: String,
    pub version: Option<String>,
    pub extra_data: Obj,
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Technology {
    fn type_name() -> &'static str { "technology" }
    fn data_fields() -> &'static [&'static str] {
        &["product", "match", "version", "extra_data", "tags"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("technology", vec![KeyPart::str(&self.product), KeyPart::str(&self.match_),
                                 KeyPart::str(self.version.as_deref().unwrap_or(""))])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ---------------------------------------------------------------------------------- Ai
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Ai {
    pub content: String,
    pub ai_type: String,
    pub mode: String,
    pub model: String,
    pub extra_data: Obj,
    pub summary: bool,
    pub status: String,
    pub answer: String,
    pub choices: Vec<Value>,
    pub session_id: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl Default for Ai {
    fn default() -> Self {
        Ai {
            content: String::new(), ai_type: "response".into(), mode: String::new(), model: String::new(),
            extra_data: Obj::new(), summary: false, status: String::new(), answer: String::new(),
            choices: Vec::new(), session_id: String::new(), meta: Meta::default(),
        }
    }
}
impl OutputType for Ai {
    fn type_name() -> &'static str { "ai" }
    fn data_fields() -> &'static [&'static str] {
        &["content", "ai_type", "mode", "model", "extra_data", "summary", "status", "answer", "choices", "session_id"]
    }
    fn compare_key(&self) -> CompareKey {
        keyed("ai", vec![KeyPart::str(&self.content), KeyPart::str(&self.ai_type)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}
