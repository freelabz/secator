//! Sensitive-data masking — Python parity with `secator.ai.encryption`.
//!
//! Despite the name "encryption" this is a **deterministic placeholder swap**:
//! patterns matching PII (emails, IPv4, hostnames) get replaced with stable
//! `[TYPE:<12-char-sha256>]` tokens before going to the LLM, and the same
//! mapping is used to restore the originals in the LLM's reply before the
//! operator sees it. The mapping lives in memory only — secrets are never
//! persisted alongside the session.

use std::collections::BTreeMap;

use regex::Regex;
use sha2::{Digest, Sha256};

/// Encryptor state — owns the placeholder ↔ original mapping built up as
/// `encrypt` runs. Threading-wise the type is single-owner: the agent loop
/// holds one instance for the run.
#[derive(Debug, Clone)]
pub struct SensitiveDataEncryptor {
    salt: String,
    /// `[TYPE:hash]` → original.
    pii_map: BTreeMap<String, String>,
    /// Bare `hash` → original. Lets us decrypt placeholders the LLM might emit
    /// without the brackets (Python parity).
    hash_map: BTreeMap<String, String>,
    custom_patterns: Vec<Regex>,
}

impl Default for SensitiveDataEncryptor {
    fn default() -> Self {
        Self::new("secator_pii_salt", &[])
    }
}

impl SensitiveDataEncryptor {
    pub fn new(salt: impl Into<String>, custom_patterns: &[&str]) -> Self {
        let mut compiled = Vec::with_capacity(custom_patterns.len());
        for raw in custom_patterns {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Try as regex first; if it doesn't parse, treat as a literal.
            let re = Regex::new(trimmed).unwrap_or_else(|_| {
                Regex::new(&regex::escape(trimmed)).expect("escaped literal compiles")
            });
            compiled.push(re);
        }
        Self {
            salt: salt.into(),
            pii_map: BTreeMap::new(),
            hash_map: BTreeMap::new(),
            custom_patterns: compiled,
        }
    }

    /// Replace every PII match in `text` with a stable placeholder; record the
    /// reverse mapping. Calling `encrypt` repeatedly is idempotent for the same
    /// inputs (same hash → same placeholder).
    pub fn encrypt(&mut self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        let mut out = text.to_string();
        // Custom patterns first (Python parity: custom_0, custom_1, ...).
        let custom_count = self.custom_patterns.len();
        for i in 0..custom_count {
            let pat = self.custom_patterns[i].clone();
            out = self.replace_matches(out, &pat, &format!("custom_{i}"));
        }
        // Built-in patterns: email → ipv4 → host (specific before general).
        let pats = builtin_patterns();
        for (kind, pat) in pats {
            if kind == "host" {
                out = self.replace_host_matches(out, &pat);
            } else {
                out = self.replace_matches(out, &pat, kind);
            }
        }
        out
    }

    /// Restore originals from placeholders. Handles three shapes (Python parity):
    /// 1. `[TYPE:hash]` — full placeholder,
    /// 2. `TYPE:hash` — placeholder without brackets,
    /// 3. bare `hash` — the LLM dropped the prefix entirely.
    pub fn decrypt(&self, text: &str) -> String {
        let mut out = text.to_string();
        // Full placeholders.
        for (placeholder, original) in &self.pii_map {
            out = out.replace(placeholder, original);
        }
        // Without brackets.
        for (placeholder, original) in &self.pii_map {
            let no_brackets = &placeholder[1..placeholder.len() - 1];
            out = out.replace(no_brackets, original);
        }
        // Bare hashes.
        for (hash, original) in &self.hash_map {
            out = out.replace(hash, original);
        }
        out
    }

    /// Total mappings recorded so far — useful for telemetry / tests.
    #[allow(dead_code)]
    pub fn mapping_count(&self) -> usize {
        self.pii_map.len()
    }

    fn replace_matches(&mut self, text: String, pat: &Regex, kind: &str) -> String {
        let mut result = text;
        loop {
            let m = match pat.find(&result) {
                Some(m) => (m.start(), m.end(), m.as_str().to_string()),
                None => break,
            };
            let placeholder = self.hash_value(&m.2, kind);
            // Replace just this one match, then loop to catch overlapping / cascaded matches.
            result.replace_range(m.0..m.1, &placeholder);
        }
        result
    }

    /// Same as `replace_matches` but skips matches that look like hash-named
    /// files (Python `_is_hash_filename`) so paths like `abc...123.txt` don't
    /// get masked as hostnames.
    fn replace_host_matches(&mut self, text: String, pat: &Regex) -> String {
        let mut result = text;
        let mut search_from = 0usize;
        loop {
            let Some(m) = pat.find_at(&result, search_from) else { break };
            let span = (m.start(), m.end());
            let matched = m.as_str().to_string();
            if is_hash_filename(&matched) {
                search_from = span.1;
                continue;
            }
            let placeholder = self.hash_value(&matched, "host");
            result.replace_range(span.0..span.1, &placeholder);
            // Resume scanning after the inserted placeholder so we don't re-match
            // it (the `[HOST:...]` shape can't itself satisfy the host regex, but
            // skipping past keeps us linear regardless).
            search_from = span.0 + placeholder.len();
        }
        result
    }

    fn hash_value(&mut self, value: &str, kind: &str) -> String {
        // If we've already seen this exact value+kind, reuse the placeholder
        // so the mapping stays stable.
        let placeholder = self.compute_placeholder(value, kind);
        if !self.pii_map.contains_key(&placeholder) {
            self.pii_map.insert(placeholder.clone(), value.to_string());
            let bare = placeholder.trim_start_matches('[').trim_end_matches(']');
            let hash = bare.rsplit(':').next().unwrap_or("").to_string();
            if !hash.is_empty() {
                self.hash_map.insert(hash, value.to_string());
            }
        }
        placeholder
    }

    fn compute_placeholder(&self, value: &str, kind: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.salt.as_bytes());
        h.update(b":");
        h.update(kind.as_bytes());
        h.update(b":");
        h.update(value.as_bytes());
        let digest = h.finalize();
        let mut hex = String::with_capacity(12);
        for b in &digest[..6] {
            // first 6 bytes → 12 hex chars (matches Python `[:12]`).
            hex.push_str(&format!("{b:02x}"));
        }
        format!("[{}:{}]", kind.to_uppercase(), hex)
    }
}

/// Built-in pattern set, ordered specific → general so longer matches win.
fn builtin_patterns() -> Vec<(&'static str, Regex)> {
    use std::sync::OnceLock;
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            (
                "email",
                Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            ),
            (
                "ipv4",
                Regex::new(
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                )
                .unwrap(),
            ),
            (
                "host",
                Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
                    .unwrap(),
            ),
        ]
    })
    .clone()
}

/// File extensions that should never be treated as TLDs (Python parity).
const FAKE_HOST_EXTENSIONS: &[&str] = &[
    "txt", "json", "xml", "html", "htm", "log", "csv", "md", "yaml", "yml", "toml", "ini", "cfg",
    "conf", "py", "js", "ts", "sh", "bash", "rb", "php", "go", "rs", "java", "c", "h", "cpp",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "pdf", "zip", "tar", "gz", "bz2", "xz", "mp3",
    "mp4",
];

fn is_hash_filename(s: &str) -> bool {
    let Some(dot_idx) = s.rfind('.') else { return false };
    let label = &s[..dot_idx].to_lowercase();
    let ext = &s[dot_idx + 1..].to_lowercase();
    if !FAKE_HOST_EXTENSIONS.contains(&ext.as_str()) {
        return false;
    }
    // Pure hex string of cryptographic length → looks like a hash filename.
    label.len() >= 8 && label.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_replaces_emails_with_placeholders() {
        let mut enc = SensitiveDataEncryptor::default();
        let out = enc.encrypt("Contact admin@example.com for help.");
        assert!(!out.contains("admin@example.com"));
        assert!(out.contains("[EMAIL:"));
    }

    #[test]
    fn encrypt_replaces_ipv4() {
        let mut enc = SensitiveDataEncryptor::default();
        let out = enc.encrypt("Server is at 192.168.1.42 and 10.0.0.1.");
        assert!(!out.contains("192.168.1.42"));
        assert!(!out.contains("10.0.0.1"));
        assert!(out.matches("[IPV4:").count() == 2);
    }

    #[test]
    fn encrypt_replaces_hostnames() {
        let mut enc = SensitiveDataEncryptor::default();
        let out = enc.encrypt("Probe customer.example.com please.");
        assert!(!out.contains("customer.example.com"));
        assert!(out.contains("[HOST:"));
    }

    #[test]
    fn encrypt_skips_hash_filenames() {
        let mut enc = SensitiveDataEncryptor::default();
        let out = enc
            .encrypt("Response stored at fefdc75b8092569ffdaaf5c91522f10d063a93d2.txt");
        // The hash filename must NOT become a [HOST:...] placeholder.
        assert!(out.contains("fefdc75b8092569ffdaaf5c91522f10d063a93d2.txt"));
        assert!(!out.contains("[HOST:"));
    }

    #[test]
    fn decrypt_restores_originals() {
        let mut enc = SensitiveDataEncryptor::default();
        let original = "Hit https://admin@example.com on 192.168.1.42 (customer.test.com).";
        let masked = enc.encrypt(original);
        let restored = enc.decrypt(&masked);
        assert_eq!(restored, original, "round trip should be exact");
    }

    #[test]
    fn decrypt_handles_bracketless_and_bare_hashes() {
        let mut enc = SensitiveDataEncryptor::default();
        let masked = enc.encrypt("Server at 192.168.1.42");
        let placeholder = masked.split_whitespace().last().unwrap().to_string(); // "[IPV4:...]"
        // Without brackets:
        let bare_p = &placeholder[1..placeholder.len() - 1]; // "IPV4:..."
        assert_eq!(enc.decrypt(&format!("see {bare_p} for details")), "see 192.168.1.42 for details");
        // Just the hash:
        let hash = bare_p.rsplit(':').next().unwrap();
        assert_eq!(enc.decrypt(&format!("hash={hash}")), "hash=192.168.1.42");
    }

    #[test]
    fn same_value_yields_same_placeholder() {
        let mut enc = SensitiveDataEncryptor::default();
        let out1 = enc.encrypt("admin@example.com");
        let out2 = enc.encrypt("admin@example.com");
        assert_eq!(out1, out2, "deterministic mapping");
        assert_eq!(enc.mapping_count(), 1);
    }

    #[test]
    fn empty_text_returns_unchanged() {
        let mut enc = SensitiveDataEncryptor::default();
        assert_eq!(enc.encrypt(""), "");
    }

    #[test]
    fn custom_pattern_redacts_secrets() {
        let mut enc = SensitiveDataEncryptor::new("salt", &["sk-[A-Za-z0-9]{10,}"]);
        let masked = enc.encrypt("API key: sk-abcdef1234567890");
        assert!(!masked.contains("sk-abcdef1234567890"));
        assert!(masked.contains("[CUSTOM_0:"));
        let restored = enc.decrypt(&masked);
        assert!(restored.contains("sk-abcdef1234567890"));
    }

    #[test]
    fn custom_pattern_literal_fallback_for_invalid_regex() {
        // `(unclosed` is not valid regex — must fall back to literal match.
        let mut enc = SensitiveDataEncryptor::new("salt", &["(unclosed"]);
        let masked = enc.encrypt("This (unclosed token should be masked");
        assert!(!masked.contains("(unclosed"));
        assert!(masked.contains("[CUSTOM_0:"));
    }

    #[test]
    fn is_hash_filename_detects_typical_hashes() {
        assert!(is_hash_filename("d41d8cd98f00b204e9800998ecf8427e.json"));
        assert!(is_hash_filename("fefdc75b8092569ffdaaf5c91522f10d063a93d2.txt"));
        assert!(!is_hash_filename("example.com"));
        assert!(!is_hash_filename("readme.md")); // .md is in the extension list, but "readme" isn't pure hex
        assert!(!is_hash_filename("abc.unknownext")); // ext not in list
    }
}
