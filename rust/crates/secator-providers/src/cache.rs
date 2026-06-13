//! On-disk cache for resolved CVE entries (Python `CONFIG.dirs.data/cves/<id>.json`).
//!
//! `LocalCache.get(id)` returns the cached Vulnerability if present;
//! `LocalCache.put(id, &vuln)` persists the JSON for the next run. Lookups in the
//! Rust port are short — round-tripping through `serde_json` ensures the cached
//! file is identical to what Python writes (Python uses the same JSON shape).

use std::path::PathBuf;

use secator_model::{OutputMap, OutputType, Vulnerability};

use crate::LookupError;

#[derive(Debug, Clone)]
pub struct LocalCache {
    pub dir: PathBuf,
}

impl LocalCache {
    /// Build a cache rooted at `<data_dir>/cves`. The directory is created lazily
    /// on first write so a read-only deployment can still call `get` safely.
    pub fn new(data_dir: PathBuf) -> Self {
        LocalCache { dir: data_dir.join("cves") }
    }

    fn path_for(&self, id: &str) -> PathBuf {
        // Sanitize: keep `[A-Za-z0-9_-]`, replace everything else with `_`.
        // `.` is excluded so a maliciously-crafted id can't include `..`.
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.json"))
    }

    pub fn get(&self, id: &str) -> Result<Option<Vulnerability>, LookupError> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        let body = std::fs::read_to_string(&path)
            .map_err(|e| LookupError::Cache(format!("read {}: {e}", path.display())))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| LookupError::Cache(format!("parse {}: {e}", path.display())))?;
        let map = match value {
            serde_json::Value::Object(m) => m,
            _ => return Ok(None),
        };
        Ok(Vulnerability::load(&map, &OutputMap::new()))
    }

    pub fn put(&self, id: &str, vuln: &Vulnerability) -> Result<(), LookupError> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| LookupError::Cache(format!("mkdir {}: {e}", self.dir.display())))?;
        let path = self.path_for(id);
        let map = vuln.to_map();
        let body = serde_json::to_string_pretty(&map)
            .map_err(|e| LookupError::Cache(format!("encode: {e}")))?;
        std::fs::write(&path, body)
            .map_err(|e| LookupError::Cache(format!("write {}: {e}", path.display())))?;
        Ok(())
    }
}

/// On-disk cache for exploit raw bytes (Python `CONFIG.dirs.data/exploits/<id>.html`).
/// The Python ExploitProvider stores raw upstream content; we mirror that shape
/// so the cache directory layout stays compatible between the two stacks.
#[derive(Debug, Clone)]
pub struct ExploitCache {
    pub dir: PathBuf,
}

impl ExploitCache {
    pub fn new(data_dir: PathBuf) -> Self {
        ExploitCache { dir: data_dir.join("exploits") }
    }

    fn path_for(&self, id: &str) -> PathBuf {
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // `.html` matches Python upstream-content semantics (raw page).
        self.dir.join(format!("{safe}.html"))
    }

    pub fn get(&self, id: &str) -> Result<Option<String>, LookupError> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        let body = std::fs::read_to_string(&path)
            .map_err(|e| LookupError::Cache(format!("read {}: {e}", path.display())))?;
        Ok(Some(body))
    }

    pub fn put(&self, id: &str, body: &str) -> Result<(), LookupError> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| LookupError::Cache(format!("mkdir {}: {e}", self.dir.display())))?;
        let path = self.path_for(id);
        std::fs::write(&path, body)
            .map_err(|e| LookupError::Cache(format!("write {}: {e}", path.display())))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = LocalCache::new(tmp.path().to_path_buf());
        let vuln = Vulnerability {
            id: "CVE-2024-1234".into(),
            severity: "high".into(),
            cvss_score: 7.5,
            description: "Demo".into(),
            ..Default::default()
        };
        cache.put("CVE-2024-1234", &vuln).unwrap();
        let back = cache.get("CVE-2024-1234").unwrap().expect("should exist");
        assert_eq!(back.severity, "high");
        assert_eq!(back.cvss_score, 7.5);
    }

    #[test]
    fn get_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = LocalCache::new(tmp.path().to_path_buf());
        assert!(cache.get("CVE-9999-0000").unwrap().is_none());
    }

    #[test]
    fn path_sanitizes_unsafe_characters() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = LocalCache::new(tmp.path().to_path_buf());
        let p = cache.path_for("../../etc/passwd");
        assert!(p.starts_with(tmp.path()), "should stay under cache dir");
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        // No path-traversal characters survive in the final name.
        assert!(!name.contains('/'));
        assert!(!name.contains(".."));
        assert!(name.ends_with(".json"));
    }
}
