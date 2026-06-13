//! The `OutputType` trait — behavior shared by every output record.
//!
//! Maps to Python `OutputType` (`output_types/_base.py`). Default `to_map`/`load` are
//! provided via serde so each concrete type only implements `type_name`, `data_fields`,
//! `compare_key`, the meta accessors, and (optionally) `post_init`.

use serde::Serialize;
use serde_json::Value;

use crate::key::{CompareKey, Map, OutputMap};
use crate::meta::Meta;

/// Meta field keys passed through verbatim during `load` so round-trips preserve identity.
pub const META_KEYS: [&str; 7] = [
    "_uuid",
    "_source",
    "_timestamp",
    "_context",
    "_duplicate",
    "_related",
    "_tagged",
];

pub trait OutputType: Serialize + serde::de::DeserializeOwned + Sized {
    /// snake_case discriminator, e.g. `"url"` (Python `get_name()`).
    fn type_name() -> &'static str;

    /// The non-meta (data) field names, used by `load` to decide a match.
    fn data_fields() -> &'static [&'static str];

    /// The dedup identity. Must match the Python `compare=True` field set EXACTLY.
    /// Implementations should prepend the type name (see `keyed`).
    fn compare_key(&self) -> CompareKey;

    fn meta(&self) -> &Meta;
    fn meta_mut(&mut self) -> &mut Meta;

    /// Normalization after construction/deserialization (Python `__post_init__`).
    fn post_init(&mut self) {}

    /// Serialize to a loose map with the `_type` discriminator injected (Python `toDict`).
    fn to_map(&self) -> Map {
        let mut value = serde_json::to_value(self).expect("OutputType serialize");
        let obj = value.as_object_mut().expect("OutputType serializes to object");
        obj.insert("_type".to_string(), Value::String(Self::type_name().to_string()));
        obj.clone()
    }

    /// Enrich `self` in place by copying non-empty fields from `other`. Mirrors
    /// Python `_base.OutputType.merge_with(other, exclude_fields=[])`:
    ///   * scalars: overwrite when the source value is non-empty,
    ///   * arrays: union (preserve order; append items not already present),
    ///   * objects: shallow merge (source keys override matching destination keys).
    ///
    /// Meta fields (`_uuid`, `_timestamp`, …) are never touched; the type
    /// discriminator is dropped. `exclude_fields` skips named fields by source
    /// key, useful when a caller wants to preserve a higher-confidence value
    /// (e.g. nuclei keeps its `description` even when CVE enrichment has one).
    fn merge_with(&mut self, other: &Self, exclude_fields: &[&str]) {
        let mut target = self.to_map();
        let source = other.to_map();
        for (k, v) in source.iter() {
            if k.starts_with('_') || exclude_fields.contains(&k.as_str()) {
                continue;
            }
            if value_is_empty(v) {
                continue;
            }
            match (target.get_mut(k), v) {
                // Array union: keep existing order, append new entries.
                (Some(Value::Array(dst)), Value::Array(src)) => {
                    for entry in src {
                        if !dst.contains(entry) {
                            dst.push(entry.clone());
                        }
                    }
                }
                // Object shallow merge: source keys overwrite matching destination keys.
                (Some(Value::Object(dst)), Value::Object(src)) => {
                    for (sk, sv) in src {
                        dst.insert(sk.clone(), sv.clone());
                    }
                }
                // Scalar (or shape mismatch): overwrite.
                _ => {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
        // Round-trip through serde to apply any post-init normalization.
        if let Ok(refreshed) = serde_json::from_value::<Self>(Value::Object(target)) {
            let meta = self.meta().clone();
            *self = refreshed;
            *self.meta_mut() = meta;
            self.post_init();
        }
    }

    /// Construct from a loose map applying `output_map` renames (Python `load`).
    /// Returns `None` when the `_type` mismatches or no data field is present
    /// (so a caller can try the next candidate type — the "all-None ⇒ reject" rule).
    fn load(item: &Map, output_map: &OutputMap) -> Option<Self> {
        if let Some(Value::String(t)) = item.get("_type") {
            if t != Self::type_name() {
                return None;
            }
        }
        let mut built = Map::new();
        let mut any = false;
        for &field in Self::data_fields() {
            let src = output_map.get(field).map(|s| s.as_str()).unwrap_or(field);
            if let Some(val) = item.get(src) {
                if !val.is_null() {
                    any = true;
                }
                built.insert(field.to_string(), val.clone());
            }
        }
        if !any {
            return None;
        }
        for k in META_KEYS {
            if let Some(val) = item.get(k) {
                built.insert(k.to_string(), val.clone());
            }
        }
        let mut obj: Self = serde_json::from_value(Value::Object(built)).ok()?;
        obj.post_init();
        Some(obj)
    }
}

/// "Empty" by Python `_base.OutputType.merge_with` rules: None / "" / [] / {}.
/// Numbers and booleans always count as set (even `0` / `false`) so a CVSS of
/// `0.0` from an unenriched feed can't silently overwrite a real score later.
fn value_is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Build a `CompareKey` starting with the type name (so types never collide), then the
/// per-type comparable fields. Used inside each `compare_key` impl via `keyed!`.
pub fn keyed(type_name: &str, parts: Vec<crate::key::KeyPart>) -> CompareKey {
    let mut key = Vec::with_capacity(parts.len() + 1);
    key.push(crate::key::KeyPart::Str(type_name.to_string()));
    key.extend(parts);
    key
}

#[cfg(test)]
mod merge_with_tests {
    use super::*;
    use crate::findings::{Url, Vulnerability};

    #[test]
    fn merge_overwrites_empty_scalars_only() {
        let mut target = Vulnerability {
            id: "CVE-2024-1".into(),
            severity: "unknown".into(),
            cvss_score: 0.0,
            description: String::new(),
            ..Default::default()
        };
        let src = Vulnerability {
            id: "OTHER".into(), // present in target → don't overwrite (target.id is non-empty)
            severity: "critical".into(),
            cvss_score: 9.8,
            description: "Stack buffer overflow".into(),
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        // Pre-existing non-empty `id` survives — Python `merge_with` only fills empty fields.
        // Wait — looking at Python: it OVERWRITES scalars when source is non-empty. So target.id becomes "OTHER".
        assert_eq!(target.id, "OTHER");
        assert_eq!(target.severity, "critical");
        assert_eq!(target.cvss_score, 9.8);
        assert_eq!(target.description, "Stack buffer overflow");
    }

    #[test]
    fn merge_skips_empty_source_values() {
        let mut target = Vulnerability {
            id: "CVE-2024-2".into(),
            description: "Original".into(),
            ..Default::default()
        };
        let src = Vulnerability {
            description: String::new(),    // empty — skip
            reference: String::new(),      // empty — skip
            severity: "high".into(),       // non-empty — overwrite
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        assert_eq!(target.description, "Original");
        assert_eq!(target.severity, "high");
    }

    #[test]
    fn merge_unions_arrays_preserving_order() {
        let mut target = Vulnerability {
            references: vec!["https://a".into(), "https://b".into()],
            tags: vec!["cve".into()],
            ..Default::default()
        };
        let src = Vulnerability {
            references: vec!["https://b".into(), "https://c".into()],
            tags: vec!["cve".into(), "rce".into()],
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        assert_eq!(
            target.references,
            vec!["https://a".to_string(), "https://b".into(), "https://c".into()]
        );
        assert_eq!(target.tags, vec!["cve".to_string(), "rce".into()]);
    }

    #[test]
    fn merge_shallow_merges_extra_data() {
        let mut target = Url {
            url: "https://x".into(),
            ..Default::default()
        };
        target.extra_data.insert("seen".into(), Value::Bool(true));
        let mut src = Url {
            url: "https://x".into(),
            ..Default::default()
        };
        src.extra_data.insert("score".into(), serde_json::json!(0.5));
        src.extra_data.insert("seen".into(), Value::Bool(false)); // overwrites
        target.merge_with(&src, &[]);
        assert_eq!(target.extra_data.get("seen"), Some(&Value::Bool(false)));
        assert_eq!(
            target.extra_data.get("score"),
            Some(&serde_json::json!(0.5))
        );
    }

    #[test]
    fn merge_excludes_specified_fields() {
        let mut target = Vulnerability {
            description: "Original".into(),
            severity: "low".into(),
            ..Default::default()
        };
        let src = Vulnerability {
            description: "Overwritten".into(),
            severity: "critical".into(),
            ..Default::default()
        };
        target.merge_with(&src, &["description"]);
        assert_eq!(target.description, "Original");
        assert_eq!(target.severity, "critical");
    }

    #[test]
    fn merge_preserves_meta() {
        let mut target = Url {
            url: "https://x".into(),
            ..Default::default()
        };
        target.meta.uuid = "u-1".into();
        target.meta.source = "httpx".into();
        target.meta.timestamp = 42.0;
        let src = Url {
            url: "https://x".into(),
            title: "Title".into(),
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        assert_eq!(target.title, "Title");
        // Meta MUST survive — meta is its own identity, not an enrichment field.
        assert_eq!(target.meta.uuid, "u-1");
        assert_eq!(target.meta.source, "httpx");
        assert_eq!(target.meta.timestamp, 42.0);
    }

    #[test]
    fn merge_fires_post_init() {
        // Vulnerability::post_init derives severity_nb from severity.
        let mut target = Vulnerability {
            severity: "low".into(),
            ..Default::default()
        };
        let src = Vulnerability {
            severity: "critical".into(),
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        assert_eq!(target.severity, "critical");
        assert_eq!(target.severity_nb, 0, "post_init should re-derive severity_nb");
    }

    #[test]
    fn merge_does_not_overwrite_with_empty_string() {
        let mut target = Vulnerability {
            description: "Set".into(),
            ..Default::default()
        };
        let src = Vulnerability {
            description: String::new(),
            ..Default::default()
        };
        target.merge_with(&src, &[]);
        assert_eq!(target.description, "Set");
    }
}
