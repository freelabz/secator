//! Unified output data model.
//!
//! Maps to Python `secator/output_types/`. This crate is the spine: every tool's output
//! is normalized into one of these typed records, deduplicated by a per-type key, and
//! serialized consistently (serde JSON). See `../docs/rewrite/03-data-model.md` and
//! ADR-0004.

mod execution;
mod findings;
mod key;
mod meta;
mod output_type;

pub use execution::*;
pub use findings::*;
pub use key::{CompareKey, KeyPart, Map, OutputMap};
pub use meta::Meta;
pub use output_type::OutputType;

/// Generate the `OutputItem` enum + dispatch + reconstruction from the variant list.
macro_rules! output_item {
    ($($variant:ident => $ty:ty),+ $(,)?) => {
        /// The closed set of result kinds that flow through the system (Python `OUTPUT_TYPES`).
        #[derive(Debug, Clone, PartialEq)]
        pub enum OutputItem { $($variant($ty)),+ }

        impl OutputItem {
            /// snake_case discriminator of the inner type.
            pub fn type_name(&self) -> &'static str {
                match self { $(OutputItem::$variant(_) => <$ty>::type_name()),+ }
            }
            /// Dedup identity of the inner finding.
            pub fn compare_key(&self) -> CompareKey {
                match self { $(OutputItem::$variant(x) => x.compare_key()),+ }
            }
            pub fn meta(&self) -> &Meta {
                match self { $(OutputItem::$variant(x) => x.meta()),+ }
            }
            pub fn meta_mut(&mut self) -> &mut Meta {
                match self { $(OutputItem::$variant(x) => x.meta_mut()),+ }
            }
            /// Serialize to a loose map with `_type` injected (Python `toDict`).
            pub fn to_map(&self) -> Map {
                match self { $(OutputItem::$variant(x) => x.to_map()),+ }
            }
            /// Reconstruct from a loose map using its `_type` discriminator (Python
            /// `_convert_item_schema` "_type key" path). Returns `None` if `_type` is
            /// missing/unknown or the inner `load` rejects the map.
            pub fn from_map(item: &Map, output_map: &OutputMap) -> Option<OutputItem> {
                let ty = item.get("_type").and_then(|v| v.as_str())?;
                OutputItem::load_as(ty, item, output_map)
            }

            /// Load the item as a specific candidate type name (Python's
            /// "try each candidate in `output_types`" path). Returns `None` if the name
            /// is unknown or the inner `load` rejects the map.
            pub fn load_as(name: &str, item: &Map, output_map: &OutputMap) -> Option<OutputItem> {
                match name {
                    $(n if n == <$ty>::type_name() =>
                        <$ty>::load(item, output_map).map(OutputItem::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

output_item! {
    // Findings
    Subdomain => Subdomain,
    Ip => Ip,
    Port => Port,
    Url => Url,
    Tag => Tag,
    Exploit => Exploit,
    UserAccount => UserAccount,
    Vulnerability => Vulnerability,
    Certificate => Certificate,
    Record => Record,
    Domain => Domain,
    Ai => Ai,
    Technology => Technology,
    // Execution
    Target => Target,
    Progress => Progress,
    Info => Info,
    Warning => Warning,
    Error => Error,
    State => State,
    // Stat
    Stat => Stat,
}

/// Finding type names (Python `FINDING_TYPES`).
pub const FINDING_TYPE_NAMES: &[&str] = &[
    "subdomain", "ip", "port", "url", "tag", "exploit", "user_account", "vulnerability",
    "certificate", "record", "domain", "ai", "technology",
];
/// Execution type names (Python `EXECUTION_TYPES`).
pub const EXECUTION_TYPE_NAMES: &[&str] = &["target", "progress", "info", "warning", "error", "state"];
/// Stat type names (Python `STAT_TYPES`).
pub const STAT_TYPE_NAMES: &[&str] = &["stat"];

impl OutputItem {
    /// Whether this is a (persisted/exported/deduped) finding.
    pub fn is_finding(&self) -> bool {
        FINDING_TYPE_NAMES.contains(&self.type_name())
    }

    /// Convenience: parse a JSON value into an item via its `_type`.
    pub fn from_json(value: &serde_json::Value) -> Option<OutputItem> {
        let obj = value.as_object()?;
        OutputItem::from_map(obj, &OutputMap::new())
    }
}

// --------------------------------------------------------------------------------- Dedup

/// Ranking for "which duplicate survives": source preference dominates, then newest
/// timestamp (Python `__gt__` + per-type source overrides: Url→httpx, Port→nmap).
fn dedup_rank(item: &OutputItem) -> (i32, f64) {
    let src = &item.meta().source;
    let pref = match item {
        OutputItem::Url(_) => (src == "httpx") as i32,
        OutputItem::Port(_) => (src == "nmap") as i32,
        _ => 0,
    };
    (pref, item.meta().timestamp)
}

fn rank_cmp(a: &OutputItem, b: &OutputItem) -> std::cmp::Ordering {
    let (pa, ta) = dedup_rank(a);
    let (pb, tb) = dedup_rank(b);
    pa.cmp(&pb).then(ta.total_cmp(&tb))
}

/// First-wins dedup by `compare_key` (Python `remove_duplicates`).
pub fn remove_duplicates(items: Vec<OutputItem>) -> Vec<OutputItem> {
    use std::collections::HashSet;
    let mut seen: HashSet<CompareKey> = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if seen.insert(it.compare_key()) {
            out.push(it);
        }
    }
    out
}

/// Group-and-mark dedup run at the aggregating runner (Python `mark_duplicates`):
/// in each group of ≥2 with the same `compare_key`, the highest-ranked item is the
/// "main" (`duplicate=false`, collects the others' uuids in `related`); the rest are
/// marked `duplicate=true`. O(n).
pub fn mark_duplicates(items: &mut [OutputItem]) {
    use std::collections::HashMap;
    let mut groups: HashMap<CompareKey, Vec<usize>> = HashMap::new();
    for (i, it) in items.iter().enumerate() {
        groups.entry(it.compare_key()).or_default().push(i);
    }
    for (_key, idxs) in groups {
        if idxs.len() < 2 {
            continue;
        }
        let main_idx = *idxs
            .iter()
            .max_by(|&&a, &&b| rank_cmp(&items[a], &items[b]))
            .unwrap();
        let mut related: Vec<String> = Vec::new();
        for &i in &idxs {
            if i == main_idx {
                continue;
            }
            items[i].meta_mut().duplicate = true;
            let uuid = items[i].meta().uuid.clone();
            if !uuid.is_empty() {
                related.push(uuid);
            }
        }
        let m = items[main_idx].meta_mut();
        m.duplicate = false;
        for r in related {
            if !m.related.contains(&r) {
                m.related.push(r);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(v: serde_json::Value) -> Map {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn type_names_match_python() {
        assert_eq!(Url::type_name(), "url");
        assert_eq!(UserAccount::type_name(), "user_account");
        assert_eq!(Vulnerability::type_name(), "vulnerability");
    }

    #[test]
    fn url_dedup_key_is_url_only() {
        let a = Url::load(&map(json!({"url": "https://x.com/", "status_code": 200})), &OutputMap::new()).unwrap();
        let b = Url::load(&map(json!({"url": "https://x.com/", "status_code": 404, "title": "z"})), &OutputMap::new()).unwrap();
        let c = Url::load(&map(json!({"url": "https://y.com/"})), &OutputMap::new()).unwrap();
        assert_eq!(a.compare_key(), b.compare_key()); // same url => same identity
        assert_ne!(a.compare_key(), c.compare_key());
    }

    #[test]
    fn url_post_init_normalizes() {
        let u = Url::load(
            &map(json!({"url": "https://ex.com/", "status_code": 200,
                        "response_headers": {"Server": "nginx", "Content-Type": "text/html; charset=utf-8"}})),
            &OutputMap::new(),
        )
        .unwrap();
        assert_eq!(u.host, "ex.com");
        assert_eq!(u.protocol, "https");
        assert!(u.verified); // high confidence + status_code != 0
        assert!(u.is_root);
        assert_eq!(u.webserver, "nginx");
        assert_eq!(u.content_type, "text/html");
        assert_eq!(u.tech, vec!["nginx".to_string()]);
    }

    #[test]
    fn url_roundtrip_is_idempotent() {
        let item = OutputItem::from_map(
            &map(json!({"_type": "url", "url": "https://ex.com/a", "status_code": 200,
                        "_uuid": "u1", "_source": "httpx", "_timestamp": 1.0})),
            &OutputMap::new(),
        )
        .unwrap();
        let m = item.to_map();
        let back = OutputItem::from_map(&m, &OutputMap::new()).unwrap();
        assert_eq!(item, back);
        assert!(matches!(back, OutputItem::Url(_)));
    }

    #[test]
    fn reconstruction_picks_right_variant() {
        let v = OutputItem::from_map(
            &map(json!({"_type": "port", "port": 22, "ip": "1.1.1.1", "state": "open"})),
            &OutputMap::new(),
        )
        .unwrap();
        assert_eq!(v.type_name(), "port");
        assert!(matches!(v, OutputItem::Port(_)));
    }

    #[test]
    fn load_rejects_mismatch_and_empty() {
        // _type mismatch
        assert!(Url::load(&map(json!({"_type": "port", "url": "x"})), &OutputMap::new()).is_none());
        // no data fields present
        assert!(Port::load(&map(json!({"_type": "port"})), &OutputMap::new()).is_none());
        // unknown _type at the enum level
        assert!(OutputItem::from_map(&map(json!({"_type": "nope", "x": 1})), &OutputMap::new()).is_none());
    }

    #[test]
    fn output_map_renames_source_keys() {
        // tool emits "ipv4"; map it onto the `ip` field.
        let mut om = OutputMap::new();
        om.insert("ip".into(), "ipv4".into());
        om.insert("port".into(), "p".into());
        let port = Port::load(&map(json!({"p": 443, "ipv4": "2.2.2.2", "state": "open"})), &om).unwrap();
        assert_eq!(port.port, 443);
        assert_eq!(port.ip, "2.2.2.2");
    }

    #[test]
    fn vulnerability_post_init_severity_and_ordinals() {
        let v = Vulnerability::load(
            &map(json!({"name": "X", "cvss_score": 9.5, "confidence": "high",
                        "references": ["https://a", "https://b"]})),
            &OutputMap::new(),
        )
        .unwrap();
        assert_eq!(v.severity, "critical"); // derived from cvss
        assert_eq!(v.severity_nb, 0); // critical
        assert_eq!(v.confidence_nb, 1); // high
        assert_eq!(v.reference, "https://a"); // first reference
    }

    #[test]
    fn remove_duplicates_first_wins() {
        let a = OutputItem::Url(Url { url: "https://x".into(), ..Default::default() });
        let b = OutputItem::Url(Url { url: "https://x".into(), status_code: 200, ..Default::default() });
        let c = OutputItem::Url(Url { url: "https://y".into(), ..Default::default() });
        let out = remove_duplicates(vec![a, b, c]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn mark_duplicates_prefers_httpx_then_newest() {
        let mk = |source: &str, ts: f64, uuid: &str| {
            let mut u = Url { url: "https://x".into(), ..Default::default() };
            u.meta.source = source.into();
            u.meta.timestamp = ts;
            u.meta.uuid = uuid.into();
            OutputItem::Url(u)
        };
        // older httpx should beat newer non-httpx (source preference dominates).
        let mut items = vec![mk("katana", 100.0, "a"), mk("httpx", 1.0, "b")];
        mark_duplicates(&mut items);
        let httpx = items.iter().find(|i| i.meta().source == "httpx").unwrap();
        let katana = items.iter().find(|i| i.meta().source == "katana").unwrap();
        assert!(!httpx.meta().duplicate, "httpx item should be the main");
        assert!(katana.meta().duplicate, "katana item should be the duplicate");
        assert!(httpx.meta().related.contains(&"a".to_string()));
    }
}
