//! Output parsing: line serializers + the dict→record mapper.
//!
//! Maps to Python `secator/serializers/` and `Runner._convert_item_schema`. A `Command`
//! task feeds each stdout line to its serializers; the resulting loose maps are converted
//! into typed `OutputItem`s via `output_map` + a discriminator + `load`. See
//! `../docs/rewrite/04-task-integration.md` §3F and `08-subsystems.md` §5.

use std::collections::BTreeMap;

use secator_model::{Map, OutputItem, OutputMap};
use serde_json::Value;

/// A line serializer turns one output line into zero or more loose records
/// (Python serializer `.run(line)`).
pub trait Serializer {
    fn run(&self, line: &str) -> Vec<Map>;
}

/// Per-type rename maps (Python task `output_map = {Class: {field: src}}`).
/// Keyed by the type's `type_name()` (snake_case).
pub type OutputMaps = BTreeMap<String, OutputMap>;

/// A discriminator function picks a single candidate type name from a parsed record
/// (Python `output_discriminator`).
pub type Discriminator = fn(&Map) -> Option<&'static str>;

// ----------------------------------------------------------------------- JsonSerializer

/// Extracts the first `{...}` (or `[{...}]` when `list=true`) JSON substring from a
/// line and parses it with serde_json. Tolerant — tools mix logs with JSON.
#[derive(Debug, Clone, Default)]
pub struct JsonSerializer {
    /// When true, the JSON must start at byte 0 of the line.
    pub strict: bool,
    /// Parse a JSON list `[{...}, {...}]` instead of a single object.
    pub list: bool,
}

impl JsonSerializer {
    pub fn new() -> Self { Self::default() }
    pub fn list() -> Self { Self { strict: false, list: true } }
    pub fn strict() -> Self { Self { strict: true, list: false } }
}

impl Serializer for JsonSerializer {
    fn run(&self, line: &str) -> Vec<Map> {
        if self.list {
            return parse_json_list(line, self.strict);
        }
        parse_json_object(line, self.strict).into_iter().collect()
    }
}

fn parse_json_object(line: &str, strict: bool) -> Option<Map> {
    let start = line.find('{')?;
    let end = line.rfind('}')?;
    if start > end {
        return None;
    }
    if strict && start != 0 {
        return None;
    }
    let slice = &line[start..=end];
    let value: Value = serde_json::from_str(slice).ok()?;
    match value {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn parse_json_list(line: &str, strict: bool) -> Vec<Map> {
    let start = match line.find("[{") {
        Some(i) => i,
        None => return vec![],
    };
    let end = match line.rfind("}]") {
        Some(i) => i + 1, // include the ']'
        None => return vec![],
    };
    if strict && start != 0 {
        return vec![];
    }
    let slice = &line[start..=end];
    let value: Value = match serde_json::from_str(slice) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    match value {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .collect(),
        Value::Object(m) => vec![m],
        _ => vec![],
    }
}

// ---------------------------------------------------------------------- RegexSerializer

/// Regex match → named-group record (or `findall` raw matches as a single-field record).
#[derive(Debug, Clone)]
pub struct RegexSerializer {
    re: regex::Regex,
    pub fields: Vec<String>,
    pub findall: bool,
}

impl RegexSerializer {
    pub fn new(pattern: &str, fields: Vec<String>) -> Result<Self, regex::Error> {
        Ok(Self { re: regex::Regex::new(pattern)?, fields, findall: false })
    }
    pub fn findall(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self { re: regex::Regex::new(pattern)?, fields: Vec::new(), findall: true })
    }
}

impl Serializer for RegexSerializer {
    fn run(&self, line: &str) -> Vec<Map> {
        if self.findall {
            let mut out = Vec::new();
            for m in self.re.find_iter(line) {
                let mut rec = Map::new();
                rec.insert("match".to_string(), Value::String(m.as_str().to_string()));
                out.push(rec);
            }
            return out;
        }
        let caps = match self.re.captures(line) {
            Some(c) => c,
            None => return vec![],
        };
        if self.fields.is_empty() {
            let mut rec = Map::new();
            rec.insert(
                "match".to_string(),
                Value::String(caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string()),
            );
            return vec![rec];
        }
        let mut rec = Map::new();
        for f in &self.fields {
            if let Some(m) = caps.name(f) {
                rec.insert(f.clone(), Value::String(m.as_str().to_string()));
            }
        }
        vec![rec]
    }
}

// ---------------------------------------------------------------------------- convert_item

/// Convert a loose record into a typed `OutputItem`.
///
/// Mirrors Python `_convert_item_schema`:
/// - If `discriminator` is provided: its return is the sole candidate (`None` ⇒ no item).
/// - Else if the item has `_type`: candidate set = the matching candidate (if any).
/// - Else: try each candidate in `candidates` order; first that loads non-empty wins.
///
/// `output_maps[type_name]` provides per-candidate field renames (Python `output_map`).
pub fn convert_item(
    item: &Map,
    candidates: &[&str],
    output_maps: &OutputMaps,
    discriminator: Option<Discriminator>,
) -> Option<OutputItem> {
    let empty = OutputMap::new();
    let effective: Vec<&str> = if let Some(d) = discriminator {
        match d(item) {
            Some(n) => vec![n],
            None => vec![],
        }
    } else if let Some(t) = item.get("_type").and_then(|v| v.as_str()) {
        candidates.iter().copied().filter(|c| *c == t).collect()
    } else {
        candidates.to_vec()
    };
    for name in effective {
        let om = output_maps.get(name).unwrap_or(&empty);
        if let Some(out) = OutputItem::load_as(name, item, om) {
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_serializer_extracts_object_from_mixed_line() {
        let s = JsonSerializer::new();
        let out = s.run(r#"INFO loaded {"host":"a.com","input":"x.com"} ok"#);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].get("host").and_then(|v| v.as_str()), Some("a.com"));
    }

    #[test]
    fn json_serializer_strict_requires_start_at_zero() {
        let s = JsonSerializer::strict();
        assert_eq!(s.run("LOG: {\"k\":1}").len(), 0);
        assert_eq!(s.run("{\"k\":1}").len(), 1);
    }

    #[test]
    fn json_serializer_list_mode() {
        let s = JsonSerializer::list();
        let out = s.run(r#"some prefix [{"a":1},{"a":2}] suffix"#);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].get("a").and_then(|v| v.as_i64()), Some(2));
    }

    #[test]
    fn regex_serializer_named_groups() {
        let s = RegexSerializer::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)", vec!["ip".into(), "port".into()]).unwrap();
        let out = s.run("hit on 10.0.0.1:8080 today");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].get("ip").and_then(|v| v.as_str()), Some("10.0.0.1"));
        assert_eq!(out[0].get("port").and_then(|v| v.as_str()), Some("8080"));
    }

    #[test]
    fn regex_serializer_findall() {
        let s = RegexSerializer::findall(r"\b\d+\b").unwrap();
        let out = s.run("there are 3 cats and 4 dogs");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn convert_item_first_matching_candidate_wins() {
        let item = json!({"port": 80, "ip": "1.1.1.1", "state": "open"})
            .as_object().unwrap().clone();
        // Try Url first (no url field -> rejects), then Port (matches).
        let out = convert_item(&item, &["url", "port"], &OutputMaps::new(), None).unwrap();
        assert_eq!(out.type_name(), "port");
    }

    #[test]
    fn convert_item_respects_output_map_rename() {
        // Subfinder emits "input" for the domain.
        let item = json!({"host": "git.example.com", "input": "example.com", "sources": ["alienvault"]})
            .as_object().unwrap().clone();
        let mut maps = OutputMaps::new();
        let mut rename = OutputMap::new();
        rename.insert("domain".into(), "input".into());
        maps.insert("subdomain".into(), rename);
        let out = convert_item(&item, &["subdomain"], &maps, None).unwrap();
        match out {
            OutputItem::Subdomain(s) => {
                assert_eq!(s.host, "git.example.com");
                assert_eq!(s.domain, "example.com");
                assert_eq!(s.sources, vec!["alienvault".to_string()]);
            }
            _ => panic!("expected Subdomain"),
        }
    }

    #[test]
    fn convert_item_discriminator_replaces_candidates() {
        let item = json!({"port": 80, "ip": "1.1.1.1", "state": "open"})
            .as_object().unwrap().clone();
        // Force-pick Url even though only Port would match → returns None.
        let disc: Discriminator = |_m| Some("url");
        let out = convert_item(&item, &["port"], &OutputMaps::new(), Some(disc));
        assert!(out.is_none());
        // None from the discriminator ⇒ no candidates tried.
        let disc2: Discriminator = |_m| None;
        let out2 = convert_item(&item, &["port"], &OutputMaps::new(), Some(disc2));
        assert!(out2.is_none());
    }

    #[test]
    fn convert_item_uses_type_key_when_no_discriminator() {
        let mut item = Map::new();
        item.insert("_type".into(), Value::String("port".into()));
        item.insert("port".into(), json!(443));
        item.insert("ip".into(), json!("9.9.9.9"));
        item.insert("state".into(), json!("open"));
        // Url is first in candidates but _type says port.
        let out = convert_item(&item, &["url", "port"], &OutputMaps::new(), None).unwrap();
        assert_eq!(out.type_name(), "port");
    }
}
