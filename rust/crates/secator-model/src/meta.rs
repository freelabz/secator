//! Internal/meta fields carried by every output record.
//!
//! Maps to Python's `_`-prefixed dataclass fields (`_uuid`, `_source`, `_timestamp`,
//! `_context`, `_duplicate`, `_related`, `_tagged`). In Python these are flattened into
//! the item dict; here we flatten `Meta` into each record via `#[serde(flatten)]` so the
//! JSON shape matches (`{"url": ..., "_uuid": ..., "_source": ...}`).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    #[serde(rename = "_uuid", default)]
    pub uuid: String,
    #[serde(rename = "_source", default)]
    pub source: String,
    #[serde(rename = "_timestamp", default)]
    pub timestamp: f64,
    #[serde(rename = "_context", default)]
    pub context: JsonMap<String, Value>,
    #[serde(rename = "_duplicate", default)]
    pub duplicate: bool,
    #[serde(rename = "_related", default)]
    pub related: Vec<String>,
    #[serde(rename = "_tagged", default)]
    pub tagged: bool,
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            uuid: String::new(),
            source: String::new(),
            timestamp: 0.0,
            context: JsonMap::new(),
            duplicate: false,
            related: Vec::new(),
            tagged: false,
        }
    }
}

impl Meta {
    /// Current unix time as seconds (Python `time.time()` default for `_timestamp`).
    pub fn now() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// A `Meta` with `timestamp` set to now (used by constructors).
    pub fn fresh() -> Self {
        Meta {
            timestamp: Meta::now(),
            ..Meta::default()
        }
    }
}
