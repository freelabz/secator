//! Execution + stat output types (control/observability, not findings).
//!
//! Maps to Python `Target`, `Progress`, `Info`, `Warning`, `Error`, `State`, `Stat`.
//! See `../docs/rewrite/03-data-model.md` §4/§5.
//!
//! NOTE: in Python `Info`/`Warning`/`Error` lack a `_tagged` field; here the shared `Meta`
//! always carries it, so their JSON includes `_tagged: false`. Harmless for Rust
//! round-trips; can be slimmed later if exact Python-shape parity is required.

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::key::{CompareKey, KeyPart};
use crate::meta::Meta;
use crate::output_type::{keyed, OutputType};

type Obj = JsonMap<String, Value>;

// ------------------------------------------------------------------------------ Target
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Target {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Target {
    fn type_name() -> &'static str { "target" }
    fn data_fields() -> &'static [&'static str] { &["name", "type"] }
    fn compare_key(&self) -> CompareKey {
        keyed("target", vec![KeyPart::str(&self.name), KeyPart::str(&self.type_)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        if self.type_.is_empty() {
            self.type_ = autodetect_type(&self.name);
        }
    }
}

/// Simplified target-type autodetection (Python `autodetect_type` uses the `validators`
/// crate; full fidelity comes with a dedicated input-detection module).
pub fn autodetect_type(name: &str) -> String {
    if name.contains("://") {
        "url".into()
    } else if is_ipv4(name) {
        "ip".into()
    } else if is_cidr(name) {
        "cidr_range".into()
    } else if name.contains('@') {
        "email".into()
    } else if name.contains('.') {
        "host".into()
    } else {
        "string".into()
    }
}
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}
fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, mask)) => is_ipv4(ip) && mask.parse::<u8>().map(|m| m <= 32).unwrap_or(false),
        None => false,
    }
}

// ---------------------------------------------------------------------------- Progress
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Progress {
    pub percent: f64,
    pub extra_data: Obj,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Progress {
    fn type_name() -> &'static str { "progress" }
    fn data_fields() -> &'static [&'static str] { &["percent", "extra_data"] }
    fn compare_key(&self) -> CompareKey {
        keyed("progress", vec![KeyPart::float(self.percent), KeyPart::str(&self.meta.source)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        if !(0.0..=100.0).contains(&self.percent) {
            self.percent = 0.0;
        }
    }
}

// -------------------------------------------------------------------------------- Info
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Info {
    pub message: String,
    pub task_id: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Info {
    fn type_name() -> &'static str { "info" }
    fn data_fields() -> &'static [&'static str] { &["message", "task_id"] }
    fn compare_key(&self) -> CompareKey {
        keyed("info", vec![KeyPart::str(&self.message), KeyPart::str(&self.meta.source)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ----------------------------------------------------------------------------- Warning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Warning {
    pub message: String,
    pub message_color: String,
    pub task_id: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Warning {
    fn type_name() -> &'static str { "warning" }
    fn data_fields() -> &'static [&'static str] { &["message", "message_color", "task_id"] }
    fn compare_key(&self) -> CompareKey {
        keyed("warning", vec![KeyPart::str(&self.message), KeyPart::str(&self.meta.source)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
    fn post_init(&mut self) {
        // Python keeps the colored variant and strips markup from `message`.
        if self.message_color.is_empty() {
            self.message_color = self.message.clone();
        }
        self.message = strip_markup(&self.message);
    }
}

/// Strip simple `[...]` rich markup tokens (Python `strip_rich_markup`, simplified).
fn strip_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0u32;
    for c in s.chars() {
        match c {
            '[' => depth += 1,
            ']' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

// ------------------------------------------------------------------------------- Error
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Error {
    pub message: String,
    pub traceback: String,
    pub traceback_title: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Error {
    fn type_name() -> &'static str { "error" }
    fn data_fields() -> &'static [&'static str] { &["message", "traceback", "traceback_title"] }
    fn compare_key(&self) -> CompareKey {
        keyed("error", vec![KeyPart::str(&self.message), KeyPart::str(&self.meta.source)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// ------------------------------------------------------------------------------- State
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct State {
    pub task_id: String,
    pub state: String,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for State {
    fn type_name() -> &'static str { "state" }
    fn data_fields() -> &'static [&'static str] { &["task_id", "state"] }
    fn compare_key(&self) -> CompareKey {
        keyed("state", vec![KeyPart::str(&self.task_id), KeyPart::str(&self.state)])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}

// -------------------------------------------------------------------------------- Stat
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Stat {
    pub name: String,
    pub pid: i64,
    pub cpu: f64,
    pub memory: f64,
    pub memory_limit: f64,
    pub net_conns: Option<i64>,
    pub extra_data: Obj,
    #[serde(flatten)]
    pub meta: Meta,
}
impl OutputType for Stat {
    fn type_name() -> &'static str { "stat" }
    fn data_fields() -> &'static [&'static str] {
        &["name", "pid", "cpu", "memory", "memory_limit", "net_conns", "extra_data"]
    }
    fn compare_key(&self) -> CompareKey {
        let net = self.net_conns.map(KeyPart::Int).unwrap_or(KeyPart::Null);
        let extra = serde_json::to_string(&self.extra_data).unwrap_or_default();
        keyed("stat", vec![
            KeyPart::str(&self.name), KeyPart::Int(self.pid), KeyPart::float(self.cpu),
            KeyPart::float(self.memory), KeyPart::float(self.memory_limit), net, KeyPart::Str(extra),
        ])
    }
    fn meta(&self) -> &Meta { &self.meta }
    fn meta_mut(&mut self) -> &mut Meta { &mut self.meta }
}
