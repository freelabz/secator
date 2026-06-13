//! Dedup keys and the loose-map types.
//!
//! `CompareKey` is the Rust analogue of Python `_compare_key()`: the ordered tuple of the
//! `compare=True` fields that defines a finding's identity. See
//! `../docs/rewrite/03-data-model.md` §1/§6.

use serde_json::{Map as JsonMap, Value};

/// A loosely-typed record as parsed from tool output (Python item dict).
pub type Map = JsonMap<String, Value>;

/// `{field -> source_key}` rename mapping consumed by `OutputType::load` (the string-key
/// subset of Python `output_map`; callable mappers live in the parse layer, M2).
pub type OutputMap = std::collections::BTreeMap<String, String>;

/// One component of a dedup key. Hashable so keys can group in a `HashMap` (Python uses a
/// tuple). Floats are stored as their bit pattern for `Eq`/`Hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyPart {
    Str(String),
    Int(i64),
    Bool(bool),
    Float(u64),
    Null,
}

impl KeyPart {
    pub fn float(f: f64) -> Self {
        KeyPart::Float(f.to_bits())
    }
    pub fn str<S: Into<String>>(s: S) -> Self {
        KeyPart::Str(s.into())
    }
}

/// The deduplication identity of a finding. The leading element is the type name so two
/// different types never collide (mirrors `_type` being part of the Python key).
pub type CompareKey = Vec<KeyPart>;
