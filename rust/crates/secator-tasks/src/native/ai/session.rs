//! Session save/resume — persist chat history to disk so the operator can
//! pick up where they left off.
//!
//! Layout: `<config.dirs.data>/sessions/<sanitized-name>.json`. One file per
//! named session. The schema is intentionally hand-rolled (not the raw
//! `ChatMessage` shape) so future changes to litellm-rust don't break old
//! sessions.

// `SessionRecord::new`, `SessionMeta`, and `list` aren't called from the
// agent loop yet (they're for the eventual session-picker CLI subcommand)
// but the tests exercise them. Allow dead_code so the public API stays
// available without warnings.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use litellm_rust::{ChatMessage, ChatMessageContent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::history::ChatHistory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub name: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub mode: String,
    /// ISO-8601 timestamp set on first save. Empty when restoring from a session
    /// written by an older build that didn't stamp it.
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    pub messages: Vec<StoredMessage>,
}

/// Mirror of `ChatMessage` we control directly, so a litellm-rust schema bump
/// doesn't silently break replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub role: String,
    /// Text content (we only persist text-mode messages for v1; multipart
    /// content isn't surfaced in the current loop).
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
}

impl SessionRecord {
    pub fn new(name: impl Into<String>, model: impl Into<String>, mode: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: model.into(),
            mode: mode.into(),
            created_at: String::new(),
            updated_at: String::new(),
            messages: Vec::new(),
        }
    }

    pub fn from_history(
        name: impl Into<String>,
        model: impl Into<String>,
        mode: impl Into<String>,
        history: &ChatHistory,
        created_at: String,
        updated_at: String,
    ) -> Self {
        Self {
            name: name.into(),
            model: model.into(),
            mode: mode.into(),
            created_at,
            updated_at,
            messages: history.messages.iter().map(StoredMessage::from_chat).collect(),
        }
    }

    pub fn to_history(&self) -> ChatHistory {
        let mut h = ChatHistory::new();
        h.messages = self.messages.iter().map(StoredMessage::to_chat).collect();
        h
    }
}

impl StoredMessage {
    fn from_chat(m: &ChatMessage) -> Self {
        let content = match &m.content {
            ChatMessageContent::Text(s) => s.clone(),
            // Multi-part content gets flattened to a JSON string so we
            // don't lose the structure — we just can't round-trip it back
            // into the typed parts on load (v1 limitation).
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        Self {
            role: m.role.clone(),
            content,
            tool_call_id: m.tool_call_id.clone(),
            tool_calls: m.tool_calls.clone(),
        }
    }

    fn to_chat(&self) -> ChatMessage {
        ChatMessage {
            role: self.role.clone(),
            content: ChatMessageContent::Text(self.content.clone()),
            name: None,
            tool_call_id: self.tool_call_id.clone(),
            tool_calls: self.tool_calls.clone(),
            function_call: None,
            provider_specific_fields: None,
        }
    }
}

/// Compute the on-disk path for a session within `root` (typically
/// `<config.dirs.data>/sessions`). The name is sanitized — only alphanumeric
/// + `-_.` survive; anything else becomes `_`.
pub fn session_path(root: &Path, name: &str) -> PathBuf {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let safe = if sanitized.is_empty() { "untitled".into() } else { sanitized };
    root.join(format!("{safe}.json"))
}

/// Persist `record` to `root/<name>.json`. Creates the directory if needed.
pub fn save(root: &Path, record: &SessionRecord) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| format!("create sessions dir: {e}"))?;
    let path = session_path(root, &record.name);
    let pretty = serde_json::to_string_pretty(record).map_err(|e| format!("serialize session: {e}"))?;
    fs::write(&path, pretty).map_err(|e| format!("write {path:?}: {e}"))?;
    Ok(path)
}

/// Load a session by name. Returns Err if the file doesn't exist or doesn't
/// parse.
pub fn load(root: &Path, name: &str) -> Result<SessionRecord, String> {
    let path = session_path(root, name);
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    serde_json::from_str::<SessionRecord>(&raw).map_err(|e| format!("parse {path:?}: {e}"))
}

/// Light metadata for the session picker. Sorted newest-first by `updated_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub name: String,
    pub model: String,
    pub mode: String,
    pub updated_at: String,
    pub message_count: usize,
}

pub fn list(root: &Path) -> Vec<SessionMeta> {
    let Ok(entries) = fs::read_dir(root) else { return Vec::new() };
    let mut metas: Vec<SessionMeta> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e != "json").unwrap_or(true) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        let Ok(rec) = serde_json::from_str::<SessionRecord>(&raw) else { continue };
        metas.push(SessionMeta {
            name: rec.name,
            model: rec.model,
            mode: rec.mode,
            updated_at: rec.updated_at,
            message_count: rec.messages.len(),
        });
    }
    metas.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    metas
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn session_path_sanitizes_name() {
        let root = PathBuf::from("/tmp/sessions");
        let p = session_path(&root, "scan example.com/path?q=1");
        assert!(p.to_string_lossy().ends_with("scan_example.com_path_q_1.json"));
    }

    #[test]
    fn session_path_falls_back_to_untitled_when_fully_sanitized() {
        // 7 non-alnum chars → 7 underscores → still a non-empty name, NOT "untitled".
        let p = session_path(&PathBuf::from("/tmp"), "!@#$%^&");
        assert!(p.to_string_lossy().ends_with("_______.json"), "got {p:?}");
        // Empty name → "untitled".
        let empty = session_path(&PathBuf::from("/tmp"), "");
        assert!(empty.to_string_lossy().ends_with("untitled.json"));
    }

    #[test]
    fn save_then_load_roundtrips_messages() {
        let tmp = tempdir().unwrap();
        let mut h = ChatHistory::new();
        h.set_system("sys");
        h.add_user("hi");
        h.add_assistant(
            "",
            Some(serde_json::json!([{"id":"c1","type":"function","function":{"name":"stop","arguments":"{}"}}])),
        );
        h.add_tool_result("c1", "ok");

        let rec = SessionRecord::from_history(
            "my-session",
            "openai/gpt-4o",
            "attack",
            &h,
            "2026-06-12T20:00:00Z".into(),
            "2026-06-12T20:05:00Z".into(),
        );
        let path = save(tmp.path(), &rec).unwrap();
        assert!(path.exists());

        let back = load(tmp.path(), "my-session").unwrap();
        assert_eq!(back.name, "my-session");
        assert_eq!(back.model, "openai/gpt-4o");
        assert_eq!(back.mode, "attack");
        assert_eq!(back.messages.len(), 4);

        let history = back.to_history();
        let (s, u, a, t) = history.count_by_role();
        assert_eq!((s, u, a, t), (1, 1, 1, 1));
    }

    #[test]
    fn load_missing_session_errors() {
        let tmp = tempdir().unwrap();
        let err = load(tmp.path(), "nope").unwrap_err();
        assert!(err.contains("read"));
    }

    #[test]
    fn list_returns_newest_first() {
        let tmp = tempdir().unwrap();
        let r1 = SessionRecord {
            updated_at: "2026-01-01T00:00:00Z".into(),
            ..SessionRecord::new("old", "m", "attack")
        };
        let r2 = SessionRecord {
            updated_at: "2026-06-12T00:00:00Z".into(),
            ..SessionRecord::new("new", "m", "attack")
        };
        save(tmp.path(), &r1).unwrap();
        save(tmp.path(), &r2).unwrap();
        let metas = list(tmp.path());
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].name, "new", "newest first");
        assert_eq!(metas[1].name, "old");
    }

    #[test]
    fn list_skips_non_json_and_garbage() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("notes.txt"), b"ignore me").unwrap();
        fs::write(tmp.path().join("broken.json"), b"{this is not json").unwrap();
        save(tmp.path(), &SessionRecord::new("good", "m", "chat")).unwrap();
        let metas = list(tmp.path());
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "good");
    }
}
