//! Chat history — system / user / assistant / tool messages in OpenAI format.
//!
//! Mirrors Python `secator.ai.history.ChatHistory`. The shape is the same
//! OpenAI message format the litellm-rust client serializes, so we just hand
//! the buffered `Vec<ChatMessage>` straight to `ChatRequest.messages`.
//!
//! Token budget: each message's text content is counted via a chars/4
//! heuristic (close enough to GPT-style tokenization for the budget decision
//! that triggers trimming). The system message is always preserved; oldest
//! non-system messages are dropped first. When the budget is still exceeded
//! after dropping non-tool turns, tool-result messages get truncated with a
//! `[TRUNCATED]` marker (Python parity with `truncate_to_tokens`).

use litellm_rust::{ChatMessage, ChatMessageContent};
use serde_json::Value;

/// Rough chars-per-token ratio. GPT-style tokenizers average ~4 chars/token
/// on natural-language English; tool output (JSON, hex blobs) tokenizes
/// denser but for budget purposes the over-estimate keeps us safe.
pub const CHARS_PER_TOKEN: usize = 4;

/// Default hard cap for `to_messages_within` — sized to comfortably fit
/// inside a 128k-window model with room for output. Operators override via
/// the agent loop's `max_tokens_total` opt (Python parity).
pub const DEFAULT_MAX_TOKENS_TOTAL: usize = 100_000;

/// Max bytes of any single tool result we keep in history. Larger results
/// get the tail clipped + a `[TRUNCATED]` marker appended. Keeps a single
/// noisy nuclei run from blowing the budget. Matches the per-action cap in
/// `dispatch.rs` (40 KB ≈ 10k tokens).
pub const MAX_TOOL_BYTES_IN_HISTORY: usize = 40_000;

#[derive(Debug, Clone, Default)]
pub struct ChatHistory {
    pub messages: Vec<ChatMessage>,
}

impl ChatHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace any existing system message and push it to the front. Python
    /// `set_system` semantics: there should be at most one.
    pub fn set_system(&mut self, prompt: impl Into<String>) {
        self.messages.retain(|m| m.role != "system");
        self.messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: ChatMessageContent::Text(prompt.into()),
                name: None,
                tool_call_id: None,
                tool_calls: None,
                function_call: None,
                provider_specific_fields: None,
            },
        );
    }

    pub fn add_user(&mut self, content: impl Into<String>) {
        self.messages.push(ChatMessage {
            role: "user".into(),
            content: ChatMessageContent::Text(content.into()),
            name: None,
            tool_call_id: None,
            tool_calls: None,
            function_call: None,
            provider_specific_fields: None,
        });
    }

    /// Add an assistant turn. `tool_calls` is the raw OpenAI-shape array from
    /// `ChatResponse.tool_calls`; pass `None` for a text-only reply.
    pub fn add_assistant(&mut self, content: impl Into<String>, tool_calls: Option<Value>) {
        self.messages.push(ChatMessage {
            role: "assistant".into(),
            content: ChatMessageContent::Text(content.into()),
            name: None,
            tool_call_id: None,
            tool_calls,
            function_call: None,
            provider_specific_fields: None,
        });
    }

    /// Add a `tool` role message tying a result string back to a specific
    /// `tool_call_id` from the matching assistant message.
    pub fn add_tool_result(&mut self, tool_call_id: impl Into<String>, content: impl Into<String>) {
        self.messages.push(ChatMessage {
            role: "tool".into(),
            content: ChatMessageContent::Text(content.into()),
            name: None,
            tool_call_id: Some(tool_call_id.into()),
            tool_calls: None,
            function_call: None,
            provider_specific_fields: None,
        });
    }

    /// Snapshot of the full message buffer ready to send to the LLM.
    pub fn to_messages(&self) -> Vec<ChatMessage> {
        self.messages.clone()
    }

    /// Snapshot trimmed to fit within `max_tokens` (Python `to_messages(max)`
    /// + `trim_messages`). Always keeps the system message + the most-recent
    /// turn. Drops oldest non-system messages first; if still over budget,
    /// truncates the largest tool-result message in place.
    pub fn to_messages_within(&self, max_tokens: usize) -> Vec<ChatMessage> {
        if max_tokens == 0 {
            return self.to_messages();
        }
        let mut msgs = self.messages.clone();
        if total_tokens(&msgs) <= max_tokens {
            return msgs;
        }
        // Find indices of non-system messages, oldest first. Always keep the
        // last message so the most recent turn survives.
        let mut drop_idx: Vec<usize> = Vec::new();
        for (i, m) in msgs.iter().enumerate() {
            if m.role != "system" && i + 1 < msgs.len() {
                drop_idx.push(i);
            }
        }
        for i in drop_idx {
            if total_tokens(&msgs) <= max_tokens {
                break;
            }
            // Don't actually `remove()` — mark with a tiny placeholder so
            // indices stay stable, then filter at the end.
            msgs[i].content = ChatMessageContent::Text(String::new());
        }
        msgs.retain(|m| match &m.content {
            ChatMessageContent::Text(s) if s.is_empty() => m.role == "system",
            _ => true,
        });
        // Still over? Truncate the longest tool-result content.
        while total_tokens(&msgs) > max_tokens {
            let Some(worst) = msgs
                .iter()
                .enumerate()
                .filter(|(_, m)| m.role == "tool")
                .max_by_key(|(_, m)| content_len(*m))
                .map(|(i, _)| i)
            else {
                break;
            };
            let body = match &msgs[worst].content {
                ChatMessageContent::Text(s) => s.clone(),
                _ => continue,
            };
            let max_chars = max_tokens.saturating_mul(CHARS_PER_TOKEN) / 4;
            if body.len() <= max_chars {
                break;
            }
            let head = &body[..max_chars.min(body.len())];
            let truncated = format!("{head}\n[TRUNCATED — {} bytes elided]", body.len() - head.len());
            msgs[worst].content = ChatMessageContent::Text(truncated);
        }
        msgs
    }

    /// Approximate total token count across every message (chars/4 heuristic
    /// applied to text bodies; non-text parts are ignored). Used by the agent
    /// loop to decide when to invoke `to_messages_within`.
    pub fn token_count(&self) -> usize {
        total_tokens(&self.messages)
    }

    /// Trim a single string to `max_tokens` worth of characters with an
    /// `[TRUNCATED]` marker. Python `truncate_to_tokens` minus the file
    /// fallback (we don't write the overflow to disk because the dispatcher
    /// already returns a path via `cached_path` on ExploitDB items and the
    /// stdout/stderr buffer for shell commands).
    pub fn truncate_to_tokens(content: &str, max_tokens: usize) -> String {
        let max_chars = max_tokens.saturating_mul(CHARS_PER_TOKEN);
        if content.len() <= max_chars {
            return content.to_string();
        }
        let head: String = content.chars().take(max_chars).collect();
        format!(
            "{head}\n[TRUNCATED — {} chars elided. Use shell/grep on the artifact path to read more.]",
            content.len() - head.len()
        )
    }

    /// Count messages by role for `Info` lines / telemetry. Not yet wired into
    /// the loop output but kept exposed for follow-up Phase F (session
    /// save/resume) which needs per-role buckets to render summaries.
    #[allow(dead_code)]
    pub fn count_by_role(&self) -> (usize, usize, usize, usize) {
        let mut sys = 0;
        let mut usr = 0;
        let mut asst = 0;
        let mut tool = 0;
        for m in &self.messages {
            match m.role.as_str() {
                "system" => sys += 1,
                "user" => usr += 1,
                "assistant" => asst += 1,
                "tool" => tool += 1,
                _ => {}
            }
        }
        (sys, usr, asst, tool)
    }
}

/// Sum of approximate tokens across `msgs` (chars/CHARS_PER_TOKEN).
fn total_tokens(msgs: &[ChatMessage]) -> usize {
    msgs.iter()
        .map(|m| (content_len(m) + CHARS_PER_TOKEN - 1) / CHARS_PER_TOKEN)
        .sum()
}

/// Character length of a message's text content (0 for non-text parts).
fn content_len(m: &ChatMessage) -> usize {
    match &m.content {
        ChatMessageContent::Text(s) => s.len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content_str(m: &ChatMessage) -> &str {
        match &m.content {
            ChatMessageContent::Text(s) => s,
            _ => "",
        }
    }

    #[test]
    fn set_system_replaces_and_keeps_first() {
        let mut h = ChatHistory::new();
        h.add_user("hi");
        h.set_system("you are a pentester");
        h.set_system("you are a senior pentester"); // replaces
        assert_eq!(h.messages.len(), 2);
        assert_eq!(h.messages[0].role, "system");
        assert_eq!(content_str(&h.messages[0]), "you are a senior pentester");
        assert_eq!(h.messages[1].role, "user");
    }

    #[test]
    fn add_assistant_carries_tool_calls() {
        let mut h = ChatHistory::new();
        let tcs = serde_json::json!([{"id":"c1","type":"function","function":{"name":"x","arguments":"{}"}}]);
        h.add_assistant("", Some(tcs.clone()));
        let last = h.messages.last().unwrap();
        assert_eq!(last.role, "assistant");
        assert_eq!(last.tool_calls.as_ref().unwrap(), &tcs);
    }

    #[test]
    fn add_tool_result_sets_tool_call_id() {
        let mut h = ChatHistory::new();
        h.add_tool_result("call_42", "OK");
        let last = h.messages.last().unwrap();
        assert_eq!(last.role, "tool");
        assert_eq!(last.tool_call_id.as_deref(), Some("call_42"));
        assert_eq!(content_str(last), "OK");
    }

    #[test]
    fn token_count_uses_chars_per_4_heuristic() {
        let mut h = ChatHistory::new();
        h.add_user("hello world"); // 11 chars → ceil(11/4) = 3 tokens
        h.add_user(&"x".repeat(40)); // 40 chars → 10 tokens
        assert_eq!(h.token_count(), 13);
    }

    #[test]
    fn to_messages_within_returns_full_when_under_budget() {
        let mut h = ChatHistory::new();
        h.set_system("sys");
        h.add_user("hi");
        h.add_assistant("hello", None);
        let trimmed = h.to_messages_within(10_000);
        assert_eq!(trimmed.len(), 3);
    }

    #[test]
    fn to_messages_within_drops_oldest_non_system() {
        let mut h = ChatHistory::new();
        h.set_system("sys");
        for i in 0..10 {
            h.add_user(&format!("user msg {i} {}", "x".repeat(400)));
            h.add_assistant(&format!("assistant {i} {}", "y".repeat(400)), None);
        }
        let before = h.token_count();
        // Budget cap below current usage forces trimming.
        let trimmed = h.to_messages_within(before / 2);
        // System still first.
        assert_eq!(trimmed[0].role, "system");
        // Last message preserved (most-recent turn).
        assert_eq!(trimmed.last().unwrap().role, "assistant");
        // Trimmed budget honored.
        assert!(total_tokens(&trimmed) <= before / 2 + 50, "got {} tokens", total_tokens(&trimmed));
    }

    #[test]
    fn to_messages_within_truncates_last_tool_result_when_still_over() {
        // When the SINGLE last tool message alone blows the budget, dropping
        // older non-system messages can't help — we fall through to the
        // truncate-largest-tool branch.
        let mut h = ChatHistory::new();
        h.set_system("sys");
        h.add_user("brief"); // small filler
        // Huge tool result is the LAST message — kept by the drop-oldest pass,
        // then targeted for in-place truncation by the second pass.
        h.add_tool_result("call_1", "x".repeat(200_000));
        let trimmed = h.to_messages_within(5_000);
        let tool_msg = trimmed.iter().find(|m| m.role == "tool").unwrap();
        let body = match &tool_msg.content {
            ChatMessageContent::Text(s) => s,
            _ => panic!("expected text"),
        };
        assert!(body.contains("TRUNCATED"));
        assert!(body.len() < 200_000);
    }

    #[test]
    fn to_messages_within_drops_old_tool_messages_to_make_room() {
        // A huge OLD tool message gets dropped (not truncated) — recent
        // messages have higher signal value, drop oldest first matches
        // Python's `litellm.trim_messages` behaviour.
        let mut h = ChatHistory::new();
        h.set_system("sys");
        h.add_tool_result("call_1", "x".repeat(200_000)); // oldest non-system
        h.add_user("anything");
        let trimmed = h.to_messages_within(5_000);
        // Old tool message dropped.
        assert!(trimmed.iter().all(|m| m.role != "tool"));
        // System + last user survive.
        assert_eq!(trimmed.len(), 2);
        assert_eq!(trimmed[0].role, "system");
        assert_eq!(trimmed[1].role, "user");
    }

    #[test]
    fn truncate_to_tokens_adds_marker_when_exceeded() {
        let long = "a".repeat(100_000);
        let t = ChatHistory::truncate_to_tokens(&long, 1000);
        assert!(t.contains("TRUNCATED"));
        assert!(t.len() < long.len());
        // Under-budget input is returned untouched.
        let short = "hello";
        assert_eq!(ChatHistory::truncate_to_tokens(short, 1000), short);
    }

    #[test]
    fn count_by_role_buckets() {
        let mut h = ChatHistory::new();
        h.set_system("s");
        h.add_user("u1");
        h.add_assistant("a1", None);
        h.add_user("u2");
        h.add_assistant("a2", None);
        h.add_tool_result("c1", "r");
        let (s, u, a, t) = h.count_by_role();
        assert_eq!((s, u, a, t), (1, 2, 2, 1));
    }
}
