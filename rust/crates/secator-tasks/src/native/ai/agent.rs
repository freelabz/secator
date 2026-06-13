//! The agent loop — drives history + LLM + tool dispatch until the model
//! produces a `stop` tool call, hits `max_iterations`, or stops emitting
//! tool_calls (a natural exit).
//!
//! Mirrors Python `tasks/ai.py::_run_loop` shape, scaled to v1:
//!   * no token-budget summarization (Phase F follow-up),
//!   * no permission-engine interactive prompts (we just emit a Warning when
//!     guardrails deny an action and feed the denial back to the LLM),
//!   * no remote backend / subagent dispatch.

use litellm_rust::{ChatRequest, ChatResponse, LiteLLM};
use litellm_rust::registry::ModelPricing;
use secator_model::{Ai, Error, Info, Map, OutputItem, Warning};
use serde_json::Value;

use super::encryption::SensitiveDataEncryptor;
use super::guardrails;
use super::history::ChatHistory;
use super::tools::{build_tool_schemas, tool_call_to_action};

/// Per-run configuration carved out of RunOpts before the loop starts. Keeps
/// the loop signature small and lets us write unit tests against the parsed
/// shape without going through the option engine.
pub struct AgentConfig {
    pub model: String,
    pub temperature: f32,
    pub max_iterations: u32,
    pub is_subagent: bool,
    pub dangerous: bool,
    /// Depth in the subagent chain (1 for the top-level run, 2+ for subagents
    /// spawned via `run_task ai`). Hard-capped at `MAX_SUBAGENT_DEPTH` so the
    /// LLM can't recurse forever.
    pub ai_depth: u32,
    /// Hard token limit fed into `history.to_messages_within` before each LLM
    /// call. 0 means unlimited (Python parity). Defaults to
    /// `history::DEFAULT_MAX_TOKENS_TOTAL` when unset.
    pub max_tokens_total: usize,
    /// Pricing for the configured model (looked up from litellm-rust's
    /// embedded model registry). `None` when the model isn't in the registry
    /// (custom OpenAI-compat endpoints, self-hosted models) — cost stays
    /// unset on the Ai response in that case.
    pub pricing: Option<ModelPricing>,
    /// PII masking layer. `None` disables masking (operator passed `--no-sensitive`).
    pub encryptor: Option<SensitiveDataEncryptor>,
}

/// Hard cap on `run_task ai` recursion. Python's analogue is `subagent_max`,
/// also defaulting to 2 (top-level + one subagent generation).
pub const MAX_SUBAGENT_DEPTH: u32 = 2;

/// Run the multi-iteration agent loop. The LiteLLM client is built by the
/// caller (so tests can pass a mock-server-backed client).
///
/// History is passed in by `&mut` so the caller can persist the final state to
/// disk for session resume; on return it reflects every assistant + tool
/// message added during the loop.
pub fn run_agent(
    client: &LiteLLM,
    history: &mut ChatHistory,
    mut cfg: AgentConfig,
) -> Vec<OutputItem> {
    let mut out: Vec<OutputItem> = Vec::new();
    let tools = build_tool_schemas(cfg.is_subagent);
    let mut empty_streak = 0u32;
    let mut total_tokens: u64 = 0;

    for iteration in 1..=cfg.max_iterations {
        let mut req = ChatRequest::new(&cfg.model).temperature(cfg.temperature);
        req.messages = if cfg.max_tokens_total > 0 {
            history.to_messages_within(cfg.max_tokens_total)
        } else {
            history.to_messages()
        };
        req.tools = Some(tools.clone());

        let resp = match call_blocking(client, req) {
            Ok(r) => r,
            Err(e) => {
                out.push(OutputItem::Error(Error {
                    message: format!("ai: LLM call failed on iteration {iteration} — {e}"),
                    ..Default::default()
                }));
                return out;
            }
        };

        // Telemetry — collect token totals across the run.
        if let Some(n) = resp.usage.total_tokens {
            total_tokens = total_tokens.saturating_add(n);
        }

        let content = resp.content.clone();
        let tool_calls = resp.tool_calls.clone();
        let has_calls = tool_calls
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);

        // Detect "model returned nothing" — if it streaks for 3 iterations,
        // abort (matches Python's behaviour for non-tool-supporting models).
        if content.is_empty() && !has_calls {
            empty_streak += 1;
            out.push(OutputItem::Warning(Warning {
                message: format!(
                    "ai: LLM returned empty response on iteration {iteration} (streak={empty_streak})"
                ),
                ..Default::default()
            }));
            if empty_streak >= 3 {
                out.push(OutputItem::Error(Error {
                    message: "ai: 3 consecutive empty responses — model may not support tool-calling. Stopping."
                        .into(),
                    ..Default::default()
                }));
                return out;
            }
            continue;
        }
        empty_streak = 0;

        history.add_assistant(&content, tool_calls.clone());

        if !content.is_empty() {
            let mut extra: Map = Map::new();
            extra.insert("iteration".into(), Value::Number(iteration.into()));
            extra.insert("max_iterations".into(), Value::Number(cfg.max_iterations.into()));
            if let Some(n) = resp.usage.total_tokens {
                extra.insert("tokens".into(), Value::Number(n.into()));
            }
            // Cost: prefer the upstream-reported `x-litellm-response-cost`
            // header (LiteLLM-proxied responses set it). Fall back to the
            // model registry — input_tokens * input/1k + output_tokens *
            // output/1k — so direct OpenAI/Anthropic calls still get a price.
            let computed_cost = resp.header_cost.or_else(|| {
                let p = cfg.pricing.as_ref()?;
                let prompt = resp.usage.prompt_tokens.unwrap_or(0) as f64;
                let completion = resp.usage.completion_tokens.unwrap_or(0) as f64;
                let in_cost = p.input_cost_per_1k.unwrap_or(0.0);
                let out_cost = p.output_cost_per_1k.unwrap_or(0.0);
                let total = (prompt / 1000.0) * in_cost + (completion / 1000.0) * out_cost;
                if total > 0.0 { Some(total) } else { None }
            });
            if let Some(cost) = computed_cost {
                if let Some(n) = serde_json::Number::from_f64(cost) {
                    extra.insert("cost".into(), Value::Number(n));
                }
            }
            if let Some(n) = resp.usage.prompt_tokens {
                extra.insert("prompt_tokens".into(), Value::Number(n.into()));
            }
            if let Some(n) = resp.usage.completion_tokens {
                extra.insert("completion_tokens".into(), Value::Number(n.into()));
            }
            // Decrypt for the operator: any [TYPE:hash] placeholders the LLM
            // echoed back get restored to their original PII before display.
            let display_content = match &cfg.encryptor {
                Some(e) => e.decrypt(&content),
                None => content,
            };
            out.push(OutputItem::Ai(Ai {
                content: display_content,
                ai_type: "response".into(),
                model: cfg.model.clone(),
                summary: !has_calls,
                extra_data: extra,
                ..Default::default()
            }));
        }

        // No tool calls → the model is satisfied. Exit cleanly.
        if !has_calls {
            out.push(OutputItem::Info(Info {
                message: format!(
                    "ai: done after {iteration} iteration(s), {total_tokens} total tokens"
                ),
                ..Default::default()
            }));
            return out;
        }

        // Dispatch each tool call. Each gets a `tool` message back to the LLM.
        let mut should_stop = false;
        for call in tool_calls.as_ref().unwrap().as_array().unwrap() {
            let (id, mut action) = match parse_tool_call(call) {
                Some(p) => p,
                None => continue,
            };
            // Decrypt any PII placeholders the LLM echoed into the arguments so
            // we dispatch against real hosts / IPs / emails.
            if let Some(enc) = &cfg.encryptor {
                decrypt_action_fields(&mut action, enc);
            }
            // Guardrails first.
            if let Some(reason) = guardrails::check(&action, cfg.dangerous) {
                out.push(OutputItem::Warning(Warning {
                    message: format!("ai: {reason}"),
                    ..Default::default()
                }));
                history.add_tool_result(id, reason);
                continue;
            }
            let outcome = super::dispatch::dispatch_with_depth(&action, cfg.ai_depth);
            out.extend(outcome.items);
            // Re-encrypt the tool result before feeding it back to the LLM so
            // tool output stays masked too. Stable mappings reuse existing
            // placeholders, so the LLM keeps seeing consistent tokens.
            let tool_msg_for_llm = match cfg.encryptor.as_mut() {
                Some(enc) => enc.encrypt(&outcome.result),
                None => outcome.result.clone(),
            };
            // Cap the per-tool-result size before persisting to history so a
            // noisy single tool can't blow the context window for the rest of
            // the run. Mirrors Python `MAX_ACTION_TOKENS` (10k tokens).
            let capped = ChatHistory::truncate_to_tokens(
                &tool_msg_for_llm,
                super::history::MAX_TOOL_BYTES_IN_HISTORY / super::history::CHARS_PER_TOKEN,
            );
            history.add_tool_result(id, &capped);
            if outcome.stop {
                should_stop = true;
            }
        }
        if should_stop {
            return out;
        }
    }

    out.push(OutputItem::Warning(Warning {
        message: format!(
            "ai: hit max_iterations={} without a stop signal — exiting",
            cfg.max_iterations
        ),
        ..Default::default()
    }));
    out
}

/// Pull `id` + normalized action dict out of one OpenAI-shape tool_call entry.
/// Returns `None` when the call shape is malformed (skip + continue).
fn parse_tool_call(call: &Value) -> Option<(String, Value)> {
    let id = call.get("id").and_then(|v| v.as_str()).unwrap_or("call_unknown").to_string();
    let fname = call.get("function")?.get("name")?.as_str()?.to_string();
    let raw_args = call.get("function")?.get("arguments");
    let args: Value = match raw_args {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Object(Default::default())),
        Some(other) => other.clone(),
        None => Value::Object(Default::default()),
    };
    let action = tool_call_to_action(&fname, &args)?;
    Some((id, action))
}

/// Block the current thread on `client.completion(req)`. We're already in a
/// dedicated runtime thread (`super::run_in_thread` set it up) so a current-
/// thread runtime is fine here.
fn call_blocking(client: &LiteLLM, req: ChatRequest) -> Result<ChatResponse, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio rt build: {e}"))?;
    rt.block_on(client.completion(req)).map_err(|e| e.to_string())
}

/// Walk the normalized action dict and decrypt every string field in place.
/// Numbers, booleans, and the action discriminator itself are left alone.
fn decrypt_action_fields(action: &mut Value, enc: &SensitiveDataEncryptor) {
    match action {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "action" {
                    continue;
                }
                decrypt_action_fields(v, enc);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                decrypt_action_fields(v, enc);
            }
        }
        Value::String(s) => {
            *s = enc.decrypt(s);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_tool_call_decodes_arguments_string() {
        let call = json!({
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "run_task",
                "arguments": "{\"name\":\"nmap\",\"targets\":[\"x\"]}"
            }
        });
        let (id, action) = parse_tool_call(&call).expect("parse");
        assert_eq!(id, "call_1");
        assert_eq!(action["action"], "task");
        assert_eq!(action["name"], "nmap");
    }

    #[test]
    fn parse_tool_call_accepts_object_arguments() {
        let call = json!({
            "id": "call_2",
            "function": {
                "name": "stop",
                "arguments": { "reason": "done" }
            }
        });
        let (_, action) = parse_tool_call(&call).expect("parse");
        assert_eq!(action["action"], "stop");
        assert_eq!(action["reason"], "done");
    }

    #[test]
    fn parse_tool_call_returns_none_for_unknown_function() {
        let call = json!({
            "id": "call_3",
            "function": { "name": "definitely_not_a_tool", "arguments": "{}" }
        });
        assert!(parse_tool_call(&call).is_none());
    }

    #[test]
    fn parse_tool_call_returns_none_for_missing_function() {
        assert!(parse_tool_call(&json!({"id":"x"})).is_none());
    }
}
