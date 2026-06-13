//! Cross-process wire format for the file (and later Redis/NATS) brokers.
//!
//! `serde_json` is the on-disk encoding — debuggable with `cat` and `redis-cli`.
//! Swap to `rmp-serde`/MessagePack later if payload size matters; same serde derives.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A single dispatchable unit of work — Python `run_command` task payload.
///
/// One WorkUnit = one task class run with given inputs/opts, optionally against a
/// pre-allocated reports folder. Workflows (chain/group/chord) expand into multiple
/// WorkUnits orchestrated by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkUnit {
    pub job_id: String,
    pub unit_id: String,
    pub task_class: String,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub opts: BTreeMap<String, String>,
    #[serde(default)]
    pub reports_folder: Option<String>,
    pub submitted_at: f64,
}

/// A frame on the per-job results stream. Workers `append_line` instances of this;
/// the client `tail` reads them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResultEnvelope {
    /// Worker has accepted and started the unit.
    Started { worker_id: String },
    /// A typed `OutputItem` (already converted to its loose-map form).
    Item { value: serde_json::Value },
    /// Worker has finished — terminal frame, client stops tailing on receipt.
    Finished {
        worker_id: String,
        status: String,
        findings: u32,
        errors: u32,
        elapsed_seconds: f64,
    },
    /// Worker hit an internal error (not the same as a tool error — those flow as Item).
    WorkerError { worker_id: String, message: String },
}

/// Out-of-band control signals delivered as small marker files / pubsub messages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMsg {
    Revoke,
}

/// Helper: current Unix time as seconds.
pub fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workunit_roundtrip() {
        let u = WorkUnit {
            job_id: "j".into(),
            unit_id: "u".into(),
            task_class: "httpx".into(),
            inputs: vec!["example.com".into()],
            opts: BTreeMap::from([("threads".into(), "50".into())]),
            reports_folder: Some("/tmp/x".into()),
            submitted_at: 1.0,
        };
        let s = serde_json::to_string(&u).unwrap();
        let back: WorkUnit = serde_json::from_str(&s).unwrap();
        assert_eq!(back.task_class, "httpx");
        assert_eq!(back.opts["threads"], "50");
    }

    #[test]
    fn result_envelope_tagged_variants() {
        let started = ResultEnvelope::Started { worker_id: "w1".into() };
        let s = serde_json::to_string(&started).unwrap();
        assert!(s.contains("\"kind\":\"started\""));
        let finished = ResultEnvelope::Finished {
            worker_id: "w1".into(),
            status: "SUCCESS".into(),
            findings: 1,
            errors: 0,
            elapsed_seconds: 0.5,
        };
        let s = serde_json::to_string(&finished).unwrap();
        let back: ResultEnvelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ResultEnvelope::Finished { findings: 1, .. }));
    }
}
