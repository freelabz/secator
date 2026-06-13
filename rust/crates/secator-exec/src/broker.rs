//! File-based broker primitives.
//!
//! Zero-infra default — same role as Python Celery's `filesystem://` broker. The
//! layout under `<base>/` (default `<CONFIG.dirs.celery_data>`):
//!
//! ```text
//! tasks/                  — pending WorkUnits (one JSON file per unit)
//! claimed/<worker_id>/    — units in-flight (atomic-renamed from tasks/)
//! results/<job_id>.jsonl  — append-only result streams (one line = ResultEnvelope)
//! control/<job_id>.revoke — out-of-band revoke marker
//! workers/<worker_id>     — empty file whose mtime is the heartbeat
//! ```
//!
//! All "claim" and "publish" operations use the atomic-rename trick (write to a
//! `.tmp.<rand>` sibling, then `rename` — POSIX guarantees atomicity within a fs).
//! Tails use a byte cursor — restart-safe.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::wire::{ControlMsg, ResultEnvelope, WorkUnit};

/// Heartbeat TTL: a worker is "alive" if its sentinel mtime is newer than this.
pub const HEARTBEAT_TTL: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum BrokerError {
    Io(String),
    Encode(String),
    Decode(String),
}
impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Io(s) => write!(f, "broker io: {s}"),
            BrokerError::Encode(s) => write!(f, "broker encode: {s}"),
            BrokerError::Decode(s) => write!(f, "broker decode: {s}"),
        }
    }
}
impl std::error::Error for BrokerError {}
impl From<std::io::Error> for BrokerError {
    fn from(e: std::io::Error) -> Self { BrokerError::Io(e.to_string()) }
}
impl From<serde_json::Error> for BrokerError {
    fn from(e: serde_json::Error) -> Self { BrokerError::Encode(e.to_string()) }
}

/// File broker rooted at `base/` — the only stateful object the client and worker share.
#[derive(Debug, Clone)]
pub struct FileBroker {
    pub base: PathBuf,
}

impl FileBroker {
    pub fn new(base: impl Into<PathBuf>) -> std::io::Result<Self> {
        let base = base.into();
        for sub in ["tasks", "claimed", "results", "control", "workers"] {
            std::fs::create_dir_all(base.join(sub))?;
        }
        Ok(FileBroker { base })
    }

    pub fn tasks_dir(&self) -> PathBuf { self.base.join("tasks") }
    pub fn claimed_dir(&self, worker_id: &str) -> PathBuf {
        self.base.join("claimed").join(sanitize(worker_id))
    }
    pub fn results_path(&self, job_id: &str) -> PathBuf {
        self.base.join("results").join(format!("{}.jsonl", sanitize(job_id)))
    }
    pub fn control_path(&self, job_id: &str, signal: &str) -> PathBuf {
        self.base.join("control").join(format!("{}.{}", sanitize(job_id), signal))
    }
    pub fn worker_path(&self, worker_id: &str) -> PathBuf {
        self.base.join("workers").join(sanitize(worker_id))
    }
    pub fn workers_dir(&self) -> PathBuf { self.base.join("workers") }

    // ------------------------------------------------------------- Queue

    /// Publish a `WorkUnit` to the tasks queue. Atomic via write-then-rename.
    pub fn enqueue(&self, unit: &WorkUnit) -> Result<PathBuf, BrokerError> {
        let dir = self.tasks_dir();
        std::fs::create_dir_all(&dir)?;
        let final_path = dir.join(format!("{}.json", unit.unit_id));
        atomic_write_json(&final_path, unit)?;
        Ok(final_path)
    }

    /// List pending task files (sorted lexicographically, FIFO by `submitted_at`
    /// when ids are time-ordered).
    pub fn list_pending(&self) -> Result<Vec<PathBuf>, BrokerError> {
        let mut out = Vec::new();
        let dir = self.tasks_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(".tmp.") || !name_str.ends_with(".json") {
                continue;
            }
            out.push(entry.path());
        }
        out.sort();
        Ok(out)
    }

    /// Atomically claim a pending task by renaming `tasks/<id>.json` →
    /// `claimed/<worker>/<id>.json`. Returns `Ok(None)` if another worker beat us.
    pub fn claim(
        &self,
        path: &Path,
        worker_id: &str,
    ) -> Result<Option<(PathBuf, WorkUnit)>, BrokerError> {
        let claimed_dir = self.claimed_dir(worker_id);
        std::fs::create_dir_all(&claimed_dir)?;
        let target = claimed_dir.join(path.file_name().unwrap_or_default());
        // POSIX rename is atomic; on Windows it returns AlreadyExists for the lost race.
        match std::fs::rename(path, &target) {
            Ok(()) => {
                let unit = read_json::<WorkUnit>(&target)?;
                Ok(Some((target, unit)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BrokerError::Io(e.to_string())),
        }
    }

    /// Remove a claimed task file once processing is fully done.
    pub fn ack(&self, claimed_path: &Path) -> Result<(), BrokerError> {
        std::fs::remove_file(claimed_path)?;
        Ok(())
    }

    // ----------------------------------------------------- Results stream

    /// Append a single envelope to `results/<job_id>.jsonl`. One short line = atomic
    /// on POSIX when below PIPE_BUF (4 KiB); larger payloads may interleave with
    /// concurrent writers — fine in practice because there is ONE worker per job.
    pub fn append_result(
        &self,
        job_id: &str,
        envelope: &ResultEnvelope,
    ) -> Result<(), BrokerError> {
        let path = self.results_path(job_id);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut line = serde_json::to_vec(envelope)?;
        line.push(b'\n');
        f.write_all(&line)?;
        Ok(())
    }

    /// Open a cursor-based tail over the job's results stream. The cursor remembers
    /// the byte offset, so a restarted client can pick up where it left off.
    pub fn tail_results(&self, job_id: &str) -> ResultTail {
        ResultTail {
            path: self.results_path(job_id),
            cursor: 0,
            pending_partial: Vec::new(),
        }
    }

    // ------------------------------------------------------------- Control

    pub fn publish_control(&self, job_id: &str, msg: ControlMsg) -> Result<(), BrokerError> {
        let signal = match msg {
            ControlMsg::Revoke => "revoke",
        };
        let path = self.control_path(job_id, signal);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, b"")?;
        Ok(())
    }

    pub fn control_pending(&self, job_id: &str) -> Option<ControlMsg> {
        if self.control_path(job_id, "revoke").exists() {
            return Some(ControlMsg::Revoke);
        }
        None
    }

    pub fn ack_control(&self, job_id: &str, msg: ControlMsg) {
        let signal = match msg {
            ControlMsg::Revoke => "revoke",
        };
        let _ = std::fs::remove_file(self.control_path(job_id, signal));
    }

    // ----------------------------------------------------------- Heartbeat

    pub fn heartbeat(&self, worker_id: &str) -> Result<(), BrokerError> {
        let path = self.worker_path(worker_id);
        std::fs::create_dir_all(path.parent().unwrap())?;
        // Definitively bump mtime: a zero-byte rewrite via `fs::write` truncates and
        // sets mtime. `OpenOptions::open(.write(true))` alone doesn't on filesystems
        // that lazily update mtime — write_at-zero is the portable touch.
        std::fs::write(&path, b"")?;
        Ok(())
    }

    /// Returns the ids of any worker whose heartbeat is fresher than the TTL.
    pub fn live_workers(&self) -> Vec<String> {
        let dir = self.workers_dir();
        let mut out = Vec::new();
        let now = SystemTime::now();
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => return out,
        };
        for entry in read.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(mtime) = meta.modified() else { continue };
            let fresh = now.duration_since(mtime).map(|d| d < HEARTBEAT_TTL).unwrap_or(true);
            if fresh {
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_string());
                }
            }
        }
        out
    }

    /// Convenience: is at least one worker heartbeating? (Python `is_celery_worker_alive`.)
    pub fn worker_alive(&self) -> bool {
        !self.live_workers().is_empty()
    }
}

/// Tail iterator over a JSONL results stream — cursor-based so reconnects don't lose
/// data. `poll()` returns the next envelope or `None` if EOF (the caller sleeps).
pub struct ResultTail {
    path: PathBuf,
    cursor: u64,
    /// Buffer for an incomplete trailing line (writer hadn't finished when we read).
    pending_partial: Vec<u8>,
}
impl ResultTail {
    pub fn path(&self) -> &Path { &self.path }

    /// Return all envelopes newly appended since the last call.
    pub fn poll(&mut self) -> Result<Vec<ResultEnvelope>, BrokerError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.cursor))?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf)?;
        let mut data = std::mem::take(&mut self.pending_partial);
        data.extend_from_slice(&buf);
        self.cursor += buf.len() as u64;

        let mut out = Vec::new();
        let mut start = 0usize;
        let mut last_newline = None;
        for (i, &b) in data.iter().enumerate() {
            if b == b'\n' {
                let line = &data[start..i];
                if !line.is_empty() {
                    let env: ResultEnvelope = serde_json::from_slice(line)
                        .map_err(|e| BrokerError::Decode(e.to_string()))?;
                    out.push(env);
                }
                start = i + 1;
                last_newline = Some(i);
            }
        }
        // Stash anything after the last newline (incomplete line).
        if let Some(nl) = last_newline {
            self.pending_partial = data[(nl + 1)..].to_vec();
        } else {
            self.pending_partial = data;
        }
        Ok(out)
    }
}

// ----------------------------------------------------------------- helpers

fn atomic_write_json<T: serde::Serialize>(final_path: &Path, value: &T) -> Result<(), BrokerError> {
    let parent = final_path.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(".tmp.{}.{}", Uuid::new_v4(), final_path.file_name().unwrap().to_string_lossy()));
    {
        let mut f = File::create(&tmp)?;
        let bytes = serde_json::to_vec_pretty(value)?;
        f.write_all(&bytes)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, final_path)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, BrokerError> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes).map_err(|e| BrokerError::Decode(e.to_string()))?)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("secator-broker-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn unit(job: &str) -> WorkUnit {
        WorkUnit {
            job_id: job.into(),
            unit_id: Uuid::new_v4().to_string(),
            task_class: "fake".into(),
            inputs: vec!["a.com".into()],
            opts: Default::default(),
            reports_folder: None,
            submitted_at: crate::wire::now_secs(),
        }
    }

    #[test]
    fn enqueue_then_list_and_claim() {
        let b = FileBroker::new(tmp("enqueue")).unwrap();
        let u = unit("j1");
        b.enqueue(&u).unwrap();
        let pending = b.list_pending().unwrap();
        assert_eq!(pending.len(), 1);
        let claimed = b.claim(&pending[0], "w1").unwrap().unwrap();
        assert_eq!(claimed.1.task_class, "fake");
        // Now empty.
        assert!(b.list_pending().unwrap().is_empty());
        b.ack(&claimed.0).unwrap();
        let _ = std::fs::remove_dir_all(&b.base);
    }

    #[test]
    fn claim_race_only_one_winner() {
        let b = FileBroker::new(tmp("race")).unwrap();
        let u = unit("j2");
        b.enqueue(&u).unwrap();
        let pending = b.list_pending().unwrap();
        let first = b.claim(&pending[0], "w1").unwrap();
        let second = b.claim(&pending[0], "w2").unwrap();
        assert!(first.is_some(), "first claim should succeed");
        assert!(second.is_none(), "second claim must lose the race");
        let _ = std::fs::remove_dir_all(&b.base);
    }

    #[test]
    fn append_and_tail_results() {
        let b = FileBroker::new(tmp("results")).unwrap();
        b.append_result("j3", &ResultEnvelope::Started { worker_id: "w1".into() }).unwrap();
        b.append_result("j3", &ResultEnvelope::Item {
            value: serde_json::json!({"_type": "url", "url": "https://x"}),
        }).unwrap();
        let mut tail = b.tail_results("j3");
        let frames = tail.poll().unwrap();
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0], ResultEnvelope::Started { .. }));
        assert!(matches!(frames[1], ResultEnvelope::Item { .. }));
        // Subsequent polls return nothing until new lines appear.
        assert!(tail.poll().unwrap().is_empty());
        // Append more, cursor advances.
        b.append_result("j3", &ResultEnvelope::Finished {
            worker_id: "w1".into(),
            status: "SUCCESS".into(),
            findings: 1,
            errors: 0,
            elapsed_seconds: 0.0,
        }).unwrap();
        let frames = tail.poll().unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], ResultEnvelope::Finished { .. }));
        let _ = std::fs::remove_dir_all(&b.base);
    }

    #[test]
    fn worker_heartbeat_then_alive() {
        let b = FileBroker::new(tmp("hb")).unwrap();
        assert!(!b.worker_alive(), "no workers yet");
        b.heartbeat("worker-1").unwrap();
        assert!(b.worker_alive());
        let live = b.live_workers();
        assert_eq!(live, vec!["worker-1".to_string()]);
        let _ = std::fs::remove_dir_all(&b.base);
    }

    #[test]
    fn control_revoke_round_trip() {
        let b = FileBroker::new(tmp("ctrl")).unwrap();
        assert!(b.control_pending("j4").is_none());
        b.publish_control("j4", ControlMsg::Revoke).unwrap();
        assert!(matches!(b.control_pending("j4"), Some(ControlMsg::Revoke)));
        b.ack_control("j4", ControlMsg::Revoke);
        assert!(b.control_pending("j4").is_none());
        let _ = std::fs::remove_dir_all(&b.base);
    }
}
