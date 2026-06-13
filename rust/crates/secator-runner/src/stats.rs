//! Periodic child-process sampler — Python `Command._collect_stats`.
//!
//! Spawns a tokio task that ticks every `stat_update_frequency` seconds, walks
//! the child pid + its descendants via [`sysinfo`], and emits one [`Stat`] per
//! pid through the runner's result channel.

use std::time::Duration;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::interval;

use secator_model::{OutputItem, Stat};

/// Start the sampler. Returns `None` when sampling is disabled (`freq_secs <= 0`).
/// The returned `JoinHandle` should be aborted when the child exits to stop the
/// background poll cleanly.
pub fn spawn_sampler(
    root_pid: u32,
    freq_secs: u64,
    tx: Sender<OutputItem>,
) -> Option<JoinHandle<()>> {
    if freq_secs == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(freq_secs));
        // Skip the first immediate tick — match Python's "first sample after N
        // seconds of actual work" behavior.
        tick.tick().await;
        // System is reused across ticks so per-process CPU% can be computed
        // (sysinfo needs two samples for a delta).
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        loop {
            tick.tick().await;
            sys.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::everything(),
            );
            for stat in sample_tree(&sys, root_pid) {
                if tx.send(OutputItem::Stat(stat)).await.is_err() {
                    return; // receiver dropped → run is winding down.
                }
            }
        }
    }))
}

/// Walk the process tree rooted at `root_pid` and build one [`Stat`] per pid.
/// `sys` must already have its process snapshot refreshed by the caller.
fn sample_tree(sys: &System, root_pid: u32) -> Vec<Stat> {
    let mut out: Vec<Stat> = Vec::new();
    // Collect every pid whose ancestor chain reaches root_pid (depth-first).
    let mut stack: Vec<Pid> = vec![Pid::from_u32(root_pid)];
    let mut visited: Vec<Pid> = Vec::new();
    while let Some(pid) = stack.pop() {
        if visited.contains(&pid) {
            continue;
        }
        visited.push(pid);
        if let Some(proc) = sys.process(pid) {
            let mem_mb = proc.memory() as f64 / 1024.0 / 1024.0;
            out.push(Stat {
                name: proc.name().to_string_lossy().into_owned(),
                pid: pid.as_u32() as i64,
                cpu: proc.cpu_usage() as f64,
                memory: round2(mem_mb),
                memory_limit: 0.0,
                net_conns: None,
                ..Default::default()
            });
            // Enqueue children by scanning sysinfo's process list for matching parent pid.
            for (cpid, cproc) in sys.processes() {
                if cproc.parent() == Some(pid) {
                    stack.push(*cpid);
                }
            }
        }
    }
    out
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_returns_none_when_disabled() {
        // Need a runtime so tokio::spawn doesn't panic during tests that DO
        // start the sampler; this test only exercises the disabled path.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            assert!(spawn_sampler(1, 0, tx).is_none());
        });
    }

    #[test]
    fn sample_tree_finds_current_process() {
        // Sample our own pid — should always be present.
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        let pid = std::process::id();
        let stats = sample_tree(&sys, pid);
        assert!(!stats.is_empty(), "expected at least one stat for our own pid");
        assert!(stats.iter().any(|s| s.pid == pid as i64));
        // Memory should be > 0 for a live process.
        let our_stat = stats.iter().find(|s| s.pid == pid as i64).unwrap();
        assert!(our_stat.memory > 0.0);
    }
}
