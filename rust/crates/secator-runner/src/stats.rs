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
#[allow(dead_code)]
pub fn spawn_sampler(
    root_pid: u32,
    freq_secs: u64,
    tx: Sender<OutputItem>,
) -> Option<JoinHandle<()>> {
    spawn_sampler_with_limit(root_pid, freq_secs, None, tx)
}

/// Same as [`spawn_sampler`] plus an enforced RSS ceiling. When the process
/// tree's total memory crosses `mem_limit_mb`, the sampler emits an
/// `OutputItem::Error` describing the breach and calls `Process::kill()` on
/// the root pid. The subprocess dies → its stdout closes → the runner's read
/// loop returns naturally → `process_unit` reports `status=FAILURE`.
///
/// At least ONE periodic tick is needed for the kill check to fire, so we
/// force-enable a 1-second poll when only the memory limit is set (without
/// stat reporting).
pub fn spawn_sampler_with_limit(
    root_pid: u32,
    freq_secs: u64,
    mem_limit_mb: Option<u64>,
    tx: Sender<OutputItem>,
) -> Option<JoinHandle<()>> {
    // If no stat emission AND no memory limit, there's nothing to do.
    if freq_secs == 0 && mem_limit_mb.is_none() {
        return None;
    }
    // Pick a cadence: when only the limit is set, poll every second; otherwise
    // honor the operator's `stat_update_frequency`.
    let emit_stats = freq_secs > 0;
    let tick_secs = if emit_stats { freq_secs } else { 1 };
    Some(tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(tick_secs));
        tick.tick().await;
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
            let stats = sample_tree(&sys, root_pid);
            // Memory-limit check BEFORE emitting stats so the operator sees
            // the breach + kill notice as a final group, not after one more
            // stat tick that would race the subprocess teardown.
            if let Some(limit_mb) = mem_limit_mb {
                let total_mb: f64 = stats.iter().map(|s| s.memory).sum();
                if total_mb > limit_mb as f64 {
                    let msg = format!(
                        "task killed: subprocess tree RSS {total_mb:.0} MiB \
                         exceeded transport.task_memory_limit_mb={limit_mb}"
                    );
                    let _ = tx
                        .send(OutputItem::Error(secator_model::Error {
                            message: msg,
                            ..Default::default()
                        }))
                        .await;
                    kill_process_tree(&sys, root_pid);
                    return;
                }
            }
            if emit_stats {
                for stat in stats {
                    if tx.send(OutputItem::Stat(stat)).await.is_err() {
                        return; // receiver dropped → run is winding down.
                    }
                }
            }
        }
    }))
}

/// SIGTERM every pid in the subprocess tree, then SIGKILL the root. The
/// runner has `kill_on_drop(true)` so dropping the Child also kills it, but
/// when we trip the memory limit the runner future is still alive (waiting
/// on stdout); this nudges the kernel to tear it down promptly.
fn kill_process_tree(sys: &System, root_pid: u32) {
    let mut stack: Vec<Pid> = vec![Pid::from_u32(root_pid)];
    let mut visited: Vec<Pid> = Vec::new();
    while let Some(pid) = stack.pop() {
        if visited.contains(&pid) {
            continue;
        }
        visited.push(pid);
        if let Some(proc) = sys.process(pid) {
            let _ = proc.kill();
            for (cpid, cproc) in sys.processes() {
                if cproc.parent() == Some(pid) {
                    stack.push(*cpid);
                }
            }
        }
    }
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

    /// #171 T2: when the limit is set absurdly low (1 MB) and the subprocess
    /// is anything heavier than that (e.g. `sleep`, which RSS-ses ~1-2 MB on
    /// linux), the sampler:
    ///   1. sends an `OutputItem::Error` describing the breach
    ///   2. kills the subprocess tree via sysinfo
    /// The test verifies the Error envelope reaches the channel; we don't
    /// also assert the pid is gone because the kill is observable through
    /// the Drop-on-runner path in real use (covered by the runner's
    /// integration tests, not here).
    #[test]
    fn memory_limit_breach_emits_error() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Spawn a long-running shell so the sampler has a live pid to
            // measure. `sleep 30` is enough; the sampler has a 1-second poll
            // cadence when only the memory limit is set.
            let child = tokio::process::Command::new("sh")
                .arg("-c")
                .arg("sleep 30")
                .kill_on_drop(true)
                .spawn()
                .expect("spawn sleep");
            let pid = child.id().expect("child pid");

            let (tx, mut rx) = tokio::sync::mpsc::channel::<OutputItem>(16);
            // Limit = 1 MiB. `sleep` RSS is comfortably above that.
            let handle =
                spawn_sampler_with_limit(pid, 0, Some(1), tx).expect("sampler spawned");

            // Wait up to 5 s for the Error item to arrive (sampler polls once
            // per second; first tick is consumed before any measurement).
            let item = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("timed out waiting for breach")
                .expect("channel closed before breach");
            match item {
                OutputItem::Error(e) => {
                    assert!(e.message.contains("task_memory_limit_mb"));
                    assert!(e.message.contains("killed"));
                }
                other => panic!("expected Error item, got {other:?}"),
            }
            // Cleanup — sampler returns after the kill so handle.await ends.
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        });
    }
}
