//! Cron-style scheduler (Python Celery beat parity, minus the Celery).
//!
//! Reads schedule entries from `~/.secator/schedule.yml` and enqueues tasks /
//! workflows / scans onto a transport (Redis Streams via `secator-redis` by
//! default) at the scheduled times. One `Scheduler::run()` loop is enough — no
//! daemonizing, no background pickle — operators run `secator beat` as a
//! foreground process or a systemd unit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use cron::Schedule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    /// Free-form name used in logs.
    pub name: String,
    /// 6- or 7-field cron expression as accepted by the `cron` crate (Quartz-style:
    /// `sec min hour day-of-month month day-of-week [year]`).
    pub cron: String,
    /// `task`, `workflow`, or `scan`.
    pub kind: String,
    /// Name of the task / workflow / scan template to invoke.
    pub template: String,
    /// Initial inputs (targets).
    #[serde(default)]
    pub inputs: Vec<String>,
    /// Initial run-time options (k=v strings, matching `runner.opts`).
    #[serde(default)]
    pub opts: BTreeMap<String, String>,
    /// Per-entry enable flag — set false to mute an entry without deleting it.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

/// On-disk schedule file shape.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScheduleFile {
    #[serde(default)]
    pub entries: Vec<ScheduleEntry>,
}

impl ScheduleFile {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(ScheduleFile::default());
        }
        let body = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&body).unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_yaml::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, body)
    }
}

/// Default schedule file location — `~/.secator/schedule.yml`.
pub fn default_schedule_path() -> PathBuf {
    secator_config::user_config_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("schedule.yml")
}

/// Compute the next fire time after `from` for `cron_expr`. Returns `None` for
/// unparseable expressions or schedules that have no future occurrence.
pub fn next_fire(cron_expr: &str, from: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let s = Schedule::from_str(cron_expr).ok()?;
    s.after(&from).next()
}

/// One step of the scheduler: walk entries, find those whose `next_fire` falls
/// within `[last_tick, now]`, and return the indices that should fire NOW.
pub fn due_indices(
    entries: &[ScheduleEntry],
    last_tick: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if !e.enabled {
            continue;
        }
        // Find next fire AFTER last_tick. If it falls before/at now, this entry is due.
        if let Some(t) = next_fire(&e.cron, last_tick) {
            if t <= now {
                out.push(i);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn next_fire_resolves_known_cron() {
        // Every minute at second 0.
        let from = Utc.with_ymd_and_hms(2026, 6, 12, 12, 0, 0).unwrap();
        let next = next_fire("0 * * * * *", from).unwrap();
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 6, 12, 12, 1, 0).unwrap());
    }

    #[test]
    fn due_indices_reports_only_in_window() {
        let entries = vec![
            ScheduleEntry {
                name: "minute".into(),
                cron: "0 * * * * *".into(),
                kind: "task".into(),
                template: "subfinder".into(),
                inputs: vec!["example.com".into()],
                opts: Default::default(),
                enabled: true,
            },
            ScheduleEntry {
                name: "hourly".into(),
                cron: "0 0 * * * *".into(),
                kind: "task".into(),
                template: "httpx".into(),
                inputs: vec!["example.com".into()],
                opts: Default::default(),
                enabled: true,
            },
        ];
        // Tick window is 12:00:30 → 12:01:30. Only "minute" (fires at 12:01:00) is due.
        let last = Utc.with_ymd_and_hms(2026, 6, 12, 12, 0, 30).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 6, 12, 12, 1, 30).unwrap();
        let due = due_indices(&entries, last, now);
        assert_eq!(due, vec![0]);
    }

    #[test]
    fn disabled_entries_skipped() {
        let entries = vec![ScheduleEntry {
            name: "muted".into(),
            cron: "* * * * * *".into(), // every second
            kind: "task".into(),
            template: "noop".into(),
            inputs: vec![],
            opts: Default::default(),
            enabled: false,
        }];
        let last = Utc.with_ymd_and_hms(2026, 6, 12, 12, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 6, 12, 12, 0, 5).unwrap();
        assert!(due_indices(&entries, last, now).is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let tmp = std::env::temp_dir().join(format!("secator-beat-{}.yml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let sf = ScheduleFile {
            entries: vec![ScheduleEntry {
                name: "nightly".into(),
                cron: "0 0 2 * * *".into(),
                kind: "workflow".into(),
                template: "subdomain_enum".into(),
                inputs: vec!["example.com".into()],
                opts: Default::default(),
                enabled: true,
            }],
        };
        sf.save(&tmp).unwrap();
        let back = ScheduleFile::load(&tmp).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].cron, "0 0 2 * * *");
        let _ = std::fs::remove_file(&tmp);
    }
}
