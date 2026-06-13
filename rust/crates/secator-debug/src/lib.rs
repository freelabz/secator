//! Channel-scoped debug logging (Python `secator.utils.debug`).
//!
//! Operators flip on debug streams via the `SECATOR_DEBUG` env var:
//!
//! ```bash
//! SECATOR_DEBUG=all       # everything
//! SECATOR_DEBUG=1         # everything (same as 'all', '*')
//! SECATOR_DEBUG=start,end # only sub-channels start/end
//! SECATOR_DEBUG=init      # init AND init.options AND init.* (prefix match)
//! SECATOR_DEBUG=hooks.*   # glob match
//! ```
//!
//! Use [`debug!`] from any crate. It expands to a single `if enabled_for(sub)` check
//! plus an `eprintln!` so the cost when disabled is one env-cached read.

use std::sync::OnceLock;

/// Parsed `SECATOR_DEBUG` config. Cached once per process.
#[derive(Debug, Clone)]
pub struct DebugConfig {
    /// Wildcard short-circuit (`all`, `1`, `*`).
    pub all: bool,
    /// User-specified sub-channel filters.
    pub subs: Vec<String>,
}

impl DebugConfig {
    /// Match a sub-channel against the configured filters. `verbose=true` requires
    /// exact match; `verbose=false` allows prefix match (`init` matches `init.options`).
    pub fn enabled(&self, sub: &str, verbose: bool) -> bool {
        if self.all {
            return true;
        }
        if sub.is_empty() {
            return !self.subs.is_empty();
        }
        for s in &self.subs {
            if s.contains('*') {
                if glob_match(s, sub) {
                    return true;
                }
            } else if verbose {
                if sub == s {
                    return true;
                }
            } else if sub.starts_with(s.as_str()) {
                return true;
            }
        }
        false
    }
}

/// Mini glob — `*` is the only wildcard. Anchored at both ends (Python `re.match(s + '$', sub)`).
fn glob_match(pattern: &str, candidate: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return parts[0] == candidate;
    }
    // First part must match at the start.
    let mut pos = 0;
    if !candidate.starts_with(parts[0]) {
        return false;
    }
    pos += parts[0].len();
    // Middle parts must occur in order.
    for part in &parts[1..parts.len() - 1] {
        match candidate[pos..].find(part) {
            Some(i) => pos += i + part.len(),
            None => return false,
        }
    }
    // Last part must align at the end.
    let last = parts[parts.len() - 1];
    candidate[pos..].ends_with(last) && candidate[pos..].len() >= last.len()
}

/// Process-wide raw debug spec, set by [`init`]. When unset (or `init` was
/// never called), `read_config` falls back to the `SECATOR_DEBUG` env var.
static RAW_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Seed the debug spec from a source other than env (typically
/// `CONFIG.debug` loaded at startup). MUST be called before any `enabled()`
/// or `debug!()` call; once `config()` has materialized, further calls are
/// no-ops (OnceLock semantics). Empty `raw` leaves the env fallback intact.
pub fn init(raw: &str) {
    if !raw.trim().is_empty() {
        let _ = RAW_OVERRIDE.set(raw.to_string());
    }
}

fn read_config() -> DebugConfig {
    let raw = RAW_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::var("SECATOR_DEBUG").unwrap_or_default());
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DebugConfig { all: false, subs: Vec::new() };
    }
    if matches!(trimmed, "all" | "1" | "*") {
        return DebugConfig { all: true, subs: Vec::new() };
    }
    let subs = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    DebugConfig { all: false, subs }
}

/// Return the cached debug config (reads the [`init`] override or
/// `SECATOR_DEBUG` env once).
pub fn config() -> &'static DebugConfig {
    static C: OnceLock<DebugConfig> = OnceLock::new();
    C.get_or_init(read_config)
}

/// Cheap enable check — `false` ⇒ skip the formatting/logging entirely.
pub fn enabled(sub: &str) -> bool {
    config().enabled(sub, false)
}

pub fn enabled_verbose(sub: &str) -> bool {
    config().enabled(sub, true)
}

/// Emit a debug line to stderr. Use the [`debug!`] macro instead in normal code —
/// this is the inner that the macro expands to.
pub fn emit(sub: &str, msg: &str) {
    if sub.is_empty() {
        eprintln!("[DBG] {msg}");
    } else {
        eprintln!("[DBG] {sub:13} {msg}");
    }
}

/// `debug!("start", "spawned subprocess pid={pid}")` — emit if `start` is enabled.
#[macro_export]
macro_rules! debug {
    ($sub:expr, $($arg:tt)*) => {{
        if $crate::enabled($sub) {
            $crate::emit($sub, &format!($($arg)*));
        }
    }};
}

/// Verbose variant — requires exact match (Python `verbose=True`).
#[macro_export]
macro_rules! debug_verbose {
    ($sub:expr, $($arg:tt)*) => {{
        if $crate::enabled_verbose($sub) {
            $crate::emit($sub, &format!($($arg)*));
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_disables_all() {
        let c = DebugConfig { all: false, subs: vec![] };
        assert!(!c.enabled("start", false));
        assert!(!c.enabled("anything", false));
    }

    #[test]
    fn all_enables_everything() {
        let c = DebugConfig { all: true, subs: vec![] };
        assert!(c.enabled("start", false));
        assert!(c.enabled("hooks.mongodb", false));
    }

    #[test]
    fn prefix_match_non_verbose() {
        let c = DebugConfig { all: false, subs: vec!["init".into()] };
        assert!(c.enabled("init", false));
        assert!(c.enabled("init.options", false));
        assert!(!c.enabled("start", false));
    }

    #[test]
    fn verbose_requires_exact() {
        let c = DebugConfig { all: false, subs: vec!["init".into()] };
        assert!(c.enabled("init", true));
        assert!(!c.enabled("init.options", true));
    }

    #[test]
    fn glob_wildcard_matches() {
        let c = DebugConfig { all: false, subs: vec!["hooks.*".into()] };
        assert!(c.enabled("hooks.mongodb", false));
        assert!(c.enabled("hooks.api", false));
        assert!(!c.enabled("start", false));
    }

    #[test]
    fn multiple_subs_or_match() {
        let c = DebugConfig { all: false, subs: vec!["start".into(), "end".into()] };
        assert!(c.enabled("start", false));
        assert!(c.enabled("end", false));
        assert!(!c.enabled("monitor", false));
    }

    #[test]
    fn glob_match_helper() {
        assert!(glob_match("hooks.*", "hooks.mongodb"));
        assert!(glob_match("*.mongo", "x.mongo"));
        assert!(!glob_match("hooks.*", "hookz.x"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact2"));
    }

    /// P3.4: `init("hooks.*,start")` directly parses the spec without
    /// touching the OnceLock cache (so we can test the same parser the
    /// `init()` override path feeds).
    #[test]
    fn read_config_parses_subs() {
        // Drive the parser via env to dodge OnceLock state from other tests.
        std::env::set_var("SECATOR_DEBUG", "hooks.*,start");
        let c = read_config();
        std::env::remove_var("SECATOR_DEBUG");
        assert!(!c.all);
        assert_eq!(c.subs, vec!["hooks.*".to_string(), "start".into()]);
        assert!(c.enabled("hooks.mongodb", false));
        assert!(c.enabled("start", false));
        assert!(!c.enabled("end", false));
    }
}
