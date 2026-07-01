//! Minimal FreeProxy-equivalent — fetches a random anonymous HTTP proxy from
//! a public list and verifies it before returning. Python parity with
//! `--proxy random` (which uses `from fp.fp import FreeProxy`).
//!
//! Source: <https://api.proxyscrape.com/v2/?request=getproxies&protocol=http>
//! returns a plain-text `ip:port` list, one per line — no HTML parsing
//! needed. We pick a small random sample, ping each via an HTTP-over-HTTP
//! probe against `https://www.google.com`, and return the first that
//! responds within `timeout` seconds.
//!
//! This is intentionally best-effort: free proxy lists are noisy and most
//! entries are dead. Callers fall back to dropping the proxy opt when this
//! returns `None`.
//!
//! Network calls are blocking and run inside `configure_proxy` which is the
//! one place we accept the latency cost (proxy is opt-in, off the hot path
//! for the common no-proxy case).

use std::time::Duration;

use rand::seq::SliceRandom;
use reqwest::blocking::Client;

const PROXY_LIST_URL: &str =
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=anonymous";

/// Fetch the proxy list, shuffle, probe up to `MAX_CANDIDATES` entries, return
/// the first live `http://ip:port` URL. `timeout_secs` caps each probe; the
/// outer fetch shares the same budget. Returns `None` on any failure — caller
/// is expected to fall back to dropping the proxy opt.
pub fn random_proxy(timeout_secs: u64) -> Option<String> {
    const MAX_CANDIDATES: usize = 8;
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let client = Client::builder().timeout(timeout).build().ok()?;
    let body = client.get(PROXY_LIST_URL).send().ok()?.text().ok()?;

    let mut entries: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.contains(':'))
        .map(|l| format!("http://{l}"))
        .collect();
    if entries.is_empty() {
        return None;
    }
    entries.shuffle(&mut rand::thread_rng());

    for candidate in entries.iter().take(MAX_CANDIDATES) {
        if probe_proxy(candidate, timeout) {
            return Some(candidate.clone());
        }
    }
    None
}

fn probe_proxy(url: &str, timeout: Duration) -> bool {
    let Ok(proxy) = reqwest::Proxy::all(url) else {
        return false;
    };
    let Ok(client) = Client::builder().proxy(proxy).timeout(timeout).build() else {
        return false;
    };
    client
        .get("https://www.google.com/generate_204")
        .send()
        .map(|r| r.status().is_success() || r.status().as_u16() == 204)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// We can't hit the network in unit tests reliably — assert the function
    /// returns `None` quickly with a tiny timeout when offline (the real
    /// caller treats `None` as "drop the proxy opt" anyway).
    #[test]
    fn random_proxy_returns_option() {
        // 1-second budget. Either we get a proxy (online CI) or None
        // (offline / blocked). Both are fine — we just check it doesn't panic.
        let _ = random_proxy(1);
    }

    /// Probe must reject obviously-bogus URLs without panicking.
    #[test]
    fn probe_returns_false_for_invalid_proxy() {
        assert!(!probe_proxy("not a url", Duration::from_millis(50)));
        assert!(!probe_proxy("http://127.0.0.1:1", Duration::from_millis(200)));
    }
}
