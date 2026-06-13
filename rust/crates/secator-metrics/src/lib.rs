//! Prometheus-format metrics endpoint — Python parity follow-up.
//!
//! Exposes counters/histograms over a plain `GET /metrics` HTTP/1.1 endpoint
//! that any Prometheus scraper / curl can hit. The data shape mirrors the
//! design in `sprint-4-deferred.md`:
//!   * `secator_tasks_total{class,status}` — counter
//!   * `secator_task_seconds_sum{class}` / `secator_task_seconds_count{class}`
//!     — task runtime accumulator (Prom-style `_sum` + `_count` summary pair)
//!   * `secator_findings_total{type}` — counter
//!   * `secator_errors_total` — counter
//!
//! We hand-roll the text rendering + HTTP loop to avoid pulling in axum +
//! prometheus crates for what is fundamentally `println!` + a one-route server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// In-memory metric registry. All operations are atomic + lock-cheap; the
/// `Arc<Self>` is meant to be cloned freely across worker tasks.
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// `(class, status)` → count.
    tasks_total: HashMap<(String, String), u64>,
    /// `class` → (sum of seconds, observation count). Prom-style summary.
    task_seconds: HashMap<String, (f64, u64)>,
    /// `type` → count.
    findings_total: HashMap<String, u64>,
    /// Cumulative error count across all tasks.
    errors_total: u64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(Inner::default()) })
    }

    /// Mark a task as having completed with the given status.
    pub fn inc_task(&self, class: &str, status: &str) {
        if let Ok(mut g) = self.inner.lock() {
            *g.tasks_total
                .entry((class.to_string(), status.to_string()))
                .or_insert(0) += 1;
        }
    }

    /// Record one task's runtime (seconds). Updates both the sum + count
    /// halves of the summary.
    pub fn observe_task_seconds(&self, class: &str, secs: f64) {
        if !secs.is_finite() || secs < 0.0 {
            return;
        }
        if let Ok(mut g) = self.inner.lock() {
            let entry = g.task_seconds.entry(class.to_string()).or_insert((0.0, 0));
            entry.0 += secs;
            entry.1 += 1;
        }
    }

    /// Increment the per-finding-type counter.
    pub fn inc_finding(&self, ty: &str) {
        if let Ok(mut g) = self.inner.lock() {
            *g.findings_total.entry(ty.to_string()).or_insert(0) += 1;
        }
    }

    /// Bulk-increment the per-finding-type counter — useful at end-of-task when
    /// you only have aggregate counts from the worker streamer.
    pub fn inc_findings_by(&self, ty: &str, n: u64) {
        if n == 0 {
            return;
        }
        if let Ok(mut g) = self.inner.lock() {
            *g.findings_total.entry(ty.to_string()).or_insert(0) += n;
        }
    }

    pub fn inc_errors(&self, n: u64) {
        if n == 0 {
            return;
        }
        if let Ok(mut g) = self.inner.lock() {
            g.errors_total = g.errors_total.saturating_add(n);
        }
    }

    /// Render the current snapshot in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let Ok(g) = self.inner.lock() else {
            return String::new();
        };
        let mut out = String::new();

        out.push_str("# HELP secator_tasks_total Tasks completed, by class and final status.\n");
        out.push_str("# TYPE secator_tasks_total counter\n");
        // Sort keys for stable scraping output.
        let mut tasks: Vec<(&(String, String), &u64)> = g.tasks_total.iter().collect();
        tasks.sort_by(|a, b| a.0.cmp(b.0));
        for ((class, status), v) in tasks {
            out.push_str(&format!(
                "secator_tasks_total{{class=\"{}\",status=\"{}\"}} {v}\n",
                escape(class),
                escape(status)
            ));
        }

        out.push_str("# HELP secator_task_seconds Per-task runtime in seconds.\n");
        out.push_str("# TYPE secator_task_seconds summary\n");
        let mut secs: Vec<(&String, &(f64, u64))> = g.task_seconds.iter().collect();
        secs.sort_by(|a, b| a.0.cmp(b.0));
        for (class, (sum, count)) in secs {
            out.push_str(&format!(
                "secator_task_seconds_sum{{class=\"{}\"}} {sum}\n",
                escape(class)
            ));
            out.push_str(&format!(
                "secator_task_seconds_count{{class=\"{}\"}} {count}\n",
                escape(class)
            ));
        }

        out.push_str("# HELP secator_findings_total Findings emitted by output type.\n");
        out.push_str("# TYPE secator_findings_total counter\n");
        let mut findings: Vec<(&String, &u64)> = g.findings_total.iter().collect();
        findings.sort_by(|a, b| a.0.cmp(b.0));
        for (ty, v) in findings {
            out.push_str(&format!(
                "secator_findings_total{{type=\"{}\"}} {v}\n",
                escape(ty)
            ));
        }

        out.push_str("# HELP secator_errors_total Cumulative error count across all tasks.\n");
        out.push_str("# TYPE secator_errors_total counter\n");
        out.push_str(&format!("secator_errors_total {}\n", g.errors_total));

        out
    }
}

/// Escape a label value per Prom text format: backslash, double-quote, newline.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Spawn the HTTP listener on `addr`. Returns the bound local address (useful
/// when `addr` was `0.0.0.0:0` to pick a free port) and the JoinHandle for
/// graceful shutdown. The server serves:
///   * `GET /metrics` → text exposition,
///   * anything else → `404 Not Found`.
pub async fn spawn_server(
    addr: &str,
    metrics: Arc<Metrics>,
) -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let m = Arc::clone(&metrics);
            tokio::spawn(async move {
                if let Err(_e) = handle_conn(&mut sock, &m).await {
                    // best-effort — never abort the server on a single bad client
                }
            });
        }
    });
    Ok((bound, handle))
}

async fn handle_conn(
    sock: &mut tokio::net::TcpStream,
    metrics: &Metrics,
) -> std::io::Result<()> {
    // Read the request line + headers (up to 8 KiB). We don't care about the
    // body — `/metrics` is a GET.
    let mut buf = [0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    // Strip query string ("/metrics?x=1" → "/metrics").
    let path = path.split('?').next().unwrap_or("");

    if method.eq_ignore_ascii_case("GET") && path == "/metrics" {
        let body = metrics.render();
        write_response(
            sock,
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            &body,
        )
        .await
    } else if method.eq_ignore_ascii_case("GET") && path == "/" {
        // Tiny landing page so curling the root gives a hint where to look.
        write_response(
            sock,
            "200 OK",
            "text/plain; charset=utf-8",
            "secator metrics — scrape GET /metrics\n",
        )
        .await
    } else {
        write_response(sock, "404 Not Found", "text/plain; charset=utf-8", "404\n").await
    }
}

async fn write_response(
    sock: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn render_returns_zero_state_template() {
        let m = Metrics::new();
        let out = m.render();
        assert!(out.contains("# HELP secator_tasks_total"));
        assert!(out.contains("# TYPE secator_tasks_total counter"));
        assert!(out.contains("# HELP secator_findings_total"));
        assert!(out.contains("secator_errors_total 0"));
    }

    #[test]
    fn inc_task_aggregates_by_class_and_status() {
        let m = Metrics::new();
        m.inc_task("nmap", "SUCCESS");
        m.inc_task("nmap", "SUCCESS");
        m.inc_task("nmap", "FAILURE");
        m.inc_task("httpx", "SUCCESS");
        let out = m.render();
        assert!(out.contains("secator_tasks_total{class=\"nmap\",status=\"SUCCESS\"} 2"));
        assert!(out.contains("secator_tasks_total{class=\"nmap\",status=\"FAILURE\"} 1"));
        assert!(out.contains("secator_tasks_total{class=\"httpx\",status=\"SUCCESS\"} 1"));
    }

    #[test]
    fn task_seconds_emits_sum_and_count() {
        let m = Metrics::new();
        m.observe_task_seconds("nmap", 1.5);
        m.observe_task_seconds("nmap", 2.5);
        let out = m.render();
        assert!(out.contains("secator_task_seconds_sum{class=\"nmap\"} 4"));
        assert!(out.contains("secator_task_seconds_count{class=\"nmap\"} 2"));
    }

    #[test]
    fn observe_task_seconds_rejects_nan_and_negative() {
        let m = Metrics::new();
        m.observe_task_seconds("x", f64::NAN);
        m.observe_task_seconds("x", -1.0);
        let out = m.render();
        // Nothing got recorded → no line for class="x".
        assert!(!out.contains("secator_task_seconds_sum{class=\"x\"}"));
    }

    #[test]
    fn findings_total_groups_by_type() {
        let m = Metrics::new();
        m.inc_finding("vulnerability");
        m.inc_findings_by("vulnerability", 4);
        m.inc_finding("url");
        let out = m.render();
        assert!(out.contains("secator_findings_total{type=\"vulnerability\"} 5"));
        assert!(out.contains("secator_findings_total{type=\"url\"} 1"));
    }

    #[test]
    fn errors_total_accumulates() {
        let m = Metrics::new();
        m.inc_errors(2);
        m.inc_errors(3);
        assert!(m.render().contains("secator_errors_total 5"));
    }

    #[test]
    fn label_values_are_escaped() {
        let m = Metrics::new();
        m.inc_task("foo\"bar\\baz", "SUCCESS");
        let out = m.render();
        assert!(out.contains("class=\"foo\\\"bar\\\\baz\""));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_server_serves_metrics_endpoint() {
        let m = Metrics::new();
        m.inc_task("nmap", "SUCCESS");
        let (addr, handle) = spawn_server("127.0.0.1:0", Arc::clone(&m)).await.unwrap();
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("text/plain"));
        assert!(resp.contains("secator_tasks_total{class=\"nmap\",status=\"SUCCESS\"} 1"));
        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_server_returns_404_for_unknown_paths() {
        let m = Metrics::new();
        let (addr, handle) = spawn_server("127.0.0.1:0", m).await.unwrap();
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /not-here HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_server_root_returns_landing_text() {
        let m = Metrics::new();
        let (addr, handle) = spawn_server("127.0.0.1:0", m).await.unwrap();
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("scrape GET /metrics"));
        handle.abort();
    }
}
