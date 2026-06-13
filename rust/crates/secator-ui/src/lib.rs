//! Terminal UI: rendering OutputItems, lifecycle Info lines, the stdout/stderr split.
//!
//! Maps to Python `secator/rich.py` + each `OutputType.__rich__`. CRITICAL invariant:
//! UI to **stderr**, raw piped data to **stdout**, so
//! `secator x subfinder | secator x httpx` keeps working.
//!
//! ANSI colors are hand-rolled; we honor terminal detection via `std::io::IsTerminal`
//! and `NO_COLOR` (https://no-color.org).

use std::io::IsTerminal;

use secator_model::{
    Domain, Error, Exploit, Info, Ip, OutputItem, Port, Record, Subdomain, Tag, Technology, Url,
    Vulnerability, Warning,
};

// ----------------------------------------------------------------------- Colors

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m";

/// Per-context color toggle. `stderr_tty` controls UI coloring; `stdout_tty` decides
/// whether raw-piped output stays plain.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
}
impl Style {
    /// Detect from the actual terminals, honoring `NO_COLOR`.
    pub fn detect_stderr() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Style { color: false };
        }
        Style { color: std::io::stderr().is_terminal() }
    }
}

fn paint(s: &str, code: &str, style: Style) -> String {
    if style.color {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

fn bold(s: &str, style: Style) -> String { paint(s, BOLD, style) }
fn dim(s: &str, style: Style) -> String { paint(s, DIM, style) }
fn red(s: &str, style: Style) -> String { paint(s, RED, style) }
fn green(s: &str, style: Style) -> String { paint(s, GREEN, style) }
fn yellow(s: &str, style: Style) -> String { paint(s, YELLOW, style) }
fn blue(s: &str, style: Style) -> String { paint(s, BLUE, style) }
fn magenta(s: &str, style: Style) -> String { paint(s, MAGENTA, style) }
fn cyan(s: &str, style: Style) -> String { paint(s, CYAN, style) }

// ----------------------------------------------------------------- Lifecycle

/// Lifecycle prefix mirroring Python: `[INF]` cyan, `[WRN]` yellow, `[ERR]` red.
pub fn info(msg: &str, style: Style) -> String {
    format!("{} {msg}", bold(&cyan("[INF]", style), style))
}
pub fn warn(msg: &str, style: Style) -> String {
    format!("{} {msg}", bold(&yellow("[WRN]", style), style))
}
pub fn err(msg: &str, style: Style) -> String {
    format!("{} {msg}", bold(&red("[ERR]", style), style))
}

/// `⚡ <cmd>` echo (Python prints in bold green).
pub fn cmd_echo(cmd: &str, style: Style) -> String {
    format!("⚡ {}", bold(&green(cmd, style), style))
}

/// `🎯 <name> (<type>)` line for targets.
pub fn target_line(name: &str, kind: &str, style: Style) -> String {
    format!("      🎯 {} ({})", blue(name, style), dim(kind, style))
}

// ------------------------------------------------------------- Item rendering

/// Render an `OutputItem` for terminal display (stderr). Returns `None` for items that
/// shouldn't be shown (e.g. internal-only items in the future).
pub fn render(item: &OutputItem, style: Style) -> Option<String> {
    Some(match item {
        OutputItem::Url(u) => render_url(u, style),
        OutputItem::Subdomain(s) => render_subdomain(s, style),
        OutputItem::Port(p) => render_port(p, style),
        OutputItem::Ip(i) => render_ip(i, style),
        OutputItem::Tag(t) => render_tag(t, style),
        OutputItem::Technology(t) => render_technology(t, style),
        OutputItem::Vulnerability(v) => render_vulnerability(v, style),
        OutputItem::Exploit(e) => render_exploit(e, style),
        OutputItem::Domain(d) => render_domain(d, style),
        OutputItem::Record(r) => render_record(r, style),
        OutputItem::Target(t) => target_line(&t.name, &t.type_, style),
        OutputItem::Info(i) => render_info(i, style),
        OutputItem::Warning(w) => render_warning(w, style),
        OutputItem::Error(e) => render_error(e, style),
        // For other types, fall back to a generic line.
        _ => format!("• {} ({})", item.type_name(), dim(&item.meta().source, style)),
    })
}

fn render_url(u: &Url, style: Style) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("🔗 {}", u.url));
    if !u.method.is_empty() && u.method != "GET" {
        parts.push(format!("[{}]", cyan(&u.method, style)));
    }
    if u.status_code != 0 {
        let code_str = u.status_code.to_string();
        let colored = if u.status_code < 400 {
            green(&code_str, style)
        } else {
            red(&code_str, style)
        };
        parts.push(format!("[{colored}]"));
    }
    if !u.title.is_empty() {
        parts.push(format!("[{}]", green(&trim(&u.title, 60), style)));
    }
    if !u.webserver.is_empty() {
        parts.push(format!("[{}]", bold(&magenta(&u.webserver, style), style)));
    }
    if !u.tech.is_empty() {
        let techs = u.tech.join(", ");
        parts.push(format!("[{}]", magenta(&techs, style)));
    }
    if !u.content_type.is_empty() {
        parts.push(format!("[{}]", magenta(&u.content_type, style)));
    }
    if u.content_length > 0 {
        parts.push(format!("[{}]", magenta(&u.content_length.to_string(), style)));
    }
    if !u.stored_response_path.is_empty() {
        parts.push("📝".into());
    }
    let line = parts.join(" ");
    if u.verified {
        line
    } else {
        // Dim the whole line for unverified URLs.
        dim(&line, style)
    }
}

fn render_subdomain(s: &Subdomain, style: Style) -> String {
    let mut line = format!("🌐 {}", s.host);
    if !s.sources.is_empty() {
        line.push_str(&format!(" {}", dim(&format!("({})", s.sources.join(", ")), style)));
    }
    if !s.tags.is_empty() {
        line.push_str(&format!(" {}", dim(&format!("[{}]", s.tags.join(", ")), style)));
    }
    line
}

/// Mirrors Python `Tag.__rich__`: `🏷️ [<category>] <name> <value> found @ <match>`.
/// Long values are truncated; the multi-line `extra_data` block is intentionally
/// omitted from this single-line renderer.
fn render_tag(t: &Tag, style: Style) -> String {
    let mut line = format!("🏷️  [{}] {}", yellow(&t.category, style), magenta(&t.name, style));
    if !t.value.is_empty() && t.value.len() < 100 {
        line.push_str(&format!(" {}", bold(&t.value, style)));
    }
    if !t.match_.is_empty() && t.match_ != t.value {
        line.push_str(&format!(" found @ {}", bold(&t.match_, style)));
    }
    line
}

/// Mirrors Python `Record.__rich__`: `🎤 <name> [<type>] [<host>] [<extra>]`.
fn render_record(r: &Record, style: Style) -> String {
    let mut line = format!("🎤 {} [{}]", bold(&r.name, style), green(&r.type_, style));
    if !r.host.is_empty() {
        line.push_str(&format!(" [{}]", magenta(&r.host, style)));
    }
    let ed = format_extra_data(&r.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    line
}

/// Mirrors Python `Domain.__rich__`: `🪪  <domain> [<registrant>] [<registrar>] ...`.
fn render_domain(d: &Domain, style: Style) -> String {
    let mut line = format!("🪪  {}", bold(&d.domain, style));
    if d.alive {
        line.push_str(&format!(" [{}]", bold(&green("alive", style), style)));
    }
    if !d.registrant.is_empty() {
        line.push_str(&format!(" [{}]", bold(&magenta(&d.registrant, style), style)));
    }
    if !d.registrar.is_empty() {
        line.push_str(&format!(" [{}]", bold(&blue(&d.registrar, style), style)));
    }
    if let Some(exp) = d.expiration_date.as_deref().filter(|s| !s.is_empty()) {
        line.push_str(&format!(" [{} {}]", bold(&green("expires", style), style), exp));
    }
    let ed = format_extra_data(&d.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    line
}

/// Mirrors Python `Ip.__rich__`: `💻 <ip> [<host>] [alive]`, dimmed if `!alive`.
fn render_ip(i: &Ip, style: Style) -> String {
    let mut line = format!("💻 {}", bold(&i.ip, style));
    if !i.host.is_empty() && i.host != i.ip {
        line.push_str(&format!(" [{}]", bold(&magenta(&i.host, style), style)));
    }
    if i.alive {
        line.push_str(&format!(" [{}]", bold(&green("alive", style), style)));
    } else {
        line = dim(&line, style);
    }
    line
}

fn render_port(p: &Port, style: Style) -> String {
    let mut line = format!("🔌 {}:{}", bold(&p.host, style), bold(&p.port.to_string(), style));
    if !p.service_name.is_empty() {
        line.push_str(&format!(" [{}]", cyan(&p.service_name, style)));
    }
    if !p.state.is_empty() && p.state != "UNKNOWN" {
        line.push_str(&format!(" [{}]", green(&p.state, style)));
    }
    line
}

fn render_technology(t: &Technology, style: Style) -> String {
    let product = match &t.version {
        Some(v) if !v.is_empty() => format!("{} {}", t.product, v),
        _ => t.product.clone(),
    };
    format!(
        "📦 {} found @ {}",
        bold(&magenta(&product, style), style),
        dim(&t.match_, style),
    )
}

/// Mirrors Python `Vulnerability.__rich__`:
/// `🚨 [<id>: <name>] [<severity>] <matched_at> [<tags>] [<extra_data>] (<provider>)`.
/// Low-confidence vulns are dimmed.
fn render_vulnerability(v: &Vulnerability, style: Style) -> String {
    let sev_color = match v.severity.as_str() {
        "critical" | "high" => RED,
        "medium" => YELLOW,
        "low" => GREEN,
        "info" => MAGENTA,
        _ => GREY,
    };
    let name = if !v.id.is_empty() && v.id.to_lowercase() != v.name.to_lowercase() {
        format!("{}: {}", v.id, v.name)
    } else {
        v.name.clone()
    };
    let mut line = format!("🚨 [{}]", green(&name, style));
    line.push_str(&format!(" [{}]", paint(&v.severity, sev_color, style)));
    if !v.matched_at.is_empty() {
        line.push_str(&format!(" {}", v.matched_at));
    }
    if !v.tags.is_empty() {
        line.push_str(&format!(" [{}]", cyan(&v.tags.join(","), style)));
    }
    let ed = format_extra_data(&v.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    if !v.provider.is_empty() {
        line.push_str(&format!(" ({})", dim(&v.provider, style)));
    }
    if v.confidence == "low" {
        line = dim(&line, style);
    }
    line
}

/// Mirrors Python `Exploit.__rich__`:
/// `🔑 [<name>] <matched_at> [<cves>] [<tags>] [<extra_data>]`.
fn render_exploit(e: &Exploit, style: Style) -> String {
    let mut line = format!("🔑 [{}]", bold(&red(&e.name, style), style));
    if !e.matched_at.is_empty() {
        line.push_str(&format!(" {}", e.matched_at));
    }
    if !e.cves.is_empty() {
        line.push_str(&format!(" [{}]", green(&e.cves.join(", "), style)));
    }
    if !e.tags.is_empty() {
        line.push_str(&format!(" [{}]", cyan(&e.tags.join(", "), style)));
    }
    let ed = format_extra_data(&e.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    if e.confidence == "low" {
        line = dim(&line, style);
    }
    line
}

/// Mirrors Python `format_object`: render an `extra_data` map as
/// `[k: v, k: v]` in yellow. Empty maps return an empty string.
fn format_extra_data(m: &secator_model::Map, style: Style) -> String {
    if m.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = m
        .iter()
        .filter_map(|(k, v)| {
            let s = match v {
                serde_json::Value::String(s) if !s.is_empty() => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Array(a) if !a.is_empty() => a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => return None,
            };
            Some(format!("{k}: {s}"))
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("[{}]", yellow(&parts.join(", "), style))
    }
}

fn render_info(i: &Info, style: Style) -> String {
    info(&i.message, style)
}
fn render_warning(w: &Warning, style: Style) -> String {
    warn(&w.message, style)
}
fn render_error(e: &Error, style: Style) -> String {
    err(&e.message, style)
}

// ------------------------------------------------------------ Raw piped form

/// The string to emit on stdout when piping (Python `print_raw` mode). Returns `None`
/// for items that have no useful piped form.
pub fn raw(item: &OutputItem) -> Option<String> {
    match item {
        OutputItem::Url(u) => Some(u.url.clone()),
        OutputItem::Subdomain(s) => Some(s.host.clone()),
        OutputItem::Port(p) => Some(format!("{}:{}", p.host, p.port)),
        OutputItem::Ip(i) => Some(i.ip.clone()),
        OutputItem::Vulnerability(v) => Some(v.matched_at.clone()),
        OutputItem::Technology(t) => Some(t.match_.clone()),
        OutputItem::Tag(t) => Some(t.match_.clone()),
        OutputItem::Target(t) => Some(t.name.clone()),
        _ => None,
    }
}

// --------------------------------------------------------------- Helpers

fn trim(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

// ----------------------------------------------------------------------- Tests
// ------------------------------------------------------------- Live sink

/// In-place renderer for stderr. Overwrites the previous line when the
/// incoming item is a `Progress` (Python TUI parity — a single bar that ticks
/// up rather than a wall of lines). Non-progress items first "commit" the
/// progress line with `\n` then render normally.
pub struct LiveSink {
    /// True when stderr supports cursor moves (TTY). When false, every item
    /// renders as a fresh line — same behaviour as without LiveSink.
    pub interactive: bool,
    pending_progress: bool,
    pub style: Style,
}

impl LiveSink {
    pub fn new(style: Style) -> Self {
        use std::io::IsTerminal;
        LiveSink {
            interactive: std::io::stderr().is_terminal(),
            pending_progress: false,
            style,
        }
    }

    /// Force non-interactive mode (e.g. `--no-color` or piping stderr).
    pub fn plain(mut self) -> Self {
        self.interactive = false;
        self
    }

    /// Emit one item. Returns the line that was written (or `None` if the
    /// item is silently consumed — e.g. a Progress in non-interactive mode).
    pub fn emit(&mut self, item: &OutputItem) {
        let line = match render(item, self.style) {
            Some(l) => l,
            None => return,
        };
        match item {
            OutputItem::Progress(_) if self.interactive => {
                // `\r` returns to col 0, `\x1b[2K` erases the line. Combined,
                // the new progress bar replaces the previous one in place.
                eprint!("\r\x1b[2K{line}");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                self.pending_progress = true;
            }
            _ => {
                if self.pending_progress {
                    eprintln!();
                    self.pending_progress = false;
                }
                eprintln!("{line}");
            }
        }
    }

    /// Final cleanup — leaves stderr cursor on a fresh line. Idempotent.
    pub fn finish(&mut self) {
        if self.pending_progress {
            eprintln!();
            self.pending_progress = false;
        }
    }
}

impl Drop for LiveSink {
    fn drop(&mut self) {
        self.finish();
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Subdomain, Url};

    fn plain() -> Style { Style { color: false } }

    #[test]
    fn url_renders_primary_fields() {
        let u = Url {
            url: "https://example.com".into(),
            status_code: 200,
            title: "Example Domain".into(),
            webserver: "cloudflare".into(),
            tech: vec!["Cloudflare".into()],
            content_type: "text/html".into(),
            content_length: 528,
            verified: true,
            ..Default::default()
        };
        let s = render_url(&u, plain());
        assert!(s.starts_with("🔗 https://example.com"));
        assert!(s.contains("[200]"));
        assert!(s.contains("[Example Domain]"));
        assert!(s.contains("[cloudflare]"));
        assert!(s.contains("[Cloudflare]"));
        assert!(s.contains("[text/html]"));
        assert!(s.contains("[528]"));
    }

    #[test]
    fn subdomain_renders_host_and_sources() {
        let s = Subdomain {
            host: "a.example.com".into(),
            domain: "example.com".into(),
            sources: vec!["alienvault".into(), "crtsh".into()],
            ..Default::default()
        };
        let line = render_subdomain(&s, plain());
        assert!(line.contains("a.example.com"));
        assert!(line.contains("(alienvault, crtsh)"));
    }

    #[test]
    fn unverified_url_is_dimmed_with_color() {
        let u = Url { url: "https://x".into(), verified: false, ..Default::default() };
        let s = render_url(&u, Style { color: true });
        // The dim escape sequence wraps the line when color is on.
        assert!(s.starts_with(DIM));
        assert!(s.ends_with(RESET));
    }

    #[test]
    fn lifecycle_formatters() {
        assert!(info("hello", plain()).starts_with("[INF]"));
        assert!(warn("ouch", plain()).starts_with("[WRN]"));
        assert!(err("bad", plain()).starts_with("[ERR]"));
        assert_eq!(cmd_echo("ls -la", plain()), "⚡ ls -la");
    }

    #[test]
    fn raw_returns_url_for_url_item() {
        let item = OutputItem::Url(Url { url: "https://x".into(), ..Default::default() });
        assert_eq!(raw(&item).as_deref(), Some("https://x"));
    }
}
