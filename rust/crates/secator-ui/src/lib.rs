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
    Ai, Certificate, Domain, Error, Exploit, Info, Ip, OutputItem, Port, Record, State, Subdomain,
    Tag, Technology, Url, UserAccount, Vulnerability, Warning,
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
const WHITE: &str = "\x1b[37m";
#[allow(dead_code)]
const GREY: &str = "\x1b[90m";
// Rich extended (256-color) palette — codes match `rich.color.ANSI_COLOR_NAMES`
// so the Rust CLI paints the same hue Python does for the same concept.
const TURQUOISE4: &str = "\x1b[38;5;30m";
const SPRING_GREEN3: &str = "\x1b[38;5;41m";
const GOLD3: &str = "\x1b[38;5;178m";
const YELLOW3: &str = "\x1b[38;5;184m";
const ORANGE3: &str = "\x1b[38;5;172m";
const ORANGE4: &str = "\x1b[38;5;94m";
const DARK_ORANGE3: &str = "\x1b[38;5;166m";
const RED3: &str = "\x1b[38;5;160m";
const PURPLE: &str = "\x1b[38;5;129m";
const BRIGHT_BLUE: &str = "\x1b[94m";

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
fn white(s: &str, style: Style) -> String { paint(s, WHITE, style) }
fn turquoise4(s: &str, style: Style) -> String { paint(s, TURQUOISE4, style) }
fn spring_green3(s: &str, style: Style) -> String { paint(s, SPRING_GREEN3, style) }
#[allow(dead_code)] // Kept for palette completeness; may be used by future render fns / plugins.
fn gold3(s: &str, style: Style) -> String { paint(s, GOLD3, style) }
fn yellow3(s: &str, style: Style) -> String { paint(s, YELLOW3, style) }
fn orange3(s: &str, style: Style) -> String { paint(s, ORANGE3, style) }
fn orange4(s: &str, style: Style) -> String { paint(s, ORANGE4, style) }
fn dark_orange3(s: &str, style: Style) -> String { paint(s, DARK_ORANGE3, style) }
fn red3(s: &str, style: Style) -> String { paint(s, RED3, style) }
fn purple(s: &str, style: Style) -> String { paint(s, PURPLE, style) }
fn bright_blue(s: &str, style: Style) -> String { paint(s, BRIGHT_BLUE, style) }

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
        OutputItem::UserAccount(u) => render_user_account(u, style),
        OutputItem::Certificate(c) => render_certificate(c, style),
        OutputItem::State(s) => render_state(s, style),
        OutputItem::Ai(a) => match render_ai(a, style) {
            Some(l) => l,
            None => return None,
        },
        OutputItem::Target(t) => target_line(&t.name, &t.type_, style),
        OutputItem::Info(i) => render_info(i, style),
        OutputItem::Warning(w) => render_warning(w, style),
        OutputItem::Error(e) => render_error(e, style),
        // For other types (Progress, Stat), fall back to a generic line.
        _ => format!("• {} ({})", item.type_name(), dim(&item.meta().source, style)),
    })
}

fn render_url(u: &Url, style: Style) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("🔗 {}", white(&u.url, style)));
    if !u.method.is_empty() && u.method != "GET" {
        parts.push(format!("[{}]", turquoise4(&u.method, style)));
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
        parts.push(format!("[{}]", spring_green3(&trim(&u.title, 60), style)));
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
    let mut line = format!("🏰 {}", white(&s.host, style));
    if !s.sources.is_empty() {
        let srcs = s
            .sources
            .iter()
            .map(|src| magenta(src, style))
            .collect::<Vec<_>>()
            .join(", ");
        line.push_str(&format!(" [{srcs}]"));
    }
    if !s.tags.is_empty() {
        line.push_str(&format!(" {}", dim(&format!("[{}]", s.tags.join(", ")), style)));
    }
    let ed = format_extra_data(&s.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    if !s.verified {
        line = dim(&line, style);
    }
    line
}

/// Mirrors Python `Tag.__rich__`: `🏷️ [<category>] <name> <value> found @ <match>`.
/// Long values are truncated; the multi-line `extra_data` block is intentionally
/// omitted from this single-line renderer.
fn render_tag(t: &Tag, style: Style) -> String {
    let category = match t.category.as_str() {
        "error" => bold(&dark_orange3(&t.category, style), style),
        "secret" => bold(&red3(&t.category, style), style),
        _ => bold(&yellow(&t.category, style), style),
    };
    let mut line = format!("🏷️  [{}] {}", category, bold(&magenta(&t.name, style), style));
    if !t.value.is_empty() && t.value.len() < 100 {
        line.push_str(&format!(" {}", bold(&orange4(&t.value, style), style)));
    }
    if !t.match_.is_empty() && t.match_ != t.value {
        line.push_str(&format!(" found @ {}", bold(&t.match_, style)));
    }
    line
}

/// Mirrors Python `Record.__rich__`: `🎤 <name> [<type>] [<host>] [<extra>]`.
fn render_record(r: &Record, style: Style) -> String {
    let mut line = format!(
        "🎤 {} [{}]",
        bold(&white(&r.name, style), style),
        green(&r.type_, style),
    );
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
    let mut line = format!("🪪  {}", bold(&white(&d.domain, style), style));
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
    let mut line = format!("💻 {}", bold(&white(&i.ip, style), style));
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
    let ip = if p.ip.is_empty() { p.host.as_str() } else { p.ip.as_str() };
    // Python uses `:<4` — pad port to width 4 so the state column lines up.
    let port_padded = format!("{:<4}", p.port);
    let mut line = format!("🔓 {}:{}", ip, bold(&red(&port_padded, style), style));
    if !p.state.is_empty() {
        let mut state_str = bold(&yellow(&p.state.to_uppercase(), style), style);
        if p.confidence == "low" {
            state_str.push_str(&bold(&orange3("?", style), style));
        }
        line.push_str(&format!(" {state_str}"));
    }
    let proto_upper = p.protocol.to_uppercase();
    if !proto_upper.is_empty() && proto_upper != "TCP" {
        line.push_str(&format!(" [{}]", yellow3(&proto_upper, style)));
    }
    if !p.service_name.is_empty() {
        let mut svc = bold(&purple(&p.service_name, style), style);
        if p.service_confidence == "low" {
            svc.push_str(&bold(&orange3("?", style), style));
        }
        line.push_str(&format!(" [{svc}]"));
    }
    if !p.host.is_empty() && p.host != p.ip {
        line.push_str(&format!(" [{}]", cyan(&p.host, style)));
    }
    if !p.tags.is_empty() {
        line.push_str(&format!(" [{}]", cyan(&p.tags.join(","), style)));
    }
    let ed = format_extra_data(&p.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    if p.confidence == "low" {
        line = dim(&line, style);
    }
    line
}

fn render_technology(t: &Technology, style: Style) -> String {
    // Python: `📦 [bold orange3]{product}[/]/[red]{version}[/] found @ {match}`.
    let product_str = bold(&orange3(&t.product, style), style);
    let versioned = match &t.version {
        Some(v) if !v.is_empty() => format!("{}/{}", product_str, red(v, style)),
        _ => product_str,
    };
    format!("📦 {} found @ {}", versioned, t.match_)
}

/// Mirrors Python `Vulnerability.__rich__`:
/// `🚨 [<id>: <name>] [<severity>] <matched_at> [<tags>] [<extra_data>] (<provider>)`.
/// Low-confidence vulns are dimmed.
fn render_vulnerability(v: &Vulnerability, style: Style) -> String {
    // Python severity colors: critical=bold red, high=red, medium=yellow, low=green,
    // info=magenta, else=dim magenta.
    let paint_sev = |s: &str| -> String {
        match v.severity.as_str() {
            "critical" => bold(&red(s, style), style),
            "high" => bold(&red(s, style), style),
            "medium" => bold(&yellow(s, style), style),
            "low" => bold(&green(s, style), style),
            "info" => bold(&magenta(s, style), style),
            _ => bold(&dim(&magenta(s, style), style), style),
        }
    };
    let name = if !v.id.is_empty() && v.id.to_lowercase() != v.name.to_lowercase() {
        format!("{}: {}", v.id, v.name)
    } else {
        v.name.clone()
    };
    let mut line = format!("🚨 [{}]", paint_sev(&name));
    line.push_str(&format!(" [{}]", paint_sev(&v.severity)));
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
        line.push_str(&format!(" ({})", dim(&orange4(&v.provider, style), style)));
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

/// Mirrors Python `UserAccount.__rich__`: `👤 <username> [<email>] [<site>] [<url>] [<extra>]`.
fn render_user_account(u: &UserAccount, style: Style) -> String {
    let mut line = format!("👤 {}", green(&u.username, style));
    if !u.email.is_empty() {
        line.push_str(&format!(" [{}]", bold(&yellow(&u.email, style), style)));
    }
    if !u.site_name.is_empty() {
        line.push_str(&format!(" [{}]", bold(&blue(&u.site_name, style), style)));
    }
    if !u.url.is_empty() {
        line.push_str(&format!(" [{}]", white(&u.url, style)));
    }
    let ed = format_extra_data(&u.extra_data, style);
    if !ed.is_empty() {
        line.push_str(&format!(" {ed}"));
    }
    line
}

/// Mirrors Python `Certificate.__rich__`: `📜 <host> [<status>] [expired/valid] [cn=...] [an=...] [issuer=...] [fp_sha256=...]`.
fn render_certificate(c: &Certificate, style: Style) -> String {
    let mut line = format!("📜 {}", bold(&white(&c.host, style), style));
    if !c.status.is_empty() && c.status != "Unknown" {
        line.push_str(&format!(" [{}]", cyan(&c.status, style)));
    }
    let is_wildcard = c.subject_cn.starts_with("*.")
        || c.subject_an.iter().any(|a| a.starts_with("*."));
    if is_wildcard {
        line.push_str(&format!(" [{}]", yellow("wildcard", style)));
    }
    if let Some(exp) = c.not_after.as_deref().filter(|s| !s.is_empty()) {
        line.push_str(&format!(" [{} {}]", bold(&green("valid until", style), style), exp));
    }
    if !c.subject_cn.is_empty() {
        line.push_str(&format!(" [{}={}]", bold(&red("cn", style), style), c.subject_cn));
    }
    if !c.subject_an.is_empty() {
        line.push_str(&format!(
            " [{}={}]",
            bold(&orange4("an", style), style),
            c.subject_an.join(", "),
        ));
    }
    let issuer = if !c.issuer.is_empty() { &c.issuer } else { &c.issuer_cn };
    if !issuer.is_empty() {
        let label = if !c.issuer.is_empty() { "issuer" } else { "issuer_cn" };
        line.push_str(&format!(" [{}={}]", bold(&magenta(label, style), style), issuer));
    }
    if !c.fingerprint_sha256.is_empty() {
        let short: String = c.fingerprint_sha256.chars().take(10).collect();
        line.push_str(&format!(" [{}={}]", bold(&cyan("fingerprint_sha256", style), style), short));
    }
    line
}

/// Mirrors Python `State.__rich__`: `📊 <state> <task_id>` in bold bright_blue.
fn render_state(s: &State, style: Style) -> String {
    format!("📊 {} {}", bold(&bright_blue(&s.state, style), style), s.task_id)
}

/// Mirrors Python `Ai.__rich__`: label + colored content, varying by `ai_type`.
/// Colors match Python's `AI_TYPES` table. Returns `None` for internal-only types
/// (e.g. `token_usage`).
fn render_ai(a: &Ai, style: Style) -> Option<String> {
    if a.ai_type == "token_usage" {
        return None;
    }
    let (label, color): (&str, &str) = match a.ai_type.as_str() {
        "prompt" => ("❯", RED),
        "response" => ("🧠", WHITE),
        "chat_compacted" => ("📦", ORANGE3),
        "task" | "workflow" | "shell" | "add_finding" | "query" => ("🟢", MAGENTA),
        "shell_output" => ("◀", DIM),
        "stopped" => ("🛑", ORANGE3),
        "follow_up" => ("[FOLLOW UP]", ORANGE3),
        _ => ("•", ""),
    };
    let label_str = if color.is_empty() { label.to_string() } else { bold(&paint(label, color, style), style) };
    let colored = if color.is_empty() { a.content.clone() } else { paint(&a.content, color, style) };
    Some(format!("{label_str} {colored}"))
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
            verified: true,
            sources: vec!["alienvault".into(), "crtsh".into()],
            ..Default::default()
        };
        let line = render_subdomain(&s, plain());
        assert!(line.starts_with("🏰 a.example.com"), "got: {line}");
        assert!(line.contains("[alienvault, crtsh]"), "got: {line}");
    }

    #[test]
    fn port_renders_matches_python_layout() {
        let p = Port {
            ip: "10.0.0.1".into(),
            port: 443,
            state: "open".into(),
            service_name: "https".into(),
            protocol: "tcp".into(),
            confidence: "high".into(),
            service_confidence: "high".into(),
            ..Default::default()
        };
        let line = render_port(&p, plain());
        assert!(line.starts_with("🔓 10.0.0.1:443"), "got: {line}");
        assert!(line.contains("OPEN"), "got: {line}");
        assert!(line.contains("[https]"), "got: {line}");
        // TCP is elided; UDP would show as [UDP].
        assert!(!line.contains("[TCP]"), "got: {line}");
    }

    #[test]
    fn user_account_renders_username_and_extras() {
        let u = UserAccount {
            username: "alice".into(),
            email: "a@example.com".into(),
            site_name: "github".into(),
            url: "https://github.com/alice".into(),
            ..Default::default()
        };
        let line = render_user_account(&u, plain());
        assert!(line.starts_with("👤 alice"), "got: {line}");
        assert!(line.contains("[a@example.com]"), "got: {line}");
        assert!(line.contains("[github]"), "got: {line}");
    }

    #[test]
    fn certificate_renders_host_and_issuer() {
        let c = Certificate {
            host: "example.com".into(),
            subject_cn: "*.example.com".into(),
            issuer_cn: "Let's Encrypt".into(),
            not_after: Some("2027-01-01".into()),
            fingerprint_sha256: "abcdef1234567890".into(),
            status: "valid".into(),
            ..Default::default()
        };
        let line = render_certificate(&c, plain());
        assert!(line.starts_with("📜 example.com"), "got: {line}");
        assert!(line.contains("wildcard"), "got: {line}");
        assert!(line.contains("cn=*.example.com"), "got: {line}");
        assert!(line.contains("issuer_cn=Let's Encrypt"), "got: {line}");
        assert!(line.contains("fingerprint_sha256=abcdef1234"), "got: {line}");
    }

    #[test]
    fn state_renders_task_and_state() {
        let s = State {
            task_id: "job-42".into(),
            state: "SUCCESS".into(),
            ..Default::default()
        };
        let line = render_state(&s, plain());
        assert_eq!(line, "📊 SUCCESS job-42");
    }

    #[test]
    fn ai_renders_per_action_type() {
        let prompt = Ai { content: "hello?".into(), ai_type: "prompt".into(), ..Default::default() };
        assert_eq!(render_ai(&prompt, plain()).as_deref(), Some("❯ hello?"));

        let response = Ai { content: "hi".into(), ai_type: "response".into(), ..Default::default() };
        assert_eq!(render_ai(&response, plain()).as_deref(), Some("🧠 hi"));

        let task = Ai { content: "nmap".into(), ai_type: "task".into(), ..Default::default() };
        assert_eq!(render_ai(&task, plain()).as_deref(), Some("🟢 nmap"));

        let stopped = Ai { content: "".into(), ai_type: "stopped".into(), ..Default::default() };
        assert_eq!(render_ai(&stopped, plain()).as_deref(), Some("🛑 "));

        let tok = Ai { content: "".into(), ai_type: "token_usage".into(), ..Default::default() };
        assert_eq!(render_ai(&tok, plain()), None);
    }

    #[test]
    fn colors_match_python_rich_palette() {
        // Sanity-check that we emit the exact SGR sequences the Rich extended-color
        // names decode to — matches `rich.color.ANSI_COLOR_NAMES`.
        let color = Style { color: true };
        assert!(turquoise4("x", color).contains("\x1b[38;5;30m"));
        assert!(spring_green3("x", color).contains("\x1b[38;5;41m"));
        assert!(gold3("x", color).contains("\x1b[38;5;178m"));
        assert!(yellow3("x", color).contains("\x1b[38;5;184m"));
        assert!(orange3("x", color).contains("\x1b[38;5;172m"));
        assert!(orange4("x", color).contains("\x1b[38;5;94m"));
        assert!(dark_orange3("x", color).contains("\x1b[38;5;166m"));
        assert!(red3("x", color).contains("\x1b[38;5;160m"));
        assert!(purple("x", color).contains("\x1b[38;5;129m"));
        assert!(bright_blue("x", color).contains("\x1b[94m"));
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
