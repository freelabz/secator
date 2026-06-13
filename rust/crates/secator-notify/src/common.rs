//! Shared helpers for the Slack + Discord webhook drivers.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

use secator_driver::DriverError;
use secator_model::OutputItem;

/// Build a reqwest client used by all webhook drivers (short timeout, no TLS verify
/// override, no auth header).
pub fn build_client(timeout_secs: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .user_agent("secator-rs/0.1 (notify)")
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// POST JSON to a webhook. Returns `Ok(())` for 2xx, an error otherwise.
pub async fn post_webhook(
    client: &Client,
    url: &str,
    body: &Value,
) -> Result<(), DriverError> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| DriverError(format!("webhook POST {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(DriverError(format!(
            "webhook returned {status}: {body}"
        )));
    }
    Ok(())
}

/// Severity rank — same scale as `secator-model::severity_ordinal`, lower means
/// more severe. Unknown severities are treated as the highest possible number so
/// they fall below `min_severity` (i.e. silenced).
pub fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 99,
    }
}

/// True when `item_severity` is AT LEAST as severe as `min_severity`.
pub fn passes_severity(item_severity: &str, min_severity: &str) -> bool {
    severity_rank(item_severity) <= severity_rank(min_severity)
}

/// True when the item's type is in the allowed list. Empty list ⇒ allow all.
pub fn passes_type(item: &OutputItem, allowed_types: &[String]) -> bool {
    if allowed_types.is_empty() {
        return true;
    }
    allowed_types.iter().any(|t| t == item.type_name())
}

/// Build a one-line finding label like `[critical] CVE-2024-0001: Heap overflow
/// at https://x/y`. Used by both Slack + Discord renderers.
pub fn render_finding_text(item: &OutputItem) -> Option<String> {
    match item {
        OutputItem::Vulnerability(v) => {
            let sev = if v.severity.is_empty() { "unknown".to_string() } else { v.severity.clone() };
            let mut line = format!("[{}] ", sev);
            if !v.id.is_empty() {
                line.push_str(&v.id);
                line.push_str(": ");
            }
            line.push_str(if v.name.is_empty() { "(unnamed)" } else { v.name.as_str() });
            if !v.matched_at.is_empty() {
                line.push_str(" — ");
                line.push_str(&v.matched_at);
            }
            if v.cvss_score > 0.0 {
                line.push_str(&format!(" (CVSS {:.1})", v.cvss_score));
            }
            Some(line)
        }
        OutputItem::Exploit(e) => {
            let mut line = format!("[exploit] {}", if e.name.is_empty() { "(unnamed)" } else { e.name.as_str() });
            if !e.matched_at.is_empty() {
                line.push_str(" — ");
                line.push_str(&e.matched_at);
            }
            Some(line)
        }
        OutputItem::Tag(t) => {
            if t.value.is_empty() {
                Some(format!("[tag] {}: {}", t.category, t.name))
            } else {
                Some(format!("[tag] {}: {} = {}", t.category, t.name, t.value))
            }
        }
        OutputItem::Url(u) => Some(format!("[url] {} ({})", u.url, u.status_code)),
        OutputItem::Port(p) => Some(format!("[port] {}:{}", p.host, p.port)),
        OutputItem::Subdomain(s) => Some(format!("[subdomain] {} ({})", s.host, s.domain)),
        OutputItem::Ip(i) => Some(format!("[ip] {} alive={}", i.ip, i.alive)),
        OutputItem::Certificate(c) => Some(format!("[cert] {} ({})", c.host, c.subject_cn)),
        OutputItem::Domain(d) => Some(format!("[domain] {}", d.domain)),
        OutputItem::UserAccount(u) => Some(format!(
            "[user] {}{}",
            u.email,
            if u.site_name.is_empty() { String::new() } else { format!(" @ {}", u.site_name) }
        )),
        OutputItem::Technology(t) => Some(format!("[tech] {}", t.product)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::Vulnerability;

    #[test]
    fn severity_rank_ordering() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("medium"));
        assert!(severity_rank("low") < severity_rank("info"));
        assert!(severity_rank("low") < severity_rank("unknown"));
    }

    #[test]
    fn passes_severity_at_or_above_threshold() {
        assert!(passes_severity("critical", "high"));
        assert!(passes_severity("high", "high"));
        assert!(!passes_severity("medium", "high"));
        // Unknown severity → silenced (worse than the threshold).
        assert!(!passes_severity("unknown", "high"));
    }

    #[test]
    fn passes_type_empty_allows_all() {
        let item = OutputItem::Vulnerability(Vulnerability::default());
        assert!(passes_type(&item, &[]));
        assert!(passes_type(&item, &["vulnerability".into()]));
        assert!(!passes_type(&item, &["url".into()]));
    }

    #[test]
    fn render_finding_text_for_vulnerability() {
        let v = OutputItem::Vulnerability(Vulnerability {
            name: "RCE in widget".into(),
            id: "CVE-2024-0001".into(),
            severity: "critical".into(),
            cvss_score: 9.8,
            matched_at: "https://x/y".into(),
            ..Default::default()
        });
        let s = render_finding_text(&v).unwrap();
        assert!(s.contains("[critical]"));
        assert!(s.contains("CVE-2024-0001"));
        assert!(s.contains("RCE in widget"));
        assert!(s.contains("https://x/y"));
        assert!(s.contains("CVSS 9.8"));
    }
}
