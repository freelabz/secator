//! Discord webhook driver (Python `DiscordAddon`).
//!
//! Same wire shape as Slack — POSTs a JSON body with a `content` field to the
//! configured webhook URL. `bot_token` is captured for future bot-API use but
//! not consumed by the webhook path.

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use secator_config::DiscordAddon;
use secator_driver::{Driver, DriverError, RunKind};
use secator_model::OutputItem;
use secator_report::ReportInfo;

use crate::common::{build_client, passes_severity, passes_type, post_webhook, render_finding_text};

pub struct DiscordDriver {
    cfg: DiscordAddon,
    client: Client,
}

impl DiscordDriver {
    pub fn from_config(cfg: DiscordAddon) -> Self {
        let client = build_client(10);
        DiscordDriver { cfg, client }
    }
}

#[async_trait]
impl Driver for DiscordDriver {
    fn name(&self) -> &'static str { "discord" }

    fn enabled(&self) -> bool {
        self.cfg.enabled && !self.cfg.webhook_url.is_empty()
    }

    async fn on_run_start(
        &self,
        info: &ReportInfo,
        kind: RunKind,
    ) -> Result<Option<String>, DriverError> {
        if !self.cfg.send_runner_updates {
            return Ok(None);
        }
        let body = json!({
            "content": format!(
                "🚀 **secator** {} `{}` started — targets: {}",
                kind.plural().trim_end_matches('s'),
                info.name,
                if info.targets.is_empty() { "(none)".into() } else { info.targets.join(", ") }
            )
        });
        post_webhook(&self.client, &self.cfg.webhook_url, &body).await?;
        secator_debug::debug!("hooks.discord", "run_start posted for {}", info.name);
        Ok(None)
    }

    async fn on_finding(&self, item: &mut OutputItem) -> Result<(), DriverError> {
        if !self.cfg.send_findings || !item.is_finding() {
            return Ok(());
        }
        if !passes_type(item, &self.cfg.finding_types) {
            return Ok(());
        }
        if let OutputItem::Vulnerability(v) = item {
            if !passes_severity(&v.severity, &self.cfg.min_severity) {
                return Ok(());
            }
        }
        let Some(text) = render_finding_text(item) else { return Ok(()); };
        let body = json!({"content": format!("⚠️  {}", text)});
        post_webhook(&self.client, &self.cfg.webhook_url, &body).await?;
        secator_debug::debug!("hooks.discord", "finding posted ({})", item.type_name());
        Ok(())
    }

    async fn on_run_end(
        &self,
        info: &ReportInfo,
        _items: &[OutputItem],
        kind: RunKind,
        _external_id: Option<&str>,
    ) -> Result<(), DriverError> {
        if !self.cfg.send_runner_updates {
            return Ok(());
        }
        let emoji = if info.status == "SUCCESS" { "✅" } else { "❌" };
        let body = json!({
            "content": format!(
                "{} **secator** {} `{}` finished ({}) — {} finding(s), {} error(s), {}",
                emoji,
                kind.plural().trim_end_matches('s'),
                info.name,
                info.status,
                info.findings_count,
                info.errors_count,
                if info.elapsed_human.is_empty() { format!("{:.1}s", info.elapsed_seconds) } else { info.elapsed_human.clone() }
            )
        });
        post_webhook(&self.client, &self.cfg.webhook_url, &body).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_url_empty() {
        let d = DiscordDriver::from_config(DiscordAddon {
            enabled: true,
            webhook_url: String::new(),
            ..DiscordAddon::default()
        });
        assert!(!d.enabled());
    }

    #[test]
    fn enabled_when_both_set() {
        let d = DiscordDriver::from_config(DiscordAddon {
            enabled: true,
            webhook_url: "https://discord.com/api/webhooks/xxx".into(),
            ..DiscordAddon::default()
        });
        assert!(d.enabled());
    }
}
