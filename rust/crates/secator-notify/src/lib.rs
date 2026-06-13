//! Webhook notification drivers — Slack + Discord.
//!
//! Both post structured messages to an Incoming Webhook URL. Findings are
//! filtered by `finding_types` + `min_severity`, then rendered into a short
//! prose summary. No tokens required (webhook URL is the only credential).

pub mod common;
pub mod discord;
pub mod slack;

pub use discord::DiscordDriver;
pub use slack::SlackDriver;
