//! Configuration for Vigil's monitor mode, webhooks, and Lua plugins.
//!
//! Loaded from a `vigil.toml` file. All sections are optional so the file can
//! be as small as a single `[[webhook]]` entry.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub monitor: MonitorConfig,
    #[serde(default, rename = "webhook")]
    pub webhooks: Vec<WebhookConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorConfig {
    /// Paths to watch / scan.
    #[serde(default = "default_paths")]
    pub paths: Vec<PathBuf>,
    /// Watch the local filesystem and re-scan on change.
    #[serde(default = "default_true")]
    pub watch: bool,
    /// Poll the npm registry for new versions of declared dependencies.
    #[serde(default = "default_true")]
    pub registry: bool,
    /// Registry poll interval, e.g. "5m", "30s", "1h".
    #[serde(default = "default_interval")]
    pub interval: String,
    /// Registry base URL (overridable for private registries / testing).
    #[serde(default = "default_registry_url")]
    pub registry_url: String,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            paths: default_paths(),
            watch: true,
            registry: true,
            interval: default_interval(),
            registry_url: default_registry_url(),
        }
    }
}

impl MonitorConfig {
    /// Parse the human interval string into a Duration. Falls back to 5m.
    pub fn interval_duration(&self) -> Duration {
        parse_duration(&self.interval).unwrap_or_else(|| Duration::from_secs(300))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// Destination URL (required for generic/slack/discord).
    #[serde(default)]
    pub url: Option<String>,
    /// Payload format: "generic", "slack", "discord", or "telegram".
    #[serde(default = "default_format")]
    pub format: WebhookFormat,
    /// Minimum severity that triggers this webhook.
    #[serde(default = "default_threshold")]
    pub threshold: String,
    /// Which events fire this webhook: "block", "finding".
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    /// Telegram bot token (required when format = "telegram").
    #[serde(default)]
    pub token: Option<String>,
    /// Telegram chat ID to send to (required when format = "telegram").
    #[serde(default)]
    pub chat_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    Generic,
    Slack,
    Discord,
    Telegram,
}

impl Config {
    /// Load config from an explicit path.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&content)?;
        Ok(cfg)
    }

    /// Look for `vigil.toml` in the given directory; return default if absent.
    pub fn discover(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let candidate = dir.join("vigil.toml");
        if candidate.is_file() {
            Self::from_file(&candidate)
        } else {
            Ok(Config::default())
        }
    }
}

fn default_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(".")]
}
fn default_true() -> bool {
    true
}
fn default_interval() -> String {
    "5m".to_string()
}
fn default_registry_url() -> String {
    "https://registry.npmjs.org".to_string()
}
fn default_format() -> WebhookFormat {
    WebhookFormat::Generic
}
fn default_threshold() -> String {
    "high".to_string()
}
fn default_events() -> Vec<String> {
    vec!["block".to_string(), "finding".to_string()]
}

/// Parse a duration string like "30s", "5m", "2h", or a bare number (seconds).
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len()),
    );
    let value: f64 = num.parse().ok()?;
    let secs = match unit.trim() {
        "" | "s" | "sec" | "secs" => value,
        "m" | "min" | "mins" => value * 60.0,
        "h" | "hr" | "hrs" => value * 3600.0,
        "d" | "day" | "days" => value * 86400.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("bogus"), None);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.webhooks.is_empty());
        assert!(cfg.monitor.watch);
        assert!(cfg.monitor.registry);
        assert_eq!(cfg.monitor.interval_duration(), Duration::from_secs(300));
    }

    #[test]
    fn parses_webhook_section() {
        let toml = r#"
            [[webhook]]
            url = "https://hooks.slack.com/x"
            format = "slack"
            threshold = "critical"
            events = ["block"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.webhooks.len(), 1);
        assert_eq!(cfg.webhooks[0].format, WebhookFormat::Slack);
        assert_eq!(cfg.webhooks[0].threshold, "critical");
    }
}
