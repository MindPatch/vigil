//! Webhook notifications. Fires configurable HTTP POSTs when a scan produces
//! findings at or above a per-target severity threshold.
//!
//! Supports generic JSON, Slack, and Discord payload formats. An optional Lua
//! transform hook can reshape the payload before it is sent.

use crate::config::{WebhookConfig, WebhookFormat};
use crate::engine::Finding;
use crate::report::{self, RiskScore};
use crate::rules::Severity;

/// The result of scanning one subject (a package or a file/project path),
/// bundled with its computed risk score. This is the unit a webhook reports on.
pub struct ScanOutcome {
    /// Human label for what was scanned, e.g. "express-validator@1.0.2" or "./src".
    pub subject: String,
    pub findings: Vec<Finding>,
    pub score: RiskScore,
}

impl ScanOutcome {
    pub fn new(subject: impl Into<String>, findings: Vec<Finding>) -> Self {
        let score = report::compute_score(&findings);
        ScanOutcome {
            subject: subject.into(),
            findings,
            score,
        }
    }

    /// Build the canonical JSON object describing this outcome. This is what the
    /// generic webhook sends and what the Lua transform hook receives.
    pub fn to_json(&self) -> serde_json::Value {
        let findings: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "description": f.description,
                    "severity": f.severity.to_string().to_lowercase(),
                    "file": f.file,
                    "line": f.line,
                    "deobfuscated": f.deobfuscated,
                })
            })
            .collect();

        serde_json::json!({
            "subject": self.subject,
            "score": self.score.score,
            "risk_level": self.score.level.to_lowercase(),
            "verdict": self.score.verdict(),
            "tags": self.score.tags,
            "finding_count": self.findings.len(),
            "findings": findings,
        })
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 1,
    }
}

fn max_severity(findings: &[Finding]) -> u8 {
    findings
        .iter()
        .map(|f| match f.severity {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        })
        .max()
        .unwrap_or(0)
}

/// Decide whether a given webhook should fire for this outcome.
fn should_fire(cfg: &WebhookConfig, outcome: &ScanOutcome) -> bool {
    if outcome.findings.is_empty() {
        return false;
    }

    let is_block = outcome.score.verdict() == "BLOCK";
    let wants_block = cfg.events.iter().any(|e| e == "block");
    let wants_finding = cfg.events.iter().any(|e| e == "finding");

    // Event gate.
    if is_block && wants_block {
        // a block event always passes the event gate
    } else if wants_finding {
        // finding events are gated by the threshold below
    } else {
        return false;
    }

    // Severity threshold gate.
    let threshold = severity_rank(&cfg.threshold);
    max_severity(&outcome.findings) >= threshold
}

/// Render the payload for a specific webhook format.
fn render_payload(cfg: &WebhookConfig, outcome: &ScanOutcome) -> serde_json::Value {
    match cfg.format {
        WebhookFormat::Generic => outcome.to_json(),
        WebhookFormat::Slack => slack_payload(outcome),
        WebhookFormat::Discord => discord_payload(outcome),
        WebhookFormat::Telegram => telegram_payload(cfg, outcome),
    }
}

fn summary_line(outcome: &ScanOutcome) -> String {
    format!(
        "{} — {} ({}/100, {} finding{})",
        outcome.subject,
        outcome.score.verdict(),
        outcome.score.score,
        outcome.findings.len(),
        if outcome.findings.len() == 1 { "" } else { "s" },
    )
}

fn top_findings_text(outcome: &ScanOutcome, limit: usize) -> String {
    outcome
        .findings
        .iter()
        .take(limit)
        .map(|f| {
            format!(
                "• [{}] {} {}",
                f.severity.to_string().to_uppercase(),
                f.rule_id,
                f.rule_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Like `top_findings_text` but appends the offending code snippet (the source
/// line that matched) under each finding, with a `L<line>` location.
fn findings_with_snippets(outcome: &ScanOutcome, limit: usize) -> String {
    outcome
        .findings
        .iter()
        .take(limit)
        .map(|f| {
            let snippet = f.snippet.trim();
            let loc = if f.deobfuscated {
                format!("L{} (deobfuscated)", f.line)
            } else {
                format!("L{}", f.line)
            };
            if snippet.is_empty() {
                format!(
                    "• [{}] {} {}  —  {}",
                    f.severity.to_string().to_uppercase(),
                    f.rule_id,
                    f.rule_name,
                    loc,
                )
            } else {
                format!(
                    "• [{}] {} {}  —  {}\n    {}",
                    f.severity.to_string().to_uppercase(),
                    f.rule_id,
                    f.rule_name,
                    loc,
                    truncate(snippet, 160),
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let kept: String = s.chars().take(max).collect();
        format!("{kept}…")
    } else {
        s.to_string()
    }
}

fn slack_payload(outcome: &ScanOutcome) -> serde_json::Value {
    let emoji = if outcome.score.verdict() == "BLOCK" {
        ":no_entry:"
    } else {
        ":warning:"
    };
    let tags = if outcome.score.tags.is_empty() {
        String::new()
    } else {
        format!("\nTags: {}", outcome.score.tags.join(" "))
    };
    serde_json::json!({
        "text": format!("{} *Vigil* — {}", emoji, summary_line(outcome)),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "{} *Vigil verdict: {}*\n*{}*  —  score *{}/100* ({})\n{}{}",
                        emoji,
                        outcome.score.verdict(),
                        outcome.subject,
                        outcome.score.score,
                        outcome.score.level,
                        top_findings_text(outcome, 8),
                        tags,
                    )
                }
            }
        ]
    })
}

/// Telegram Bot API sendMessage payload. Sent as plain text (no parse_mode) so
/// rule names containing Markdown-special characters (e.g. `child_process`)
/// can't break message parsing.
fn telegram_payload(cfg: &WebhookConfig, outcome: &ScanOutcome) -> serde_json::Value {
    let emoji = if outcome.score.verdict() == "BLOCK" {
        "\u{1F6AB}" // 🚫
    } else {
        "\u{26A0}\u{FE0F}" // ⚠️
    };
    let tags = if outcome.score.tags.is_empty() {
        String::new()
    } else {
        format!("\n{}", outcome.score.tags.join("  "))
    };
    let text = format!(
        "{emoji} Vigil — {verdict}\n{subject}\nScore: {score}/100 ({level}) · {n} finding(s)\n\n{findings}{tags}",
        emoji = emoji,
        verdict = outcome.score.verdict(),
        subject = outcome.subject,
        score = outcome.score.score,
        level = outcome.score.level,
        n = outcome.findings.len(),
        findings = findings_with_snippets(outcome, 8),
        tags = tags,
    );
    serde_json::json!({
        "chat_id": cfg.chat_id.clone().unwrap_or_default(),
        "text": text,
        "disable_web_page_preview": true,
    })
}

/// Build the Telegram Bot API endpoint URL for a token.
fn telegram_url(token: &str) -> String {
    format!("https://api.telegram.org/bot{token}/sendMessage")
}

fn discord_payload(outcome: &ScanOutcome) -> serde_json::Value {
    let color = match outcome.score.level {
        "CRITICAL" => 0xFF5C5C,
        "HIGH" => 0xF2854E,
        "MEDIUM" => 0xF2C14E,
        _ => 0x3DDC97,
    };
    serde_json::json!({
        "content": format!("Vigil — {}", summary_line(outcome)),
        "embeds": [
            {
                "title": format!("{} — {}", outcome.score.verdict(), outcome.subject),
                "description": top_findings_text(outcome, 8),
                "color": color,
                "fields": [
                    { "name": "Score", "value": format!("{}/100 ({})", outcome.score.score, outcome.score.level), "inline": true },
                    { "name": "Findings", "value": outcome.findings.len().to_string(), "inline": true },
                    { "name": "Tags", "value": if outcome.score.tags.is_empty() { "—".to_string() } else { outcome.score.tags.join(" ") }, "inline": false },
                ]
            }
        ]
    })
}

/// Send all configured webhooks that match this outcome.
pub fn dispatch(webhooks: &[WebhookConfig], outcome: &ScanOutcome) -> Vec<WebhookResult> {
    let mut results = Vec::new();
    for cfg in webhooks {
        if !should_fire(cfg, outcome) {
            continue;
        }
        let payload = render_payload(cfg, outcome);

        // Resolve the actual POST target for this format.
        let (target, label) = match cfg.format {
            WebhookFormat::Telegram => match &cfg.token {
                Some(tok) if cfg.chat_id.is_some() => {
                    (telegram_url(tok), "telegram".to_string())
                }
                _ => {
                    results.push(WebhookResult {
                        url: "telegram".into(),
                        outcome: Err("telegram webhook needs both token and chat_id".into()),
                    });
                    continue;
                }
            },
            _ => match &cfg.url {
                Some(u) => (u.clone(), u.clone()),
                None => {
                    results.push(WebhookResult {
                        url: "(no url)".into(),
                        outcome: Err("webhook missing url".into()),
                    });
                    continue;
                }
            },
        };

        let res = post(&target, &payload);
        results.push(WebhookResult { url: label, outcome: res });
    }
    results
}

pub struct WebhookResult {
    pub url: String,
    pub outcome: Result<u16, String>,
}

/// Query the Telegram Bot API for recent chat IDs (via getUpdates), so a user
/// can discover the chat_id to put in their config. Returns (chat_id, label).
pub fn discover_telegram_chats(token: &str) -> Result<Vec<(String, String)>, String> {
    let url = format!("https://api.telegram.org/bot{token}/getUpdates");
    let body = ureq::get(&url)
        .call()
        .map_err(|e| format!("telegram getUpdates failed: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(updates) = json.get("result").and_then(|v| v.as_array()) {
        for u in updates {
            // chat can appear under message, channel_post, etc.
            for key in ["message", "channel_post", "edited_message", "my_chat_member"] {
                if let Some(chat) = u.get(key).and_then(|m| m.get("chat")) {
                    if let Some(id) = chat.get("id").and_then(|v| v.as_i64()) {
                        if seen.insert(id) {
                            let label = chat
                                .get("title")
                                .or_else(|| chat.get("username"))
                                .or_else(|| chat.get("first_name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("(chat)")
                                .to_string();
                            out.push((id.to_string(), label));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// POST a JSON payload to a URL. Returns the HTTP status code on success.
fn post(url: &str, payload: &serde_json::Value) -> Result<u16, String> {
    match ureq::post(url)
        .set("Content-Type", "application/json")
        .set("User-Agent", concat!("vigil/", env!("CARGO_PKG_VERSION")))
        .send_json(payload.clone())
    {
        Ok(resp) => Ok(resp.status()),
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebhookFormat;

    fn finding(sev: Severity) -> Finding {
        Finding {
            rule_id: "SC-001".into(),
            rule_name: "Test".into(),
            description: "d".into(),
            severity: sev,
            file: "f.js".into(),
            line: 1,
            column: 1,
            snippet: "x".into(),
            tags: vec![],
            deobfuscated: false,
        }
    }

    fn cfg(threshold: &str, events: &[&str]) -> WebhookConfig {
        WebhookConfig {
            url: Some("https://example.com".into()),
            format: WebhookFormat::Generic,
            threshold: threshold.into(),
            events: events.iter().map(|s| s.to_string()).collect(),
            token: None,
            chat_id: None,
        }
    }

    #[test]
    fn threshold_gates_finding_events() {
        let outcome = ScanOutcome::new("pkg", vec![finding(Severity::Medium)]);
        assert!(!should_fire(&cfg("high", &["finding"]), &outcome));
        assert!(should_fire(&cfg("low", &["finding"]), &outcome));
    }

    #[test]
    fn empty_findings_never_fire() {
        let outcome = ScanOutcome::new("pkg", vec![]);
        assert!(!should_fire(&cfg("low", &["finding", "block"]), &outcome));
    }

    #[test]
    fn block_event_fires_on_critical() {
        let outcome = ScanOutcome::new("pkg", vec![finding(Severity::Critical)]);
        assert_eq!(outcome.score.verdict(), "BLOCK");
        assert!(should_fire(&cfg("critical", &["block"]), &outcome));
    }
}
