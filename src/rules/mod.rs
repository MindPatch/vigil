pub mod builtin;

use regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Regex,
    AstNodeType,
    CallExpression,
    MemberExpression,
    SubscriptExpression,
    Entropy,
    LongLine,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub kind: RuleKind,
    pub pattern: String,
    #[serde(default)]
    pub pattern2: Option<String>,
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub struct CompiledRegex {
    pub primary: Option<Regex>,
    pub secondary: Option<Regex>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let ruleset: RuleSet = toml::from_str(&content)?;
        Ok(ruleset)
    }

    pub fn default_rules() -> Self {
        builtin::default_ruleset()
    }

    pub fn compile(&self) -> Vec<CompiledRegex> {
        self.rules
            .iter()
            .map(|rule| CompiledRegex {
                primary: if rule.kind == RuleKind::Regex {
                    Regex::new(&rule.pattern).ok()
                } else {
                    None
                },
                secondary: rule
                    .pattern2
                    .as_ref()
                    .and_then(|p| Regex::new(p).ok()),
            })
            .collect()
    }
}
