mod matcher;

use crate::rules::{CompiledRegex, RuleKind, RuleSet, Severity};
use std::path::Path;
use tree_sitter::Tree;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub tags: Vec<String>,
    pub deobfuscated: bool,
}

impl Finding {
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}:{}", self.rule_id, self.file, self.line, self.column)
    }
}

pub fn scan(
    source: &str,
    tree: &Tree,
    ruleset: &RuleSet,
    file_path: &Path,
    compiled: &[CompiledRegex],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let file = file_path.display().to_string();

    for (rule, compiled_re) in ruleset.rules.iter().zip(compiled.iter()) {
        let matches = match rule.kind {
            RuleKind::Regex => matcher::match_regex_compiled(source, rule, compiled_re),
            RuleKind::CallExpression => matcher::match_call_expr(source, tree, rule),
            RuleKind::AstNodeType => matcher::match_ast_node(source, tree, rule),
            RuleKind::MemberExpression => matcher::match_member_expr(source, tree, rule),
            RuleKind::SubscriptExpression => matcher::match_subscript_expr(source, tree, rule),
            RuleKind::Entropy => matcher::match_entropy(source, tree, rule),
            RuleKind::LongLine => matcher::match_long_line(source, rule),
        };

        for m in matches {
            findings.push(Finding {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                description: rule.description.clone(),
                severity: rule.severity,
                file: file.clone(),
                line: m.line,
                column: m.column,
                snippet: m.snippet,
                tags: rule.tags.clone(),
                deobfuscated: false,
            });
        }
    }

    findings
}

pub struct Match {
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

impl Match {
    pub fn from_byte_offset(source: &str, offset: usize) -> Self {
        let safe_offset = offset.min(source.len());
        let before = &source[..safe_offset];
        let line = before.matches('\n').count() + 1;
        let column = before.chars().rev().take_while(|&c| c != '\n').count() + 1;
        let line_text = source.lines().nth(line - 1).unwrap_or("");
        let snippet = truncate_utf8_safe(line_text, 120);
        Match { line, column, snippet }
    }
}

fn truncate_utf8_safe(s: &str, max_chars: usize) -> String {
    let truncated: String = s.chars().take(max_chars).collect();
    if truncated.len() < s.len() {
        format!("{truncated}...")
    } else {
        truncated
    }
}
