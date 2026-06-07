use super::Match;
use crate::rules::{CompiledRegex, Rule};
use tree_sitter::{Node, Tree};

/// Window (in bytes) around a primary match within which the secondary pattern
/// must also appear. File-wide correlation produces false positives on large
/// bundles (e.g. `fetch(` and the word `token` appearing in unrelated code), so
/// correlation is local: the two signals must be near each other.
const CORRELATION_WINDOW: usize = 400;

pub fn match_regex_compiled(source: &str, _rule: &Rule, compiled: &CompiledRegex) -> Vec<Match> {
    let re = match &compiled.primary {
        Some(r) => r,
        None => return vec![],
    };

    let mut results = Vec::new();

    match &compiled.secondary {
        // Correlated rule: secondary must appear within a local window of each
        // primary match, not just somewhere in the file.
        Some(re2) => {
            for m in re.find_iter(source) {
                let lo = snap_lo(source, m.start().saturating_sub(CORRELATION_WINDOW));
                let hi = snap_hi(source, m.end() + CORRELATION_WINDOW);
                if re2.is_match(&source[lo..hi]) {
                    results.push(Match::from_byte_offset(source, m.start()));
                }
            }
        }
        None => {
            for m in re.find_iter(source) {
                results.push(Match::from_byte_offset(source, m.start()));
            }
        }
    }

    results
}

/// Snap a byte index down to the nearest UTF-8 char boundary.
fn snap_lo(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Snap a byte index up to the nearest UTF-8 char boundary.
fn snap_hi(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub fn match_call_expr(source: &str, tree: &Tree, rule: &Rule) -> Vec<Match> {
    let mut results = Vec::new();
    walk_iterative(tree, |node| {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let range = func.byte_range();
                if range.end > source.len() {
                    return;
                }
                let text = &source[range];
                if text == rule.pattern {
                    results.push(Match::from_byte_offset(source, node.start_byte()));
                }
            }
        }
    });
    results
}

pub fn match_ast_node(source: &str, tree: &Tree, rule: &Rule) -> Vec<Match> {
    let mut results = Vec::new();
    let parts: Vec<&str> = rule.pattern.splitn(2, ':').collect();
    let (node_type, identifier) = if parts.len() == 2 {
        (parts[0], Some(parts[1]))
    } else {
        (parts[0], None)
    };

    walk_iterative(tree, |node| {
        if node.kind() == node_type {
            if let Some(ident) = identifier {
                if let Some(first_child) = node.named_child(0) {
                    let range = first_child.byte_range();
                    if range.end > source.len() {
                        return;
                    }
                    let child_text = &source[range];
                    if child_text == ident {
                        results.push(Match::from_byte_offset(source, node.start_byte()));
                    }
                }
            } else {
                results.push(Match::from_byte_offset(source, node.start_byte()));
            }
        }
    });
    results
}

pub fn match_member_expr(source: &str, tree: &Tree, rule: &Rule) -> Vec<Match> {
    let mut results = Vec::new();
    walk_iterative(tree, |node| {
        if node.kind() == "member_expression" {
            let range = node.byte_range();
            if range.end > source.len() {
                return;
            }
            let text = &source[range];
            if text == rule.pattern || text.starts_with(&format!("{}.", rule.pattern)) {
                results.push(Match::from_byte_offset(source, node.start_byte()));
            }
        }
    });
    results
}

/// Match bracket notation: process["env"], window["eval"], etc.
pub fn match_subscript_expr(source: &str, tree: &Tree, rule: &Rule) -> Vec<Match> {
    let parts: Vec<&str> = rule.pattern.split('.').collect();
    if parts.is_empty() {
        return vec![];
    }

    let mut results = Vec::new();
    walk_iterative(tree, |node| {
        if node.kind() == "subscript_expression" {
            if matches_dotted_pattern(source, node, &parts) {
                results.push(Match::from_byte_offset(source, node.start_byte()));
            }
        }
    });
    results
}

/// Iteratively check if a node matches a dotted pattern like "process.env"
/// handling both dot notation and bracket notation. Stack-safe.
fn matches_dotted_pattern(source: &str, node: &Node, parts: &[&str]) -> bool {
    if parts.is_empty() {
        return false;
    }

    let mut current = *node;
    let mut remaining = parts.len();

    loop {
        if remaining == 1 {
            let range = current.byte_range();
            if range.end > source.len() {
                return false;
            }
            return &source[range] == parts[0];
        }
        if remaining < 2 {
            return false;
        }

        let expected_prop = parts[remaining - 1];

        match current.kind() {
            "member_expression" => {
                let (obj, prop) = match (
                    current.child_by_field_name("object"),
                    current.child_by_field_name("property"),
                ) {
                    (Some(o), Some(p)) => (o, p),
                    _ => return false,
                };
                let range = prop.byte_range();
                if range.end > source.len() {
                    return false;
                }
                if &source[range] != expected_prop {
                    return false;
                }
                remaining -= 1;
                current = obj;
            }
            "subscript_expression" => {
                let (obj, index) = match (
                    current.child_by_field_name("object"),
                    current.child_by_field_name("index"),
                ) {
                    (Some(o), Some(i)) => (o, i),
                    _ => return false,
                };
                let range = index.byte_range();
                if range.end > source.len() {
                    return false;
                }
                let index_text = &source[range];
                let unquoted = index_text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if unquoted != expected_prop {
                    return false;
                }
                remaining -= 1;
                current = obj;
            }
            _ => return false,
        }
    }
}

pub fn match_entropy(source: &str, tree: &Tree, rule: &Rule) -> Vec<Match> {
    let threshold = rule.threshold.unwrap_or(4.5);
    let mut results = Vec::new();
    walk_iterative(tree, |node| {
        if node.kind() == "string" || node.kind() == "template_string" {
            let range = node.byte_range();
            if range.end > source.len() {
                return;
            }
            let text = &source[range];
            let inner = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            if inner.len() >= 16 && shannon_entropy(inner) > threshold {
                results.push(Match::from_byte_offset(source, node.start_byte()));
            }
        }
    });
    results
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *freq.entry(c).or_insert(0u32) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    freq.values()
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn match_long_line(source: &str, rule: &Rule) -> Vec<Match> {
    let threshold = rule.threshold.unwrap_or(1000.0) as usize;
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.len() > threshold)
        .map(|(i, line)| {
            let snippet = super::truncate_utf8_safe(line, 120);
            Match {
                line: i + 1,
                column: 1,
                snippet,
            }
        })
        .collect()
}

/// Stack-safe iterative tree walk — no recursion, no stack overflow on deep ASTs.
fn walk_iterative(tree: &Tree, mut callback: impl FnMut(&Node)) {
    let mut cursor = tree.walk();
    let mut did_visit = false;

    loop {
        if !did_visit {
            callback(&cursor.node());
        }

        if !did_visit && cursor.goto_first_child() {
            did_visit = false;
            continue;
        }

        if cursor.goto_next_sibling() {
            did_visit = false;
            continue;
        }

        if !cursor.goto_parent() {
            break;
        }
        did_visit = true;
    }
}

