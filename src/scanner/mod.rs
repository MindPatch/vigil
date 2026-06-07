//! Reusable scanning primitives shared by the one-shot CLI scan and the
//! long-running monitor. These functions are `Send`-safe (no Lua), so they can
//! run inside rayon; Lua custom rules are applied in a separate sequential pass.

use crate::deobfuscator;
use crate::engine::{self, Finding};
use crate::manifest;
use crate::parser;
use crate::rules::{self, CompiledRegex, RuleSet};
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub no_deobfuscate: bool,
    pub max_file_size: u64,
    pub verbose: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            no_deobfuscate: false,
            max_file_size: 10 * 1024 * 1024,
            verbose: false,
        }
    }
}

/// Scan a single JS/TS file: regex/AST rules on the original source, then again
/// on the deobfuscated source. Returns all findings (Lua rules not included).
pub fn scan_js_file(
    path: &Path,
    ruleset: &RuleSet,
    compiled: &[CompiledRegex],
    opts: &ScanOptions,
) -> Vec<Finding> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > opts.max_file_size {
            if opts.verbose {
                eprintln!("warn: skipping {} (exceeds max size)", path.display());
            }
            return vec![];
        }
    }

    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warn: cannot read {}: {e}", path.display());
            return vec![];
        }
    };

    scan_source(&source, path, ruleset, compiled, opts)
}

/// Scan in-memory source: regex/AST rules on the original, then on the
/// deobfuscated source. The single source of truth for both file and string
/// scanning (used by tests and the registry tarball scanner).
pub fn scan_source(
    source: &str,
    path: &Path,
    ruleset: &RuleSet,
    compiled: &[CompiledRegex],
    opts: &ScanOptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let suppressed = collect_suppressed_lines(source);

    if let Some(tree) = parser::parse_auto(source, path) {
        let mut f = engine::scan(source, &tree, ruleset, path, compiled);
        f.retain(|x| !suppressed.contains(&x.line));
        findings.extend(f);
    }

    if !opts.no_deobfuscate {
        let deob = deobfuscator::deobfuscate(source);
        if deob.transforms_applied.iter().any(|t| t.changes > 0) {
            if let Some(tree) = parser::parse_auto(&deob.source, path) {
                let deob_suppressed = collect_suppressed_lines(&deob.source);
                let mut f = engine::scan(&deob.source, &tree, ruleset, path, compiled);
                f.retain(|x| !deob_suppressed.contains(&x.line));
                for x in &mut f {
                    x.deobfuscated = true;
                }
                findings.extend(f);
            }
        }
    }

    findings
}

/// Analyze a package.json manifest, mapping manifest findings to engine Findings.
pub fn scan_manifest_file(path: &Path) -> Vec<Finding> {
    match manifest::analyze(path) {
        Ok(mfindings) => mfindings
            .into_iter()
            .map(|mf| {
                let severity = match mf.severity.as_str() {
                    "critical" => rules::Severity::Critical,
                    "high" => rules::Severity::High,
                    "medium" => rules::Severity::Medium,
                    _ => rules::Severity::Low,
                };
                Finding {
                    rule_id: mf.rule_id,
                    rule_name: mf.name,
                    description: mf.description,
                    severity,
                    file: mf.file,
                    line: 1,
                    column: 1,
                    snippet: mf.detail,
                    tags: vec!["supply-chain".into(), "manifest".into()],
                    deobfuscated: false,
                }
            })
            .collect(),
        Err(_) => vec![],
    }
}

/// Collect line numbers suppressed by `// vigil-ignore` comments.
pub fn collect_suppressed_lines(source: &str) -> HashSet<usize> {
    let mut suppressed = HashSet::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("vigil-ignore-next-line") {
            suppressed.insert(i + 2);
        }
        if trimmed.contains("vigil-ignore-line") {
            suppressed.insert(i + 1);
        }
    }
    suppressed
}

pub fn is_scannable_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".d.ts") || name.ends_with(".d.cts") || name.ends_with(".d.mts") {
        return false;
    }
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx")
    )
}

pub fn is_manifest_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |n| n == "package.json")
}
