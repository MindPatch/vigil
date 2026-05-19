mod deobfuscator;
mod engine;
mod manifest;
mod parser;
mod report;
mod rules;

use clap::Parser as ClapParser;
use colored::Colorize;
use rayon::prelude::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use walkdir::WalkDir;

#[derive(ClapParser)]
#[command(name = "ankh", version, about = "Ankh — Supply chain attack detector with advanced JS deobfuscation")]
struct Cli {
    /// Files or directories to scan
    paths: Vec<PathBuf>,

    /// Path to custom rules file (TOML)
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Minimum severity to report: low, medium, high, critical
    #[arg(short, long, default_value = "low")]
    severity: String,

    /// Output format: text, json, sarif
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Show detailed AST context in findings
    #[arg(long)]
    verbose: bool,

    /// Deobfuscate files and print cleaned source (no scan)
    #[arg(short, long)]
    deobfuscate: bool,

    /// Write deobfuscated output to this directory
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Skip deobfuscation before scanning (scan raw source only)
    #[arg(long)]
    no_deobfuscate: bool,

    /// Skip package.json manifest analysis
    #[arg(long)]
    no_manifest: bool,

    /// Only scan package.json manifests (skip JS/TS files)
    #[arg(long)]
    manifest_only: bool,

    /// Maximum file size in bytes to scan (skip larger files)
    #[arg(long, default_value = "10485760")]
    max_file_size: u64,

    /// Minimum severity to trigger non-zero exit code: low, medium, high, critical
    #[arg(long, default_value = "high")]
    exit_threshold: String,

    /// Disable specific rules by ID (comma-separated)
    #[arg(long, value_delimiter = ',')]
    disable: Vec<String>,

    /// Suppress all output except exit code
    #[arg(short, long)]
    quiet: bool,
}

const BANNER: &str = r"
     _    _   _ _  __ _   _
    / \  | \ | | |/ /| | | |
   / _ \ |  \| | ' / | |_| |
  / ___ \| |\  | . \ |  _  |
 /_/   \_\_| \_|_|\_\|_| |_|
  Supply Chain Attack Detector
";

fn main() {
    let cli = Cli::parse();

    if !cli.deobfuscate || cli.verbose {
        eprintln!("{}", BANNER.cyan());
    }

    if cli.deobfuscate {
        run_deobfuscate(&cli);
        return;
    }

    let ruleset = match &cli.rules {
        Some(path) => match rules::RuleSet::from_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{} Failed to load rules from {}: {}",
                    "error:".red().bold(),
                    path.display(),
                    e
                );
                std::process::exit(1);
            }
        },
        None => rules::RuleSet::default_rules(),
    };

    let min_severity = match cli.severity.as_str() {
        "low" => rules::Severity::Low,
        "medium" => rules::Severity::Medium,
        "high" => rules::Severity::High,
        "critical" => rules::Severity::Critical,
        other => {
            eprintln!(
                "{} Unknown severity '{}'. Use: low, medium, high, critical",
                "error:".red().bold(),
                other
            );
            std::process::exit(1);
        }
    };

    let paths = resolve_paths(&cli.paths);
    let ignore_set = load_ankhignore(&paths);

    // Collect all scannable files
    let mut js_files: Vec<PathBuf> = Vec::new();
    let mut manifest_files: Vec<PathBuf> = Vec::new();

    for path in &paths {
        if path.is_file() {
            let p = path.to_path_buf();
            if is_ignored_by_ankhignore(&p, &ignore_set) {
                continue;
            }
            if is_scannable_file(path) {
                js_files.push(p);
            } else if is_manifest_file(path) {
                manifest_files.push(p);
            }
        } else {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_entry(|e| !is_ignored_dir(e))
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let p = entry.into_path();
                    if is_ignored_by_ankhignore(&p, &ignore_set) {
                        continue;
                    }
                    if is_scannable_file(&p) {
                        js_files.push(p);
                    } else if is_manifest_file(&p) {
                        manifest_files.push(p);
                    }
                }
            }
        }
    }

    // Pre-compile regexes once — shared across all rayon threads
    let compiled = ruleset.compile();

    let mut all_findings: Vec<engine::Finding> = Vec::new();

    // Scan JS/TS files in parallel with rayon (skip if --manifest-only)
    if !cli.manifest_only {
        let findings_mutex = Mutex::new(Vec::new());

        js_files.par_iter().for_each(|path| {
            let findings = scan_file(path, &ruleset, &compiled, &cli);
            if !findings.is_empty() {
                findings_mutex
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(findings);
            }
        });

        all_findings = findings_mutex
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
    }

    // Scan package.json manifests
    if !cli.no_manifest || cli.manifest_only {
        for manifest_path in &manifest_files {
            match manifest::analyze(manifest_path) {
                Ok(mfindings) => {
                    for mf in mfindings {
                        let severity = match mf.severity.as_str() {
                            "critical" => rules::Severity::Critical,
                            "high" => rules::Severity::High,
                            "medium" => rules::Severity::Medium,
                            _ => rules::Severity::Low,
                        };
                        all_findings.push(engine::Finding {
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
                        });
                    }
                }
                Err(e) => {
                    if cli.verbose {
                        eprintln!(
                            "{} manifest {}: {}",
                            "warn:".yellow().bold(),
                            manifest_path.display(),
                            e
                        );
                    }
                }
            }
        }
    }

    // Filter, dedup, sort
    all_findings.retain(|f| f.severity >= min_severity);
    if !cli.disable.is_empty() {
        all_findings.retain(|f| !cli.disable.contains(&f.rule_id));
    }
    dedup_findings(&mut all_findings);
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    if !cli.quiet {
        match cli.format.as_str() {
            "json" => report::print_json(&all_findings),
            "sarif" => report::print_sarif(&all_findings, env!("CARGO_PKG_VERSION")),
            _ => report::print_text(&all_findings, cli.verbose),
        }
    }

    let exit_severity = match cli.exit_threshold.as_str() {
        "low" => rules::Severity::Low,
        "medium" => rules::Severity::Medium,
        "critical" => rules::Severity::Critical,
        _ => rules::Severity::High,
    };

    if all_findings.iter().any(|f| f.severity >= exit_severity) {
        std::process::exit(2);
    }
}

fn run_deobfuscate(cli: &Cli) {
    let paths = resolve_paths(&cli.paths);
    let ignore_set = load_ankhignore(&paths);

    for_each_scannable_file(&paths, &ignore_set, |path| {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} Cannot read {}: {}",
                    "warn:".yellow().bold(),
                    path.display(),
                    e
                );
                return;
            }
        };

        let mut result = deobfuscator::deobfuscate(&source);
        result.source = pretty_print_js(&result.source);

        if cli.verbose {
            eprintln!(
                "{} {} — {} transforms applied",
                "deob:".green().bold(),
                path.display(),
                result
                    .transforms_applied
                    .iter()
                    .map(|t| t.changes)
                    .sum::<usize>(),
            );
            for t in &result.transforms_applied {
                if t.changes > 0 {
                    eprintln!("  {} {}: {} changes", "->".dimmed(), t.pass_name, t.changes);
                }
            }
        }

        match &cli.output {
            Some(out_dir) => {
                let filename = path.file_name().unwrap_or_default();
                let out_path = out_dir.join(filename);
                if let Err(e) = std::fs::create_dir_all(out_dir) {
                    eprintln!(
                        "{} Cannot create {}: {}",
                        "error:".red().bold(),
                        out_dir.display(),
                        e
                    );
                    return;
                }
                if let Err(e) = std::fs::write(&out_path, &result.source) {
                    eprintln!(
                        "{} Cannot write {}: {}",
                        "error:".red().bold(),
                        out_path.display(),
                        e
                    );
                } else if cli.verbose {
                    eprintln!("  {} {}", "wrote:".green(), out_path.display());
                }
            }
            None => {
                println!("// === {} ===", path.display());
                println!("{}", result.source);
            }
        }
    });
}

fn scan_file(
    path: &std::path::Path,
    ruleset: &rules::RuleSet,
    compiled: &[rules::CompiledRegex],
    cli: &Cli,
) -> Vec<engine::Finding> {
    // Skip files exceeding max size
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > cli.max_file_size {
            if cli.verbose {
                eprintln!(
                    "{} Skipping {} ({}B > {}B max)",
                    "warn:".yellow().bold(),
                    path.display(),
                    meta.len(),
                    cli.max_file_size,
                );
            }
            return vec![];
        }
    }

    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{} Cannot read {}: {}",
                "warn:".yellow().bold(),
                path.display(),
                e
            );
            return vec![];
        }
    };

    let mut findings = Vec::new();

    // Check for inline suppression comments in source
    let suppressed_lines = collect_suppressed_lines(&source);

    // Scan original source
    if let Some(tree) = parser::parse_auto(&source, path) {
        let mut file_findings = engine::scan(&source, &tree, ruleset, path, compiled);
        file_findings.retain(|f| !suppressed_lines.contains(&f.line));
        findings.extend(file_findings);
    }

    // Deobfuscate and scan deobfuscated source
    if !cli.no_deobfuscate {
        let deob_result = deobfuscator::deobfuscate(&source);
        if deob_result
            .transforms_applied
            .iter()
            .any(|t| t.changes > 0)
        {
            if cli.verbose {
                let total: usize = deob_result
                    .transforms_applied
                    .iter()
                    .map(|t| t.changes)
                    .sum();
                eprintln!(
                    "{} {} — deobfuscated ({} transforms)",
                    "deob:".green().bold(),
                    path.display(),
                    total,
                );
            }

            if let Some(tree) = parser::parse_auto(&deob_result.source, path) {
                let deob_suppressed = collect_suppressed_lines(&deob_result.source);
                let mut deob_findings =
                    engine::scan(&deob_result.source, &tree, ruleset, path, compiled);
                deob_findings.retain(|f| !deob_suppressed.contains(&f.line));
                for f in &mut deob_findings {
                    f.deobfuscated = true;
                }
                findings.extend(deob_findings);
            }
        }
    }

    findings
}

/// Collect line numbers that have `// ankh-ignore` on the previous line or same line.
fn collect_suppressed_lines(source: &str) -> HashSet<usize> {
    let mut suppressed = HashSet::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("ankh-ignore-next-line") {
            suppressed.insert(i + 2); // next line (1-indexed)
        }
        if trimmed.contains("ankh-ignore-line") {
            suppressed.insert(i + 1); // same line
        }
    }
    suppressed
}

/// Deduplicate findings using content-based keys instead of line numbers.
fn dedup_findings(findings: &mut Vec<engine::Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.dedup_key()));
}

fn resolve_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    }
}

fn for_each_scannable_file(
    paths: &[PathBuf],
    ignore_set: &HashSet<PathBuf>,
    mut callback: impl FnMut(&std::path::Path),
) {
    for path in paths {
        if path.is_file() {
            if is_scannable_file(path) && !is_ignored_by_ankhignore(path, ignore_set) {
                callback(path);
            }
        } else {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_entry(|e| !is_ignored_dir(e))
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let p = entry.path();
                    if is_scannable_file(p) && !is_ignored_by_ankhignore(p, ignore_set) {
                        callback(p);
                    }
                }
            }
        }
    }
}

fn is_scannable_file(path: &std::path::Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".d.ts")
        || name.ends_with(".d.cts")
        || name.ends_with(".d.mts")
    {
        return false;
    }
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx")
    )
}

fn is_manifest_file(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |n| n == "package.json")
}

fn is_ignored_dir(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_str().unwrap_or("");
    matches!(
        name,
        "node_modules" | ".git" | "dist" | "build" | ".next" | "vendor" | ".ankh-cache"
    )
}

/// Load .ankhignore file (gitignore-style glob patterns, one per line).
fn load_ankhignore(paths: &[PathBuf]) -> HashSet<PathBuf> {
    let mut ignored = HashSet::new();

    for path in paths {
        let base = if path.is_file() {
            path.parent().unwrap_or(path)
        } else {
            path.as_path()
        };

        let ignore_file = base.join(".ankhignore");
        if let Ok(content) = std::fs::read_to_string(&ignore_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Ok(entries) = glob::glob(&format!("{}/{}", base.display(), line)) {
                    for entry in entries.flatten() {
                        let canonical = entry.canonicalize().unwrap_or(entry);
                        ignored.insert(canonical);
                    }
                }
            }
        }
    }

    ignored
}

fn is_ignored_by_ankhignore(path: &std::path::Path, ignore_set: &HashSet<PathBuf>) -> bool {
    if ignore_set.is_empty() {
        return false;
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    ignore_set.contains(&canonical)
}

fn pretty_print_js(source: &str) -> String {
    let mut out = String::with_capacity(source.len() * 2);
    let mut indent: usize = 0;
    let chars: Vec<char> = source.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string: Option<char> = None;
    let mut escape = false;
    let mut line_has_content = false;

    while i < len {
        let c = chars[i];

        if escape {
            out.push(c);
            escape = false;
            i += 1;
            continue;
        }

        if in_string.is_some() {
            out.push(c);
            if c == '\\' {
                escape = true;
            } else if Some(c) == in_string {
                in_string = None;
            }
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' || c == '`' {
            in_string = Some(c);
            out.push(c);
            line_has_content = true;
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < len && chars[i + 1] == '/' {
            while i < len && chars[i] != '\n' {
                out.push(chars[i]);
                i += 1;
            }
            continue;
        }

        if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            while i + 1 < len {
                out.push(chars[i]);
                if chars[i] == '*' && chars[i + 1] == '/' {
                    out.push('/');
                    i += 2;
                    break;
                }
                i += 1;
            }
            line_has_content = true;
            continue;
        }

        match c {
            '{' => {
                out.push('{');
                indent += 1;
                out.push('\n');
                push_indent(&mut out, indent);
                line_has_content = false;
                i += 1;
            }
            '}' => {
                indent = indent.saturating_sub(1);
                if line_has_content {
                    out.push('\n');
                }
                push_indent(&mut out, indent);
                out.push('}');
                let mut j = i + 1;
                while j < len && (chars[j] == ' ' || chars[j] == '\t') {
                    j += 1;
                }
                while j < len && (chars[j] == ')' || chars[j] == ';' || chars[j] == ',') {
                    out.push(chars[j]);
                    j += 1;
                }
                i = j;
                let rest: String = chars[i..].iter().collect::<String>();
                let trimmed = rest.trim_start();
                if trimmed.starts_with("else")
                    || trimmed.starts_with("catch")
                    || trimmed.starts_with("finally")
                {
                    out.push(' ');
                    line_has_content = true;
                } else {
                    out.push('\n');
                    line_has_content = false;
                }
            }
            ',' => {
                out.push(',');
                if indent > 0 {
                    out.push('\n');
                    push_indent(&mut out, indent);
                    line_has_content = false;
                } else {
                    out.push(' ');
                }
                i += 1;
            }
            ';' => {
                out.push(';');
                let in_for = {
                    let mut paren_depth = 0i32;
                    let mut found = false;
                    for &cb in out.as_bytes().iter().rev() {
                        if cb == b')' {
                            paren_depth += 1;
                        } else if cb == b'(' {
                            paren_depth -= 1;
                            if paren_depth < 0 {
                                found = true;
                                break;
                            }
                        } else if cb == b'\n' || cb == b'{' || cb == b'}' {
                            break;
                        }
                    }
                    found
                };
                if !in_for {
                    out.push('\n');
                    push_indent(&mut out, indent);
                    line_has_content = false;
                } else {
                    out.push(' ');
                    line_has_content = true;
                }
                i += 1;
            }
            '\n' | '\r' => {
                i += 1;
            }
            ' ' | '\t' => {
                if line_has_content {
                    out.push(' ');
                }
                i += 1;
            }
            _ => {
                out.push(c);
                line_has_content = true;
                i += 1;
            }
        }
    }

    let mut cleaned = String::with_capacity(out.len());
    let mut prev_blank = false;
    for line in out.lines() {
        let blank = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
        prev_blank = blank;
    }

    cleaned.trim_end().to_string()
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}
