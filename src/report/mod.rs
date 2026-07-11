use crate::engine::Finding;
use crate::rules::Severity;
use colored::Colorize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

pub struct RiskScore {
    pub score: u32,
    pub level: &'static str,
    pub categories: Vec<(&'static str, usize, u32)>, // (name, count, points)
    pub tags: Vec<String>,
}

/// Map a 0–100 score to its risk level label.
pub fn level_for(score: u32) -> &'static str {
    match score {
        0 => "CLEAN",
        1..=15 => "LOW",
        16..=40 => "MEDIUM",
        41..=70 => "HIGH",
        _ => "CRITICAL",
    }
}

const CATEGORY_MAP: &[(&str, &str)] = &[
    ("obfuscation", "Obfuscation"),
    ("execution", "Execution"),
    ("exfiltration", "Exfiltration"),
    ("network", "Network"),
    ("c2", "Network"),
    ("filesystem", "Filesystem"),
    ("manifest", "Manifest"),
    ("recon", "Recon"),
    ("encoding", "Obfuscation"),
    ("structure", "Obfuscation"),
    ("prototype-pollution", "Execution"),
    ("crypto", "Execution"),
];

impl RiskScore {
    /// Returns true if this score carries the #malware tag.
    pub fn is_malware(&self) -> bool {
        self.tags.iter().any(|t| t == "#malware")
    }

    /// Plain-text verdict string (no ANSI coloring) for JSON/webhook use.
    pub fn verdict(&self) -> &'static str {
        if self.is_malware() {
            return "BLOCK";
        }
        match self.level {
            "CLEAN" | "LOW" => "PASS",
            "MEDIUM" => "REVIEW",
            "HIGH" => "INVESTIGATE",
            _ => "BLOCK",
        }
    }
}

pub fn compute_score(findings: &[Finding]) -> RiskScore {
    let mut raw: u32 = 0;
    let mut cat_points: HashMap<&'static str, (usize, u32)> = HashMap::new();

    // Score by DISTINCT rule, not by occurrence count. A large minified bundle
    // that trips the same rule 100 times is not 100× riskier than tripping it
    // once — counting occurrences let file size, not risk, drive the verdict.
    let mut counted_rules = std::collections::HashSet::new();

    for f in findings {
        if !counted_rules.insert(f.rule_id.as_str()) {
            continue;
        }
        let pts = match f.severity {
            Severity::Critical => 25,
            Severity::High => 10,
            Severity::Medium => 4,
            Severity::Low => 1,
        };
        raw += pts;

        let cat_name = f.tags.iter()
            .find_map(|t| CATEGORY_MAP.iter().find(|(k, _)| k == t).map(|(_, v)| *v))
            .unwrap_or("Other");

        let entry = cat_points.entry(cat_name).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += pts;
    }

    let score = raw.min(100);

    let level = level_for(score);

    let mut categories: Vec<(&'static str, usize, u32)> = cat_points
        .into_iter()
        .map(|(name, (count, pts))| (name, count, pts))
        .collect();
    categories.sort_by(|a, b| b.2.cmp(&a.2));

    let mut tags = Vec::new();

    let has_tag = |tag: &str| findings.iter().any(|f| f.tags.iter().any(|t| t == tag));

    if score >= 71 || findings.iter().any(|f| f.severity == Severity::Critical) {
        tags.push("#malware".into());
    }
    if has_tag("obfuscation") || has_tag("encoding") {
        tags.push("#obfuscated".into());
    }
    if has_tag("exfiltration") || has_tag("c2") {
        tags.push("#exfiltration".into());
    }
    if has_tag("execution") {
        tags.push("#execution".into());
    }
    if has_tag("network") {
        tags.push("#network".into());
    }
    if has_tag("manifest") {
        tags.push("#manifest".into());
    }
    if has_tag("recon") {
        tags.push("#recon".into());
    }
    if score > 0 && score < 71 && !tags.contains(&"#malware".into()) {
        tags.push("#suspicious".into());
    }

    RiskScore { score, level, categories, tags }
}

/// Scan statistics shown in the text-report summary.
pub struct ScanStats {
    pub js_files: usize,
    pub manifest_files: usize,
    pub bytes: u64,
    pub duration: std::time::Duration,
}

pub fn print_text(findings: &[Finding], verbose: bool, stats: &ScanStats) {
    println!();

    if findings.is_empty() {
        println!(" {} no findings", "[OK]".green().bold());
    } else {
        let rule_w = findings.iter().map(|f| f.rule_id.len()).max().unwrap_or(0);
        let loc_w = findings
            .iter()
            .map(|f| location_of(f).len())
            .max()
            .unwrap_or(0)
            .min(56);

        for f in findings {
            let tag = severity_tag(f.severity);
            let deob = if f.deobfuscated {
                format!(" {}", "[deob]".magenta())
            } else {
                String::new()
            };
            println!(
                " {} {}  {}  {}{}",
                tag,
                format!("{:<rule_w$}", f.rule_id).cyan(),
                format!("{:<loc_w$}", location_of(f)),
                f.rule_name.dimmed(),
                deob,
            );

            if verbose {
                println!("        {}", f.description.dimmed());
                let snippet = f.snippet.lines().next().unwrap_or("").trim();
                if !snippet.is_empty() {
                    let shown: String = snippet.chars().take(96).collect();
                    println!("        {}", shown.dimmed());
                }
                if !f.tags.is_empty() {
                    println!("        {}", format!("tags: {}", f.tags.join(", ")).dimmed());
                }
            }
        }
    }

    print_summary(findings, stats);
}

fn severity_tag(sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => format!("{:<6}", "[CRIT]").red().bold(),
        Severity::High => format!("{:<6}", "[HIGH]").red(),
        Severity::Medium => format!("{:<6}", "[MED]").yellow(),
        Severity::Low => format!("{:<6}", "[LOW]").dimmed(),
    }
}

fn location_of(f: &Finding) -> String {
    format!("{}:{}", f.file, f.line)
}

fn print_summary(findings: &[Finding], stats: &ScanStats) {
    let rs = compute_score(findings);
    let (crit, high, med, low) = count_by_severity(findings);

    let count = |n: usize, name: &str, colorize: fn(String) -> String| {
        if n == 0 {
            format!("{n} {name}").dimmed().to_string()
        } else {
            colorize(format!("{n} {name}"))
        }
    };
    let sev_counts = [
        count(crit, "crit", |s| s.red().bold().to_string()),
        count(high, "high", |s| s.red().to_string()),
        count(med, "med", |s| s.yellow().to_string()),
        count(low, "low", |s| s.normal().to_string()),
    ]
    .join(&" · ".dimmed().to_string());

    let score_str = format!("{}/100 {}", rs.score, rs.level);
    let score_colored = match rs.level {
        "CLEAN" => score_str.green().bold(),
        "LOW" => score_str.normal().bold(),
        "MEDIUM" => score_str.yellow().bold(),
        "HIGH" => score_str.red().bold(),
        _ => score_str.red().bold(),
    };

    let verdict = if rs.is_malware() {
        "BLOCK — likely malicious, do not use".red().bold()
    } else {
        match rs.level {
            "CLEAN" => "PASS — no issues detected".green().bold(),
            "LOW" => "PASS — informational findings only".green(),
            "MEDIUM" => "REVIEW — suspicious patterns detected".yellow().bold(),
            "HIGH" => "INVESTIGATE — high-risk patterns found".red().bold(),
            _ => "BLOCK — likely malicious, do not use".red().bold(),
        }
    };

    let label = |s: &str| format!(" {:<10}", s).dimmed();

    println!();
    println!(" {}", "─".repeat(60).dimmed());
    println!(
        "{} {} total   {}",
        label("findings"),
        findings.len(),
        sev_counts
    );
    println!(
        "{} {} file{} · {} manifest{} · {} · {}",
        label("scanned"),
        stats.js_files,
        if stats.js_files == 1 { "" } else { "s" },
        stats.manifest_files,
        if stats.manifest_files == 1 { "" } else { "s" },
        format_bytes(stats.bytes),
        format_duration(stats.duration),
    );
    println!("{} {}", label("score"), score_colored);
    if !rs.categories.is_empty() {
        let cats: Vec<String> = rs
            .categories
            .iter()
            .map(|(name, _, pts)| format!("{name} {pts}"))
            .collect();
        println!(
            "{} {}",
            label("breakdown"),
            cats.join(&" · ".dimmed().to_string()).dimmed()
        );
    }
    if !rs.tags.is_empty() {
        let tags: Vec<String> = rs
            .tags
            .iter()
            .map(|t| {
                if t == "#malware" {
                    t.red().bold().to_string()
                } else if t == "#exfiltration" || t == "#execution" {
                    t.yellow().to_string()
                } else {
                    t.cyan().to_string()
                }
            })
            .collect();
        println!("{} {}", label("tags"), tags.join(" "));
    }
    println!("{} {}", label("verdict"), verdict);
    println!(" {}", "─".repeat(60).dimmed());
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms >= 1000 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", ms)
    }
}

pub fn print_json(findings: &[Finding]) {
    let rs = compute_score(findings);

    let entries: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "description": f.description,
                "severity": f.severity.to_string().to_lowercase(),
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
                "tags": f.tags,
                "deobfuscated": f.deobfuscated,
            })
        })
        .collect();

    let categories: Vec<serde_json::Value> = rs.categories.iter()
        .map(|(name, count, pts)| serde_json::json!({
            "category": name,
            "findings": count,
            "points": pts,
        }))
        .collect();

    let output = serde_json::json!({
        "score": rs.score,
        "risk_level": rs.level.to_lowercase(),
        "verdict": rs.verdict(),
        "tags": rs.tags,
        "categories": categories,
        "findings": entries,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
}

pub fn print_sarif(findings: &[Finding], tool_version: &str) {
    let mut seen_rules = std::collections::HashSet::new();
    let mut rule_descriptors: Vec<serde_json::Value> = Vec::new();
    let mut rule_index_map = std::collections::HashMap::new();

    for f in findings {
        if seen_rules.insert(f.rule_id.clone()) {
            let idx = rule_descriptors.len();
            rule_index_map.insert(f.rule_id.clone(), idx);
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            rule_descriptors.push(serde_json::json!({
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": { "text": f.rule_name },
                "fullDescription": { "text": f.description },
                "defaultConfiguration": { "level": level },
                "properties": { "tags": f.tags }
            }));
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            let uri = to_relative_uri(&f.file);
            let rule_index = rule_index_map.get(&f.rule_id).copied().unwrap_or(0);

            serde_json::json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": f.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column
                            }
                        }
                    }
                ],
                "properties": {
                    "deobfuscated": f.deobfuscated
                }
            })
        })
        .collect();

    let rs = compute_score(findings);

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vigil",
                        "version": tool_version,
                        "rules": rule_descriptors
                    }
                },
                "results": results,
                "properties": {
                    "riskScore": rs.score,
                    "riskLevel": rs.level.to_lowercase(),
                    "tags": rs.tags,
                }
            }
        ]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap_or_default());
}

fn to_relative_uri(path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_relative() {
        path.replace('\\', "/")
    } else if let Ok(cwd) = std::env::current_dir() {
        p.strip_prefix(&cwd)
            .map(|rel| rel.display().to_string().replace('\\', "/"))
            .unwrap_or_else(|_| path.replace('\\', "/"))
    } else {
        path.replace('\\', "/")
    }
}

fn count_by_severity(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
        }
    }
    c
}
