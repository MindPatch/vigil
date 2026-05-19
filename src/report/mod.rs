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

pub fn compute_score(findings: &[Finding]) -> RiskScore {
    let mut raw: u32 = 0;
    let mut cat_points: HashMap<&'static str, (usize, u32)> = HashMap::new();

    for f in findings {
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

    let level = match score {
        0 => "CLEAN",
        1..=15 => "LOW",
        16..=40 => "MEDIUM",
        41..=70 => "HIGH",
        _ => "CRITICAL",
    };

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

pub fn print_text(findings: &[Finding], verbose: bool) {
    if findings.is_empty() {
        println!("{}", "No findings.".green().bold());
        print_score_card(findings);
        return;
    }

    let (crit, high, med, low) = count_by_severity(findings);
    println!(
        "\n{} {} finding(s): {} critical, {} high, {} medium, {} low\n",
        "SCAN COMPLETE:".bold(),
        findings.len(),
        crit.to_string().red().bold(),
        high.to_string().red(),
        med.to_string().yellow(),
        low.to_string().white(),
    );

    for f in findings {
        let sev = match f.severity {
            Severity::Critical => f.severity.to_string().on_red().white().bold(),
            Severity::High => f.severity.to_string().red().bold(),
            Severity::Medium => f.severity.to_string().yellow().bold(),
            Severity::Low => f.severity.to_string().white().bold(),
        };

        let deob_marker = if f.deobfuscated { " [deobfuscated]".magenta().to_string() } else { String::new() };
        println!(
            "[{}] {} {}{} ({})",
            sev,
            f.rule_id.dimmed(),
            f.rule_name.bold(),
            deob_marker,
            f.file,
        );
        println!(
            "     {}:{} {}",
            format!("line {}", f.line).cyan(),
            f.column,
            f.description.dimmed(),
        );

        if verbose {
            println!("     {}", f.snippet.dimmed());
            if !f.tags.is_empty() {
                println!("     tags: {}", f.tags.join(", ").dimmed());
            }
        }

        println!();
    }

    print_score_card(findings);
}

fn print_score_card(findings: &[Finding]) {
    let rs = compute_score(findings);

    let score_colored = match rs.level {
        "CLEAN" => format!("{}/100", rs.score).green().bold(),
        "LOW" => format!("{}/100", rs.score).white().bold(),
        "MEDIUM" => format!("{}/100", rs.score).yellow().bold(),
        "HIGH" => format!("{}/100", rs.score).red().bold(),
        _ => format!("{}/100", rs.score).on_red().white().bold(),
    };

    let level_colored = match rs.level {
        "CLEAN" => rs.level.green().bold(),
        "LOW" => rs.level.white().bold(),
        "MEDIUM" => rs.level.yellow().bold(),
        "HIGH" => rs.level.red().bold(),
        _ => rs.level.on_red().white().bold(),
    };

    println!("{}", "─".repeat(50).dimmed());
    println!("  {} {} [{}]", "RISK SCORE:".bold(), score_colored, level_colored);
    println!();

    for (name, count, pts) in &rs.categories {
        let bar_len = ((*pts as usize) * 20 / 100.max(1)).min(20);
        let bar: String = "█".repeat(bar_len);
        let bar_colored = if *pts >= 25 {
            bar.red().to_string()
        } else if *pts >= 10 {
            bar.yellow().to_string()
        } else {
            bar.white().to_string()
        };
        println!("  {:<14} {:>2} findings  {:>3} pts  {}",
            name, count, pts, bar_colored);
    }

    if !rs.tags.is_empty() {
        println!();
        let tags_str: Vec<String> = rs.tags.iter().map(|t| {
            if t == "#malware" {
                t.red().bold().to_string()
            } else if t == "#exfiltration" || t == "#execution" {
                t.yellow().bold().to_string()
            } else {
                t.cyan().bold().to_string()
            }
        }).collect();
        println!("  {} {}", "TAGS:".bold(), tags_str.join("  "));
    }

    let is_malware = rs.tags.iter().any(|t| t == "#malware");
    let verdict = if is_malware {
        "BLOCK — likely malicious, do not use".on_red().white().bold()
    } else {
        match rs.level {
            "CLEAN" => "PASS — no issues detected".green().bold(),
            "LOW" => "PASS — informational findings only".white().bold(),
            "MEDIUM" => "REVIEW — suspicious patterns detected".yellow().bold(),
            "HIGH" => "INVESTIGATE — high-risk patterns found".red().bold(),
            _ => "BLOCK — likely malicious, do not use".on_red().white().bold(),
        }
    };
    println!();
    println!("  {} {}", "VERDICT:".bold(), verdict);
    println!("{}", "─".repeat(50).dimmed());
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
                        "name": "ankh",
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
