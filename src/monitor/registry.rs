//! npm registry client. Reads declared dependencies, checks for new published
//! versions, and downloads + extracts tarballs for scanning.
//!
//! SAFETY: tarballs are only ever read and statically analyzed. No lifecycle
//! scripts are run, nothing is installed, no JavaScript is executed.

use crate::engine::Finding;
use crate::rules::{CompiledRegex, RuleSet};
use crate::scanner::{self, ScanOptions};
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use tar::Archive;

/// A dependency declared in a package.json.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    /// The version range as written (e.g. "^1.2.3"); informational only.
    pub range: String,
}

/// Read dependency names from a package.json file.
pub fn read_dependencies(manifest_path: &Path) -> Vec<Dependency> {
    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(j) => j,
        Err(_) => return vec![],
    };

    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
            for (name, range) in obj {
                deps.push(Dependency {
                    name: name.clone(),
                    range: range.as_str().unwrap_or("").to_string(),
                });
            }
        }
    }
    deps
}

/// URL-encode a package name for the registry path (scoped names need `%2f`).
fn encode_name(name: &str) -> String {
    name.replace('/', "%2f")
}

/// Look up the latest published version and its tarball URL for a package.
pub fn latest_version(
    registry_url: &str,
    name: &str,
) -> Result<(String, String), String> {
    let url = format!("{}/{}", registry_url.trim_end_matches('/'), encode_name(name));
    let body = ureq::get(&url)
        .set("User-Agent", concat!("vigil/", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(|e| format!("registry request failed: {e}"))?
        .into_string()
        .map_err(|e| format!("registry read failed: {e}"))?;

    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("registry parse failed: {e}"))?;

    let latest = json
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
        .ok_or("no dist-tags.latest in registry response")?
        .to_string();

    let tarball = json
        .get("versions")
        .and_then(|v| v.get(&latest))
        .and_then(|v| v.get("dist"))
        .and_then(|d| d.get("tarball"))
        .and_then(|v| v.as_str())
        .ok_or("no tarball URL for latest version")?
        .to_string();

    Ok((latest, tarball))
}

/// Download a tarball and extract it into a temp directory. Returns the dir.
/// Path traversal entries (`..`, absolute paths) are skipped defensively.
pub fn download_and_extract(
    tarball_url: &str,
    name: &str,
    version: &str,
) -> Result<std::path::PathBuf, String> {
    let resp = ureq::get(tarball_url)
        .set("User-Agent", concat!("vigil/", env!("CARGO_PKG_VERSION")))
        .call()
        .map_err(|e| format!("tarball download failed: {e}"))?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("tarball read failed: {e}"))?;

    let safe_name = name.replace(['/', '@'], "_");
    let dir = std::env::temp_dir().join(format!("vigil-pkg-{safe_name}-{version}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir failed: {e}"))?;

    let gz = GzDecoder::new(&bytes[..]);
    let mut archive = Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("tar read failed: {e}"))?;

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        // Reject path traversal / absolute paths.
        if path.is_absolute() || path.components().any(|c| c.as_os_str() == "..") {
            continue;
        }
        let out_path = dir.join(&path);
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // unpack() writes the file; it does not execute anything.
        let _ = entry.unpack(&out_path);
    }

    Ok(dir)
}

/// Recursively scan an extracted package directory (JS/TS + manifests).
pub fn scan_extracted(
    dir: &Path,
    ruleset: &RuleSet,
    compiled: &[CompiledRegex],
    opts: &ScanOptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if scanner::is_scannable_file(p) {
            findings.extend(scanner::scan_js_file(p, ruleset, compiled, opts));
        } else if scanner::is_manifest_file(p) {
            findings.extend(scanner::scan_manifest_file(p));
        }
    }
    findings
}

/// In-memory record of the last version we observed for each package.
pub type VersionState = BTreeMap<String, String>;
