//! Long-running monitor. Two threat sources feed one notification pipeline:
//!
//!   1. File watch  — re-scan local files/manifests whenever they change.
//!   2. Registry poll — periodically check the npm registry for new versions of
//!      declared dependencies, download + statically scan each new release.
//!
//! New findings are diffed against prior state and dispatched to webhooks
//! (generic JSON, Slack, Discord, or Telegram).

mod registry;

use crate::config::Config;
use crate::engine::Finding;
use crate::rules::{CompiledRegex, RuleSet};
use crate::scanner::{self, ScanOptions};
use crate::webhook::{self, ScanOutcome};
use colored::Colorize;
use notify::{RecursiveMode, Watcher};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

pub struct Monitor {
    config: Config,
    ruleset: RuleSet,
    compiled: Vec<CompiledRegex>,
    opts: ScanOptions,
    /// Last observed registry version per package.
    versions: registry::VersionState,
    /// Last set of finding dedup-keys per subject, for diffing.
    seen: BTreeMap<String, HashSet<String>>,
}

impl Monitor {
    pub fn new(config: Config, ruleset: RuleSet, opts: ScanOptions) -> Self {
        let compiled = ruleset.compile();
        Monitor {
            config,
            ruleset,
            compiled,
            opts,
            versions: BTreeMap::new(),
            seen: BTreeMap::new(),
        }
    }

    /// Run the monitor loop. Blocks until interrupted (Ctrl-C).
    pub fn run(&mut self) {
        let interval = self.config.monitor.interval_duration();
        println!(
            "{} watching {} path(s){}  •  {} webhook(s)",
            "MONITOR".green().bold(),
            self.config.monitor.paths.len(),
            if self.config.monitor.registry {
                format!("  •  registry poll every {}", self.config.monitor.interval)
            } else {
                String::new()
            },
            self.config.webhooks.len(),
        );

        // Set up the filesystem watcher (if enabled).
        let (tx, rx) = mpsc::channel();
        let mut watcher = if self.config.monitor.watch {
            match notify::recommended_watcher(move |res| {
                let _ = tx.send(res);
            }) {
                Ok(mut w) => {
                    for p in &self.config.monitor.paths {
                        if let Err(e) = w.watch(p, RecursiveMode::Recursive) {
                            eprintln!("{} cannot watch {}: {e}", "warn:".yellow(), p.display());
                        }
                    }
                    Some(w)
                }
                Err(e) => {
                    eprintln!("{} file watcher unavailable: {e}", "warn:".yellow());
                    None
                }
            }
        } else {
            None
        };
        let _ = &mut watcher; // keep alive for the loop's lifetime

        // Baseline registry scan so a currently-malicious dependency is caught
        // immediately, not only on its next release.
        if self.config.monitor.registry {
            self.poll_registry(true);
        }

        let mut next_poll = Instant::now() + interval;

        loop {
            let timeout = next_poll.saturating_duration_since(Instant::now());
            match rx.recv_timeout(timeout) {
                Ok(Ok(event)) => self.handle_fs_event(event),
                Ok(Err(e)) => eprintln!("{} watch error: {e}", "warn:".yellow()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.config.monitor.registry {
                        self.poll_registry(false);
                    }
                    next_poll = Instant::now() + interval;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // No watcher (or it died): just sleep-poll on the interval.
                    std::thread::sleep(interval);
                    if self.config.monitor.registry {
                        self.poll_registry(false);
                    }
                    next_poll = Instant::now() + interval;
                }
            }
        }
    }

    /// A file changed: re-scan it and report any newly-appeared findings.
    fn handle_fs_event(&mut self, event: notify::Event) {
        for path in event.paths {
            if scanner::is_scannable_file(&path) {
                let findings =
                    scanner::scan_js_file(&path, &self.ruleset, &self.compiled, &self.opts);
                self.report_subject(path.display().to_string(), findings);
            } else if scanner::is_manifest_file(&path) {
                let findings = scanner::scan_manifest_file(&path);
                self.report_subject(path.display().to_string(), findings);
            }
        }
    }

    /// Poll the registry for each declared dependency's latest version.
    fn poll_registry(&mut self, baseline: bool) {
        let manifests = self.find_manifests();
        let mut deps: BTreeMap<String, String> = BTreeMap::new();
        for m in &manifests {
            for d in registry::read_dependencies(m) {
                deps.entry(d.name).or_insert(d.range);
            }
        }

        if deps.is_empty() {
            return;
        }

        if baseline {
            println!(
                "{} baseline scan of {} dependenc{}…",
                "MONITOR".green().bold(),
                deps.len(),
                if deps.len() == 1 { "y" } else { "ies" }
            );
        }

        let registry_url = self.config.monitor.registry_url.clone();
        for (name, _range) in deps {
            let (version, tarball) = match registry::latest_version(&registry_url, &name) {
                Ok(v) => v,
                Err(e) => {
                    if self.opts.verbose {
                        eprintln!("{} {name}: {e}", "warn:".yellow());
                    }
                    continue;
                }
            };

            let changed = self.versions.get(&name) != Some(&version);
            self.versions.insert(name.clone(), version.clone());

            // On a normal poll, skip packages whose version hasn't changed.
            if !baseline && !changed {
                continue;
            }

            let dir = match registry::download_and_extract(&tarball, &name, &version) {
                Ok(d) => d,
                Err(e) => {
                    if self.opts.verbose {
                        eprintln!("{} {name}@{version}: {e}", "warn:".yellow());
                    }
                    continue;
                }
            };

            let findings =
                registry::scan_extracted(&dir, &self.ruleset, &self.compiled, &self.opts);
            let _ = std::fs::remove_dir_all(&dir);

            let subject = format!("{name}@{version}");
            self.report_subject(subject, findings);
        }
    }

    /// Build an outcome, fire webhooks on NEW findings, and print a status line.
    fn report_subject(&mut self, subject: String, findings: Vec<Finding>) {
        let findings = dedup(findings);

        // Diff against previously-seen findings for this subject.
        let keys: HashSet<String> = findings.iter().map(|f| f.dedup_key()).collect();
        let prev = self.seen.get(&subject).cloned().unwrap_or_default();
        let has_new = keys.iter().any(|k| !prev.contains(k));
        self.seen.insert(subject.clone(), keys);

        let outcome = ScanOutcome::new(subject.clone(), findings);

        if outcome.findings.is_empty() {
            if self.opts.verbose {
                println!("  {} {} — clean", "ok".green(), subject);
            }
            return;
        }

        // Filesystem watchers emit several events per save; only surface a
        // result when it contains a genuinely-new finding (or in verbose mode).
        if !has_new && !self.opts.verbose {
            return;
        }

        let verdict = outcome.score.verdict();
        let badge = match verdict {
            "BLOCK" => verdict.on_red().white().bold(),
            "INVESTIGATE" => verdict.red().bold(),
            "REVIEW" => verdict.yellow().bold(),
            _ => verdict.white().bold(),
        };
        println!(
            "  {} {} — {} finding(s), score {}/100 [{}]{}",
            badge,
            subject,
            outcome.findings.len(),
            outcome.score.score,
            outcome.score.level,
            if has_new {
                "  (new)".cyan().to_string()
            } else {
                String::new()
            },
        );

        // Only notify when something new appeared, to avoid repeat spam.
        if has_new {
            self.dispatch_webhooks(&outcome);
        }
    }

    fn dispatch_webhooks(&self, outcome: &ScanOutcome) {
        if self.config.webhooks.is_empty() {
            return;
        }
        let results = webhook::dispatch(&self.config.webhooks, outcome);
        for r in results {
            match r.outcome {
                Ok(code) => {
                    if self.opts.verbose {
                        println!("    {} {} ({})", "→ webhook".cyan(), r.url, code);
                    }
                }
                Err(e) => eprintln!("    {} {} — {e}", "webhook failed:".red(), r.url),
            }
        }
    }

    fn find_manifests(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for base in &self.config.monitor.paths {
            for entry in walkdir::WalkDir::new(base)
                .into_iter()
                .filter_entry(|e| {
                    let n = e.file_name().to_str().unwrap_or("");
                    !matches!(n, "node_modules" | ".git" | "dist" | "build")
                })
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() && scanner::is_manifest_file(entry.path()) {
                    out.push(entry.into_path());
                }
            }
        }
        out
    }
}

fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert(f.dedup_key()))
        .collect()
}
