# Vigil

Static analyzer that sees through obfuscated supply-chain malware.

Vigil scans JavaScript/npm packages for supply-chain attacks. Malicious
packages usually hide their payload behind eval, hex escapes or base64, so
Vigil deobfuscates the code first and then runs its rules on the cleaned
source.

**Note: this is beta software.** Expect some false positives and breaking
changes between versions. Review the findings yourself before acting on them.

## Install

Not on crates.io yet, so build it yourself:

```
git clone https://github.com/MindPatch/vigil
cd vigil
cargo build --release
```

You'll need Rust installed, that's it.

## Demo

Point it at a package or any folder:

```
$ vigil ./some-package

 [CRIT] SC-003        malicious.js:30  Network exfiltration
 [CRIT] MANIFEST-001  package.json:1   Malicious install script
 [HIGH] OBF-001       malicious.js:21  eval usage
 [HIGH] SC-011        malicious.js:27  Sensitive file path
 [HIGH] MANIFEST-003  package.json:1   Dependency confusion risk
 [MED]  OBF-005       malicious.js:11  Base64 decode call
 [LOW]  SC-002        malicious.js:3   child_process require

 ────────────────────────────────────────────────────────────
 findings   15 total   2 crit · 3 high · 5 med · 5 low
 scanned    1 file · 1 manifest · 1.3 KB · 10ms
 score      100/100 CRITICAL
 verdict    BLOCK — likely malicious, do not use
 ────────────────────────────────────────────────────────────
```

It exits with code 2 when anything high or above shows up, so in CI you can
just do:

```
vigil ./node_modules/that-new-dep || exit 1
```

Other stuff it does:

```
vigil -d weird.js            # only deobfuscate, print the cleaned source
vigil -f json ./pkg          # machine output (sarif works too)
vigil --manifest-only .      # just check the package.json files
vigil --monitor              # watch mode: file changes + npm registry polling
vigil --baseline ok.json .   # skip findings you already reviewed
```

Watch mode reads a `vigil.toml` (copy [vigil.toml.example](vigil.toml.example)
to get started) and can send alerts to Slack, Discord, Telegram or any
webhook when a scan finds something.

## How it works

Four steps:

1. Parse the JS/TS with tree-sitter to get a proper AST.
2. Deobfuscate. eval wrappers, `Function("...")`, hex and unicode escapes,
   base64 strings, string-array indirection... it keeps making passes until
   the code stops changing. Findings that came out of hidden code get a
   `[deob]` marker so you know.
3. Scan with 47 built-in rules, on both the raw and the cleaned source. Some
   rules are AST-based (say, `child_process` plus a network call in the same
   file), some are plain regex. package.json goes through its own checks for
   install scripts, typosquats and dependency confusion.
4. Everything gets correlated into a 0-100 score and a verdict: OK,
   INVESTIGATE or BLOCK.

The rules are plain TOML in [rules/default.toml](rules/default.toml). Write
your own and pass `--rules`, or run `--list-rules` to see what's active.

## Help

<details>
<summary><code>vigil --help</code></summary>

```
Vigil — Supply chain attack detector with deobfuscation-first static analysis

Usage: vigil [OPTIONS] [PATHS]...

Arguments:
  [PATHS]...  Files or directories to scan

Options:
  -r, --rules <RULES>              Path to custom rules file (TOML)
  -s, --severity <SEVERITY>       Minimum severity to report: low, medium, high, critical [default: low]
  -f, --format <FORMAT>           Output format: text, json, sarif [default: text]
      --verbose                    Show detailed AST context in findings
  -d, --deobfuscate                Deobfuscate files and print cleaned source (no scan)
  -o, --output <OUTPUT>            Write deobfuscated output to this directory
      --no-deobfuscate             Skip deobfuscation before scanning (scan raw source only)
      --no-manifest                Skip package.json manifest analysis
      --manifest-only              Only scan package.json manifests (skip JS/TS files)
      --max-file-size <BYTES>      Maximum file size to scan [default: 10485760]
      --exit-threshold <SEVERITY>  Minimum severity for non-zero exit code [default: high]
      --disable <RULES>            Disable specific rules by ID (comma-separated)
  -q, --quiet                      Suppress all output except exit code
      --list-rules                 List all detection rules and exit
      --monitor                    Continuous monitor mode: file watch + registry polling
      --config <CONFIG>            Path to a vigil.toml config
      --notify                     Send one-shot scan results to configured webhooks
      --telegram-chat-ids <TOKEN>  Print recent Telegram chat IDs for a bot token
      --baseline <FILE>            Suppress findings recorded in this baseline file
      --write-baseline             Write current findings as the accepted baseline
  -h, --help                       Print help
  -V, --version                    Print version
```

</details>

## What's next

In rough order:

- Dynamic analysis: run the suspicious package in a sandbox and watch what it
  actually does, instead of only reading the source.
- Keep tuning the rules against real-world malicious packages to cut down
  false positives

## Contributing

Issues and PRs welcome. There's a short [CONTRIBUTING.md](CONTRIBUTING.md)
that explains how work flows here (issue, branch, PR). Please skim it before
opening one.
