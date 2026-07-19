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
          _       _ __
   _   __(_)___ _(_) /
  | | / / / __ `/ / /
  | |/ / / /_/ / / /
  |___/_/\__, /_/_/
        /____/        v0.3.0

  supply-chain attack detection · 76 rules


 [CRIT] SC-034   script.js:3    Hardcoded Discord webhook
 [CRIT] SC-034   script.js:4    Hardcoded Discord webhook
 [HIGH] SC-039   script.js:134  Hand-rolled multipart file upload
 [HIGH] SC-039   script.js:137  Hand-rolled multipart file upload
 [HIGH] SC-039   script.js:151  Hand-rolled multipart file upload
 [MED]  SC-018   script.js:197  OS fingerprinting
 [MED]  SC-018   script.js:252  OS fingerprinting
 [LOW]  OBF-006  script.js:3    High-entropy string
 [LOW]  OBF-006  script.js:4    High-entropy string
 [LOW]  SC-001   script.js:197  process.env access (dot)
 [LOW]  SC-001   script.js:197  process.env access (dot)
 [LOW]  SC-001   script.js:253  process.env access (dot)
 [LOW]  SC-001   script.js:253  process.env access (dot)
 [LOW]  SC-007   script.js:130  File system read

 ────────────────────────────────────────────────────────────
 findings   14 total   2 crit · 3 high · 2 med · 7 low
 scanned    1 file · 0 manifests · 9.5 KB · 199ms
 score      42/100 HIGH
 breakdown  Network 25 · Exfiltration 11 · Recon 4 · Obfuscation 1 · Filesystem 1
 tags       #malware #obfuscated #exfiltration #recon
 verdict    BLOCK — likely malicious, do not use

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
3. Scan with 76 built-in rules, on both the raw and the cleaned source. Some
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
