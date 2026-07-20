import { CommandBlock, ExtLink, SectionHeading } from '@/components/ui-kit'

const FLAGS: [string, string][] = [
  ['[PATHS]...', 'Files or directories to scan'],
  ['-r, --rules <RULES>', 'Path to custom rules file (TOML)'],
  ['-s, --severity <SEVERITY>', 'Minimum severity to report: low, medium, high, critical (default: low)'],
  ['-f, --format <FORMAT>', 'Output format: text, json, sarif (default: text)'],
  ['--verbose', 'Show detailed AST context in findings'],
  ['-d, --deobfuscate', 'Deobfuscate files and print cleaned source (no scan)'],
  ['-o, --output <OUTPUT>', 'Write deobfuscated output to this directory'],
  ['--no-deobfuscate', 'Skip deobfuscation before scanning (raw source only)'],
  ['--no-manifest', 'Skip package.json manifest analysis'],
  ['--manifest-only', 'Only scan package.json manifests (skip JS/TS files)'],
  ['--max-file-size <BYTES>', 'Maximum file size to scan (default: 10485760)'],
  ['--exit-threshold <SEVERITY>', 'Minimum severity for non-zero exit code (default: high)'],
  ['--disable <RULES>', 'Disable specific rules by ID (comma-separated)'],
  ['-q, --quiet', 'Suppress all output except exit code'],
  ['--list-rules', 'List all detection rules and exit'],
  ['--monitor', 'Continuous monitor mode: file watch + registry polling'],
  ['--config <CONFIG>', 'Path to a vigil.toml config'],
  ['--notify', 'Send one-shot scan results to configured webhooks'],
  ['--telegram-chat-ids <TOKEN>', 'Print recent Telegram chat IDs for a bot token'],
  ['--baseline <FILE>', 'Suppress findings recorded in this baseline file'],
  ['--write-baseline', 'Write current findings as the accepted baseline'],
]

export function CliReference() {
  return (
    <section id="cli" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="令" index="05 — reference" title="CLI reference" sub="vigil [OPTIONS] [PATHS]..." />
      <div className="card-line max-w-4xl overflow-hidden">
        <table className="w-full text-xs">
          <tbody>
            {FLAGS.map(([flag, desc], i) => (
              <tr key={flag} className={i % 2 === 0 ? 'bg-[#12110e]' : 'bg-[#0e0d0b]'}>
                <td className="px-4 py-2.5 align-top whitespace-nowrap text-[#d63a2a] font-medium border-b border-[#201e19]">
                  {flag}
                </td>
                <td className="px-4 py-2.5 text-[#a39d8f] leading-relaxed border-b border-[#201e19]">{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export function WatchMode() {
  return (
    <section id="watch" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="監" index="06 — reference" title="Watch mode" sub="continuous monitoring for your dependency tree" />
      <div className="grid md:grid-cols-2 gap-4 max-w-4xl">
        <CommandBlock title="start the monitor" code={`vigil --monitor\n\n# one-shot scan, push results to webhooks\nvigil --notify ./pkg`} />
        <div className="card-line p-5 text-xs leading-relaxed text-[#a39d8f] space-y-3">
          <p>
            <span className="text-[#e8e2d5]">File watch + registry polling.</span> Watch mode keeps an
            eye on your files and polls the npm registry for changes to packages you depend on.
          </p>
          <p>
            <span className="text-[#e8e2d5]">Alerts anywhere.</span> Configure a{' '}
            <code className="inline">vigil.toml</code> (copy{' '}
            <ExtLink href="https://github.com/MindPatch/vigil/blob/master/vigil.toml.example">vigil.toml.example</ExtLink>)
            and Vigil pushes alerts to Slack, Discord, Telegram or any webhook when a scan finds something.
          </p>
        </div>
      </div>
    </section>
  )
}

const CUSTOM_TOML = `# Custom rules file for Vigil
# pass with: vigil --rules rules/custom.toml

[[rule]]
id = "CUSTOM-001"
name = "Suspicious domain"
description = "Hardcoded request to known malicious staging domain"
severity = "critical"
kind = "regex"
pattern = '''https?://[a-z0-9]{12,}\\.(?:xyz|top|tk|ml|ga|cf)/'''
tags = ["supply-chain", "c2"]

[[rule]]
id = "CUSTOM-002"
name = "Webpack override"
description = "Overriding __webpack_require__ — module hijacking technique"
severity = "high"
kind = "regex"
pattern = '''__webpack_require__\\s*='''
tags = ["supply-chain", "hijack"]`

export function CustomRules() {
  return (
    <section id="custom-rules" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="則" index="07 — reference" title="Custom rules" sub="write your own detections in plain TOML" />
      <div className="max-w-4xl space-y-6">
        <p className="text-xs leading-relaxed text-[#a39d8f] max-w-3xl">
          Rules are plain TOML — an id, a severity, a kind and a pattern. Keep your own pack and load
          it with <code className="inline">--rules</code>, or run{' '}
          <code className="inline">--list-rules</code> to see everything that is active. The example
          below is the one shipped in{' '}
          <ExtLink href="https://github.com/MindPatch/vigil/blob/master/rules/default.toml">rules/default.toml</ExtLink>.
        </p>
        <CommandBlock title="rules/custom.toml" code={CUSTOM_TOML} />
        <CommandBlock title="load & inspect" code={`vigil --rules rules/custom.toml ./pkg\nvigil --list-rules\nvigil --disable SC-007,OBF-006 ./pkg`} />
      </div>
    </section>
  )
}
