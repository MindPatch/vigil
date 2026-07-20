import { CommandBlock, ExtLink, SectionHeading } from '@/components/ui-kit'

export function Install() {
  return (
    <section id="install" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="導" index="01 — getting started" title="Installation" sub="not on crates.io yet — build from source with cargo" />
      <div className="space-y-6 max-w-3xl">
        <CommandBlock
          title="build from source (requires Rust)"
          code={`git clone https://github.com/MindPatch/vigil\ncd vigil\ncargo build --release`}
        />
        <p className="text-xs leading-relaxed text-[#a39d8f]">
          The only prerequisite is a Rust toolchain. The binary ends up in{' '}
          <code className="inline">target/release/vigil</code>. Vigil is beta software — expect some
          false positives and breaking changes between versions; review findings before acting on them.
        </p>
      </div>
    </section>
  )
}

export function Usage() {
  return (
    <section id="usage" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="使" index="02 — getting started" title="Usage" sub="point it at a package, a folder, or your whole dependency tree" />
      <div className="grid md:grid-cols-2 gap-4 max-w-4xl">
        <CommandBlock title="scan a package" code={`vigil ./some-package`} />
        <CommandBlock title="CI gate — exit 2 on high+" code={`vigil ./node_modules/that-new-dep || exit 1`} />
        <CommandBlock title="deobfuscate only" code={`vigil -d weird.js`} />
        <CommandBlock title="machine output (json / sarif)" code={`vigil -f json ./pkg\nvigil -f sarif ./pkg`} />
        <CommandBlock title="manifest-only audit" code={`vigil --manifest-only .`} />
        <CommandBlock title="suppress reviewed findings" code={`vigil --baseline ok.json .`} />
      </div>
      <p className="text-xs leading-relaxed text-[#a39d8f] mt-6 max-w-3xl">
        Findings that surfaced only after deobfuscation carry a{' '}
        <code className="inline">[deob]</code> marker, so you can tell what was hidden from plain
        sight. See the full flag list in the <a href="#cli" className="text-[#d63a2a] hover:underline">CLI reference</a>.
      </p>
    </section>
  )
}

const STEPS = [
  {
    kanji: '析',
    n: '1',
    title: 'Parse',
    body: 'JS/TS is parsed with tree-sitter into a real AST — not line greps. Rules can match call expressions, member access and node types structurally.',
  },
  {
    kanji: '復',
    n: '2',
    title: 'Deobfuscate',
    body: 'eval wrappers, Function("..."), hex and unicode escapes, base64 strings, string-array indirection — passes repeat until the code stops changing. Hidden-code findings get a [deob] marker.',
  },
  {
    kanji: '査',
    n: '3',
    title: 'Scan',
    body: '77 built-in rules run on both the raw and cleaned source — AST-based rules (child_process plus network in one file) alongside regex signatures. package.json goes through its own manifest checks.',
  },
  {
    kanji: '点',
    n: '4',
    title: 'Correlate & score',
    body: 'Findings are correlated into a 0–100 score with a per-category breakdown and a verdict: OK, INVESTIGATE or BLOCK. Exit code 2 on high-or-above, ready for CI.',
  },
]

export function HowItWorks() {
  return (
    <section id="how-it-works" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="理" index="03 — internals" title="How it works" sub="four steps, from raw source to verdict" />
      <div className="grid md:grid-cols-2 gap-4 max-w-4xl">
        {STEPS.map((s) => (
          <div key={s.n} className="card-line card-line-hover p-5 flex gap-4">
            <div
              className="font-serif-jp text-2xl text-[#d63a2a] w-12 h-12 flex items-center justify-center shrink-0"
              style={{ boxShadow: 'inset 0 0 0 1px #d63a2a44' }}
            >
              {s.kanji}
            </div>
            <div>
              <div className="text-[10px] tracking-[0.25em] uppercase text-[#6e6a5f] mb-1">step {s.n}</div>
              <h3 className="text-sm font-semibold text-[#e8e2d5] mb-1.5">{s.title}</h3>
              <p className="text-xs leading-relaxed text-[#a39d8f]">{s.body}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-[#6e6a5f] mt-6 max-w-3xl leading-relaxed">
        The engine: tree-sitter parsing in{' '}
        <ExtLink href="https://github.com/MindPatch/vigil/tree/master/src">src/</ExtLink>, deobfuscator passes in{' '}
        <ExtLink href="https://github.com/MindPatch/vigil/tree/master/src/deobfuscator">src/deobfuscator/</ExtLink>,
        all {77} built-in rules in{' '}
        <ExtLink href="https://github.com/MindPatch/vigil/blob/master/src/rules/builtin.rs">src/rules/builtin.rs</ExtLink>.
      </p>
    </section>
  )
}
