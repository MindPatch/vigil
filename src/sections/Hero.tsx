import { stats } from '@/data/rules'
import { CopyButton } from '@/components/ui-kit'

const DEMO = `$ vigil ./some-package
          _       _ __
   _   __(_)___ _(_) /
  | | / / / __ \`/ / /
  | |/ / / /_/ / / /
  |___/_/\\__, /_/_/
        /____/        v0.3.0

  supply-chain attack detection · ${stats.sourceRules} rules

 [CRIT] SC-034   script.js:3    Hardcoded Discord webhook
 [CRIT] SC-034   script.js:4    Hardcoded Discord webhook
 [HIGH] SC-039   script.js:134  Hand-rolled multipart file upload
 [MED]  SC-018   script.js:197  OS fingerprinting
 [LOW]  OBF-006  script.js:3    High-entropy string
 [LOW]  SC-001   script.js:197  process.env access (dot)

 ────────────────────────────────────────────────────────
 findings   14 total   2 crit · 3 high · 2 med · 7 low
 scanned    1 file · 0 manifests · 9.5 KB · 199ms
 score      42/100 HIGH
 breakdown  Network 25 · Exfiltration 11 · Recon 4 · Obfuscation 1
 tags       #malware #obfuscated #exfiltration #recon
 verdict    BLOCK — likely malicious, do not use`

function highlightDemo(line: string, i: number) {
  let color = '#a39d8f'
  if (line.includes('[CRIT]')) color = '#d63a2a'
  else if (line.includes('[HIGH]')) color = '#e07b39'
  else if (line.includes('[MED]')) color = '#d4b34a'
  else if (line.includes('[LOW]')) color = '#8a9a7b'
  else if (line.startsWith('$')) color = '#e8e2d5'
  else if (line.includes('verdict') || line.includes('score')) color = '#e8e2d5'
  return (
    <div key={i} style={{ color }}>
      {line || ' '}
    </div>
  )
}

export default function Hero() {
  return (
    <header id="top" className="relative border-b border-[#2a2822]">
      {/* vertical kanji ornament */}
      <div className="absolute right-6 md:right-12 top-0 bottom-0 hidden md:flex items-center pointer-events-none select-none" aria-hidden>
        <span className="vertical-rl font-serif-jp text-[#e8e2d508] text-[11rem] leading-none font-bold">
          見張り
        </span>
      </div>

      <div className="relative px-6 md:px-12 pt-16 md:pt-24 pb-14 max-w-5xl">
        <div className="flex items-center gap-3 text-[10px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-6">
          <span className="inline-block w-8 h-px bg-[#d63a2a]" />
          static analysis · deobfuscation-first · rust
        </div>

        <h1 className="font-serif-jp font-black text-[#e8e2d5] leading-[0.95] text-6xl md:text-8xl mb-6">
          vigil<span className="text-[#d63a2a]">.</span>
        </h1>

        <p className="text-sm md:text-base text-[#a39d8f] leading-relaxed max-w-2xl mb-3">
          Static analyzer that sees through obfuscated supply-chain malware. Vigil scans JavaScript
          and npm packages — it <span className="text-[#e8e2d5]">deobfuscates first</span>, then runs{' '}
          <span className="text-[#e8e2d5]">{stats.sourceRules} rules</span> on the cleaned source, so
          payloads hidden behind eval, hex escapes or base64 have nowhere to hide.
        </p>
        <p className="text-xs text-[#6e6a5f] mb-10">
          <span className="font-serif-jp text-[#8f8a7c]">警戒</span> — vigilance, for your node_modules.
        </p>

        <div className="card-line inline-flex items-center gap-0 mb-10 max-w-full">
          <code className="px-4 py-3 text-[13px] text-[#e8e2d5] overflow-x-auto whitespace-nowrap">
            <span className="text-[#d63a2a]">$</span> git clone https://github.com/MindPatch/vigil &amp;&amp; cd vigil &amp;&amp; cargo build --release
          </code>
          <CopyButton text="git clone https://github.com/MindPatch/vigil && cd vigil && cargo build --release" className="mr-2 shrink-0" />
        </div>

        <div className="flex flex-wrap gap-x-8 gap-y-3 mb-12">
          {[
            ['rules', String(stats.sourceRules)],
            ['manifest checks', String(stats.manifestRules)],
            ['critical sigs', String(stats.critical)],
            ['exit code on hit', '2'],
          ].map(([k, v]) => (
            <div key={k}>
              <div className="font-serif-jp text-2xl font-bold text-[#e8e2d5]">{v}</div>
              <div className="text-[10px] tracking-[0.2em] uppercase text-[#6e6a5f] mt-0.5">{k}</div>
            </div>
          ))}
        </div>

        {/* demo terminal */}
        <div className="card-line max-w-3xl">
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#2a2822]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#d63a2a66]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#d4b34a66]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#8a9a7b66]" />
            </div>
            <span className="text-[10px] tracking-[0.2em] uppercase text-[#6e6a5f]">demo — real output</span>
          </div>
          <pre className="px-4 py-4 text-[11px] md:text-xs leading-[1.7] overflow-x-auto">
            {DEMO.split('\n').map(highlightDemo)}
          </pre>
        </div>
      </div>
    </header>
  )
}
