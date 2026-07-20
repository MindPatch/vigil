import { SectionHeading, SevBadge } from '@/components/ui-kit'

const VERDICTS = [
  {
    verdict: 'OK',
    color: '#8a9a7b',
    range: '0 – 19',
    body: 'Nothing of note. Minor hygiene findings at most — safe to proceed.',
  },
  {
    verdict: 'INVESTIGATE',
    color: '#d4b34a',
    range: '20 – 39',
    body: 'Suspicious signals that need a human eye. Read the flagged lines before shipping.',
  },
  {
    verdict: 'BLOCK',
    color: '#d63a2a',
    range: '40 – 100',
    body: 'Likely malicious — do not install, do not ship. The score correlates decode-execute, exfil and C2 signals.',
  },
]

export default function Scoring() {
  return (
    <section id="scoring" className="px-6 md:px-12 py-16 border-b border-[#2a2822] max-w-5xl">
      <SectionHeading kanji="点" index="04 — internals" title="Scoring & verdicts" sub="every finding feeds one 0–100 risk score" />

      <div className="grid md:grid-cols-3 gap-4 max-w-4xl mb-10">
        {VERDICTS.map((v) => (
          <div key={v.verdict} className="card-line card-line-hover p-5">
            <div className="flex items-baseline justify-between mb-3">
              <span className="font-serif-jp text-xl font-bold" style={{ color: v.color }}>
                {v.verdict}
              </span>
              <span className="text-[10px] tracking-[0.2em] text-[#6e6a5f]">{v.range}</span>
            </div>
            <div className="h-1 w-full bg-[#201e19] mb-3">
              <div className="h-1" style={{ background: v.color, width: v.range === '0 – 19' ? '19%' : v.range === '20 – 39' ? '39%' : '100%' }} />
            </div>
            <p className="text-xs leading-relaxed text-[#a39d8f]">{v.body}</p>
          </div>
        ))}
      </div>

      <div className="grid md:grid-cols-2 gap-4 max-w-4xl">
        <div className="card-line p-5">
          <h3 className="text-sm font-semibold text-[#e8e2d5] mb-3">Severity ladder</h3>
          <div className="space-y-2.5 text-xs text-[#a39d8f]">
            {([
              ['critical', 'hardcoded exfil channels, decode-then-execute, reverse shells, C2 infrastructure'],
              ['high', 'credential paths, clipboard clippers, LOLBAS droppers, hidden install downloads'],
              ['medium', 'obfuscation signals, recon correlations, persistence writes, anti-analysis'],
              ['low', 'single weak signals — env reads, fs reads, bare module requires'],
            ] as const).map(([sev, d]) => (
              <div key={sev} className="flex items-start gap-3">
                <SevBadge sev={sev} />
                <span className="leading-relaxed">{d}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card-line p-5">
          <h3 className="text-sm font-semibold text-[#e8e2d5] mb-3">CI behaviour</h3>
          <div className="space-y-2.5 text-xs text-[#a39d8f] leading-relaxed">
            <p>
              Exit code <code className="inline">2</code> when anything at or above the threshold
              (default <code className="inline">high</code>) shows up — tune with{' '}
              <code className="inline">--exit-threshold</code>.
            </p>
            <p>
              The summary breaks the score down per category — Network, Exfiltration, Recon,
              Obfuscation, Filesystem — and tags the package (e.g.{' '}
              <code className="inline">#malware #obfuscated #exfiltration</code>).
            </p>
            <p>
              Reviewed findings can be frozen with <code className="inline">--write-baseline</code> and
              suppressed on later runs with <code className="inline">--baseline ok.json</code>.
            </p>
          </div>
        </div>
      </div>
    </section>
  )
}
