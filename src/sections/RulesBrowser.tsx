import { useMemo, useState } from 'react'
import { techniques, stats, type Severity } from '@/data/rules'
import RuleCard from '@/components/RuleCard'
import { ExtLink, SEV_STYLE } from '@/components/ui-kit'

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low']

export default function RulesBrowser() {
  const [query, setQuery] = useState('')
  const [sev, setSev] = useState<Severity | null>(null)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return techniques
      .map((t) => ({
        ...t,
        rules: t.rules.filter((r) => {
          if (sev && r.severity !== sev) return false
          if (!q) return true
          return (
            r.id.toLowerCase().includes(q) ||
            r.name.toLowerCase().includes(q) ||
            r.description.toLowerCase().includes(q) ||
            r.tags.some((tag) => tag.includes(q))
          )
        }),
      }))
      .filter((t) => t.rules.length > 0)
  }, [query, sev])

  const shown = filtered.reduce((n, t) => n + t.rules.length, 0)

  return (
    <div id="rules">
      {/* rules header + search */}
      <div className="px-6 md:px-12 pt-20 pb-10 border-b border-[#2a2822] max-w-5xl">
        <div className="flex items-center gap-3 text-[10px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-4">
          <span className="inline-block w-8 h-px bg-[#d63a2a]" />
          detection rule reference
        </div>
        <h2 className="font-serif-jp text-3xl md:text-5xl font-black text-[#e8e2d5] leading-tight mb-4">
          Techniques <span className="text-[#d63a2a]">&amp;</span> rules
        </h2>
        <p className="text-sm text-[#a39d8f] leading-relaxed max-w-2xl mb-8">
          {stats.sourceRules} source-code rules plus {stats.manifestRules} manifest checks, grouped by
          attack technique. Every rule id links to its exact line in the Vigil source. Correlated
          rules need a second signal nearby before they fire — that is how Vigil keeps false positives
          low against the benign npm corpus.
        </p>

        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="card-line flex items-center flex-1 max-w-md">
            <span className="pl-3.5 text-[#6e6a5f] text-sm">⌕</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter rules — id, name, tag… (e.g. webhook, eval, exfil)"
              className="bg-transparent flex-1 px-3 py-2.5 text-xs text-[#e8e2d5] placeholder:text-[#6e6a5f] outline-none"
            />
            {query && (
              <button onClick={() => setQuery('')} className="pr-3 text-[#6e6a5f] hover:text-[#e8e2d5] text-sm">
                ×
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            {SEVS.map((s) => (
              <button
                key={s}
                onClick={() => setSev(sev === s ? null : s)}
                className="text-[10px] tracking-[0.15em] font-semibold px-2 py-1 transition-opacity"
                style={{
                  color: SEV_STYLE[s].color,
                  background: sev === s ? SEV_STYLE[s].bg : 'transparent',
                  boxShadow: `inset 0 0 0 1px ${sev === s ? SEV_STYLE[s].color : '#2a2822'}`,
                  opacity: sev && sev !== s ? 0.4 : 1,
                }}
              >
                {SEV_STYLE[s].label}
              </button>
            ))}
          </div>
        </div>
        {(query || sev) && (
          <div className="mt-4 text-[11px] text-[#6e6a5f]">
            {shown} rule{shown === 1 ? '' : 's'} match
          </div>
        )}
      </div>

      {/* technique sections */}
      {filtered.map((t, idx) => (
        <section key={t.slug} id={`tech-${t.slug}`} className="px-6 md:px-12 py-14 border-b border-[#2a2822] max-w-5xl relative">
          <div className="flex items-start justify-between gap-6 mb-2">
            <div className="flex items-start gap-5">
              <div
                className="font-serif-jp text-3xl md:text-4xl leading-none text-[#d63a2a] select-none shrink-0 w-12 h-12 md:w-14 md:h-14 flex items-center justify-center"
                style={{ boxShadow: 'inset 0 0 0 1px #d63a2a44' }}
              >
                {t.kanji}
              </div>
              <div className="pt-0.5">
                <div className="text-[10px] tracking-[0.3em] text-[#6e6a5f] uppercase mb-1">
                  technique {String(idx + 1).padStart(2, '0')} · {t.rules.length} rule{t.rules.length === 1 ? '' : 's'}
                </div>
                <h3 className="font-serif-jp text-xl md:text-2xl font-bold text-[#e8e2d5] leading-tight">
                  {t.title}
                </h3>
                <p className="text-xs text-[#6e6a5f] mt-1">{t.subtitle}</p>
              </div>
            </div>
            <span className="vertical-rl font-serif-jp text-[#e8e2d506] text-7xl leading-none select-none hidden lg:block" aria-hidden>
              {t.kanji}
            </span>
          </div>

          <p className="text-xs md:text-[13px] leading-relaxed text-[#a39d8f] max-w-3xl mb-4 ml-[4.25rem] md:ml-[4.75rem]">
            {t.intro}
          </p>

          {t.refs.length > 0 && (
            <div className="flex flex-wrap gap-x-5 gap-y-1.5 mb-8 ml-[4.25rem] md:ml-[4.75rem] text-[11px]">
              {t.refs.map((r) => (
                <ExtLink key={r.url} href={r.url}>
                  {r.label} ↗
                </ExtLink>
              ))}
            </div>
          )}
          {t.refs.length === 0 && <div className="mb-8" />}

          <div className="grid lg:grid-cols-2 gap-3">
            {t.rules.map((r) => (
              <RuleCard key={r.id} rule={r} />
            ))}
          </div>
        </section>
      ))}

      {filtered.length === 0 && (
        <div className="px-6 md:px-12 py-20 text-center text-sm text-[#6e6a5f] border-b border-[#2a2822]">
          no rules match — <button className="text-[#d63a2a] hover:underline" onClick={() => { setQuery(''); setSev(null) }}>clear filters</button>
        </div>
      )}
    </div>
  )
}
