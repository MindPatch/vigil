import { techniques, stats } from '@/data/rules'

const GUIDE = [
  { id: 'install', label: 'Installation' },
  { id: 'usage', label: 'Usage' },
  { id: 'how-it-works', label: 'How it works' },
  { id: 'scoring', label: 'Scoring & verdicts' },
  { id: 'cli', label: 'CLI reference' },
  { id: 'watch', label: 'Watch mode' },
  { id: 'custom-rules', label: 'Custom rules' },
]

export default function Sidebar({ active, onNavigate }: { active: string; onNavigate?: () => void }) {
  const item = (id: string, label: React.ReactNode, extra?: React.ReactNode) => (
    <a
      key={id}
      href={`#${id}`}
      onClick={onNavigate}
      className={`nav-item flex items-center justify-between gap-2 py-1.5 text-xs text-[#8f8a7c] hover:text-[#e8e2d5] ${active === id ? 'active' : ''}`}
    >
      <span className="truncate">{label}</span>
      {extra}
    </a>
  )

  return (
    <div className="h-full flex flex-col bg-[#0c0b09]">
      {/* brand */}
      <a href="#top" onClick={onNavigate} className="flex items-center gap-3.5 px-6 pt-7 pb-6 border-b border-[#2a2822]">
        <div
          className="font-serif-jp text-2xl text-[#d63a2a] w-11 h-11 flex items-center justify-center shrink-0"
          style={{ boxShadow: 'inset 0 0 0 1px #d63a2a55' }}
        >
          見
        </div>
        <div>
          <div className="font-serif-jp text-lg font-bold text-[#e8e2d5] leading-none">vigil</div>
          <div className="text-[9px] tracking-[0.25em] text-[#6e6a5f] uppercase mt-1.5">supply-chain detector</div>
        </div>
      </a>

      <nav className="flex-1 overflow-y-auto px-6 py-6 space-y-7">
        <div>
          <div className="text-[9px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-2.5">Guide</div>
          <div className="space-y-0.5">{GUIDE.map((g) => item(g.id, g.label))}</div>
        </div>

        <div>
          <div className="text-[9px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-2.5">
            Detection rules · {stats.totalRules}
          </div>
          <div className="space-y-0.5">
            {techniques.map((t) =>
              item(
                `tech-${t.slug}`,
                t.title,
                <span className="text-[10px] text-[#6e6a5f] shrink-0">{t.rules.length}</span>,
              ),
            )}
          </div>
        </div>
      </nav>

      <div className="px-6 py-5 border-t border-[#2a2822] space-y-2">
        <a
          href="https://github.com/MindPatch/vigil"
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-2 text-xs text-[#a39d8f] hover:text-[#d63a2a] transition-colors"
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
          </svg>
          MindPatch / vigil
        </a>
        <div className="text-[10px] text-[#6e6a5f]">beta · expect false positives</div>
      </div>
    </div>
  )
}
