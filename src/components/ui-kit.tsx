import { useState } from 'react'
import type { Severity } from '@/data/rules'

export const SEV_STYLE: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: '#d63a2a', bg: '#d63a2a1a', label: 'CRIT' },
  high: { color: '#e07b39', bg: '#e07b391a', label: 'HIGH' },
  medium: { color: '#d4b34a', bg: '#d4b34a1a', label: 'MED' },
  low: { color: '#8a9a7b', bg: '#8a9a7b1a', label: 'LOW' },
}

export function SevBadge({ sev }: { sev: Severity }) {
  const s = SEV_STYLE[sev]
  return (
    <span
      className="text-[10px] tracking-[0.15em] font-semibold px-1.5 py-0.5 shrink-0"
      style={{ color: s.color, background: s.bg, boxShadow: `inset 0 0 0 1px ${s.color}55` }}
    >
      {s.label}
    </span>
  )
}

export function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] tracking-wider text-[#8f8a7c] px-1.5 py-0.5" style={{ boxShadow: 'inset 0 0 0 1px #2a2822' }}>
      {children}
    </span>
  )
}

export function CopyButton({ text, className = '' }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).catch(() => {})
        setCopied(true)
        setTimeout(() => setCopied(false), 1400)
      }}
      className={`text-[10px] tracking-[0.15em] uppercase px-2 py-1 text-[#8f8a7c] hover:text-[#e8e2d5] transition-colors ${className}`}
      style={{ boxShadow: 'inset 0 0 0 1px #2a2822' }}
      aria-label="copy"
    >
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

export function CommandBlock({ title, code }: { title?: string; code: string }) {
  return (
    <div className="card-line">
      {title && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-[#2a2822]">
          <span className="text-[10px] tracking-[0.2em] uppercase text-[#6e6a5f]">{title}</span>
          <CopyButton text={code} />
        </div>
      )}
      <pre className="px-4 py-3 text-[13px] leading-relaxed overflow-x-auto text-[#e8e2d5]">
        <code>{code}</code>
      </pre>
    </div>
  )
}

export function SectionHeading({
  kanji,
  index,
  title,
  sub,
}: {
  kanji: string
  index: string
  title: string
  sub?: string
}) {
  return (
    <div className="flex items-start gap-5 mb-8">
      <div
        className="font-serif-jp text-4xl md:text-5xl leading-none text-[#d63a2a] select-none shrink-0 w-14 h-14 md:w-16 md:h-16 flex items-center justify-center"
        style={{ boxShadow: 'inset 0 0 0 1px #d63a2a44' }}
      >
        {kanji}
      </div>
      <div className="pt-1">
        <div className="text-[10px] tracking-[0.3em] text-[#6e6a5f] uppercase mb-1.5">{index}</div>
        <h2 className="font-serif-jp text-2xl md:text-3xl font-bold text-[#e8e2d5] leading-tight">{title}</h2>
        {sub && <p className="text-xs text-[#8f8a7c] mt-1.5">{sub}</p>}
      </div>
    </div>
  )
}

export function ExtLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-[#a39d8f] hover:text-[#d63a2a] underline decoration-[#2a2822] underline-offset-4 hover:decoration-[#d63a2a] transition-colors"
    >
      {children}
    </a>
  )
}
