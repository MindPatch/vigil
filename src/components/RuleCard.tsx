import { ruleUrl, type Rule } from '@/data/rules'
import { Chip, SevBadge } from './ui-kit'

const KIND_LABEL: Record<string, string> = {
  Regex: 'regex',
  CallExpression: 'AST · call',
  MemberExpression: 'AST · member',
  SubscriptExpression: 'AST · subscript',
  AstNodeType: 'AST · node',
  Entropy: 'entropy',
  LongLine: 'structure',
  Manifest: 'manifest',
}

export default function RuleCard({ rule }: { rule: Rule }) {
  return (
    <article id={`rule-${rule.id}`} className="card-line card-line-hover flex flex-col">
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-[#2a2822]">
        <a
          href={ruleUrl(rule)}
          target="_blank"
          rel="noreferrer"
          className="text-[13px] font-semibold text-[#d63a2a] hover:text-[#e8e2d5] transition-colors tracking-wide"
          title="view rule source on GitHub"
        >
          {rule.id} <span className="text-[#6e6a5f] font-normal text-[11px]">↗</span>
        </a>
        <div className="flex items-center gap-2">
          <span className="text-[10px] tracking-wider text-[#6e6a5f] hidden sm:inline">
            {KIND_LABEL[rule.kind] ?? rule.kind}
          </span>
          <SevBadge sev={rule.severity} />
        </div>
      </div>

      <div className="px-4 py-3 flex-1">
        <h4 className="text-sm font-semibold text-[#e8e2d5] mb-1.5">{rule.name}</h4>
        <p className="text-xs leading-relaxed text-[#a39d8f]">{rule.description}</p>
      </div>

      {(rule.pattern || rule.correlatesWith) && (
        <details className="border-t border-[#2a2822] group">
          <summary className="px-4 py-2 text-[10px] tracking-[0.2em] uppercase text-[#6e6a5f] hover:text-[#e8e2d5] transition-colors flex items-center gap-2">
            <span className="chev text-[#d63a2a]">▸</span> signature
          </summary>
          <div className="px-4 pb-3 space-y-2">
            {rule.pattern && (
              <div>
                <div className="text-[9px] tracking-[0.2em] uppercase text-[#6e6a5f] mb-1">pattern</div>
                <pre className="text-[11px] leading-relaxed text-[#8f8a7c] overflow-x-auto whitespace-pre-wrap break-all bg-[#0c0b09] p-2.5" style={{ boxShadow: 'inset 0 0 0 1px #201e19' }}>
                  {rule.pattern}
                </pre>
              </div>
            )}
            {rule.correlatesWith && (
              <div>
                <div className="text-[9px] tracking-[0.2em] uppercase text-[#6e6a5f] mb-1">
                  + correlates with <span className="normal-case tracking-normal">(second signal required nearby)</span>
                </div>
                <pre className="text-[11px] leading-relaxed text-[#8f8a7c] overflow-x-auto whitespace-pre-wrap break-all bg-[#0c0b09] p-2.5" style={{ boxShadow: 'inset 0 0 0 1px #201e19' }}>
                  {rule.correlatesWith}
                </pre>
              </div>
            )}
          </div>
        </details>
      )}

      <div className="px-4 py-2.5 border-t border-[#2a2822] flex flex-wrap gap-1.5">
        {rule.tags.map((t) => (
          <Chip key={t}>#{t}</Chip>
        ))}
      </div>
    </article>
  )
}
