import { ExtLink } from '@/components/ui-kit'

export default function Footer() {
  return (
    <footer className="px-6 md:px-12 py-14 max-w-5xl">
      <div className="grid md:grid-cols-3 gap-10">
        <div>
          <div className="flex items-center gap-3 mb-4">
            <div
              className="font-serif-jp text-xl text-[#d63a2a] w-10 h-10 flex items-center justify-center"
              style={{ boxShadow: 'inset 0 0 0 1px #d63a2a55' }}
            >
              見
            </div>
            <span className="font-serif-jp text-lg font-bold text-[#e8e2d5]">vigil</span>
          </div>
          <p className="text-[11px] leading-relaxed text-[#6e6a5f] max-w-xs">
            Static analyzer that sees through obfuscated supply-chain malware. Beta software — review
            findings before acting on them.
          </p>
        </div>
        <div>
          <div className="text-[10px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-3">Project</div>
          <ul className="space-y-2 text-xs">
            <li><ExtLink href="https://github.com/MindPatch/vigil">GitHub repository ↗</ExtLink></li>
            <li><ExtLink href="https://github.com/MindPatch/vigil/blob/master/src/rules/builtin.rs">Built-in rules source ↗</ExtLink></li>
            <li><ExtLink href="https://github.com/MindPatch/vigil/blob/master/rules/default.toml">Custom rules example ↗</ExtLink></li>
            <li><ExtLink href="https://github.com/MindPatch/vigil/blob/master/vigil.toml.example">vigil.toml example ↗</ExtLink></li>
          </ul>
        </div>
        <div>
          <div className="text-[10px] tracking-[0.3em] uppercase text-[#6e6a5f] mb-3">Credits</div>
          <ul className="space-y-2 text-xs">
            <li><ExtLink href="https://github.com/DataDog/guarddog">DataDog/guarddog — GD rule family origin ↗</ExtLink></li>
            <li><ExtLink href="https://tree-sitter.github.io/tree-sitter/">tree-sitter — parsing ↗</ExtLink></li>
            <li><ExtLink href="https://github.com/MindPatch">MindPatch ↗</ExtLink></li>
          </ul>
        </div>
      </div>
      <div className="mt-12 pt-6 border-t border-[#2a2822] flex flex-wrap items-center justify-between gap-3 text-[10px] tracking-[0.2em] uppercase text-[#6e6a5f]">
        <span>vigil docs — 見張り · built for defenders</span>
        <a href="#top" className="hover:text-[#d63a2a] transition-colors">back to top ↑</a>
      </div>
    </footer>
  )
}
