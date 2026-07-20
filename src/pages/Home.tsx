import { useEffect, useState } from 'react'
import Sidebar from '@/components/Sidebar'
import Hero from '@/sections/Hero'
import { Install, Usage, HowItWorks } from '@/sections/Guide'
import Scoring from '@/sections/Scoring'
import { CliReference, WatchMode, CustomRules } from '@/sections/Reference'
import RulesBrowser from '@/sections/RulesBrowser'
import Footer from '@/sections/Footer'
import { techniques } from '@/data/rules'

const SPY_IDS = [
  'install',
  'usage',
  'how-it-works',
  'scoring',
  'cli',
  'watch',
  'custom-rules',
  ...techniques.map((t) => `tech-${t.slug}`),
]

export default function Home() {
  const [active, setActive] = useState('')
  const [drawer, setDrawer] = useState(false)

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(e.target.id)
        }
      },
      { rootMargin: '-15% 0px -75% 0px' },
    )
    SPY_IDS.forEach((id) => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [])

  return (
    <div className="texture min-h-screen bg-[#0c0b09]">
      {/* desktop sidebar */}
      <aside className="hidden lg:block fixed inset-y-0 left-0 w-72 border-r border-[#2a2822] z-30">
        <Sidebar active={active} />
      </aside>

      {/* mobile top bar */}
      <div className="lg:hidden sticky top-0 z-40 flex items-center justify-between px-5 py-3 bg-[#0c0b09f2] backdrop-blur border-b border-[#2a2822]">
        <a href="#top" className="flex items-center gap-2.5">
          <span
            className="font-serif-jp text-lg text-[#d63a2a] w-8 h-8 flex items-center justify-center"
            style={{ boxShadow: 'inset 0 0 0 1px #d63a2a55' }}
          >
            見
          </span>
          <span className="font-serif-jp font-bold text-[#e8e2d5]">vigil</span>
        </a>
        <button
          onClick={() => setDrawer(!drawer)}
          className="text-[10px] tracking-[0.2em] uppercase text-[#a39d8f] px-3 py-2"
          style={{ boxShadow: 'inset 0 0 0 1px #2a2822' }}
        >
          {drawer ? 'close ×' : 'menu ☰'}
        </button>
      </div>

      {/* mobile drawer */}
      {drawer && (
        <div className="lg:hidden fixed inset-0 z-30 pt-14 bg-[#0c0b09] overflow-y-auto">
          <Sidebar active={active} onNavigate={() => setDrawer(false)} />
        </div>
      )}

      <main className="relative z-10 lg:pl-72">
        <Hero />
        <Install />
        <Usage />
        <HowItWorks />
        <Scoring />
        <CliReference />
        <WatchMode />
        <CustomRules />
        <RulesBrowser />
        <Footer />
      </main>
    </div>
  )
}
