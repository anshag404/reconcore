import { useState } from 'react'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scans', label: 'Scans' },
  { id: 'assets', label: 'Assets' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'reports', label: 'Reports' },
  { id: 'settings', label: 'Settings' },
]

function App() {
  const [activeNav, setActiveNav] = useState('dashboard')

  return (
    <div className="flex h-full min-h-screen bg-[#0b1220] text-gray-200">
      {/* Sidebar */}
      <aside className="flex w-64 shrink-0 flex-col border-r border-slate-800 bg-[#0f172a]">
        <div className="border-b border-slate-800 px-6 py-5">
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
            Cybersecurity
          </p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight text-white">
            ReconCore
          </h1>
        </div>

        <nav className="flex-1 px-3 py-4" aria-label="Primary">
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const isActive = activeNav === item.id

              return (
                <li key={item.id}>
                  <button
                    type="button"
                    onClick={() => setActiveNav(item.id)}
                    className={`w-full rounded-md px-3 py-2.5 text-left text-sm transition-colors ${
                      isActive
                        ? 'bg-blue-700 text-white'
                        : 'text-slate-400 hover:bg-slate-800/80 hover:text-slate-100'
                    }`}
                  >
                    {item.label}
                  </button>
                </li>
              )
            })}
          </ul>
        </nav>

        <div className="border-t border-slate-800 px-6 py-4">
          <p className="text-xs text-slate-500">v1.0.0 · Dark mode</p>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b border-slate-800 bg-[#0f172a]/60 px-6">
          <h2 className="text-sm font-medium capitalize text-white">
            {activeNav}
          </h2>
          <span className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-400">
            Offline
          </span>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <section className="mx-auto max-w-5xl">
            <h3 className="text-2xl font-semibold tracking-tight text-white">
              {NAV_ITEMS.find((item) => item.id === activeNav)?.label}
            </h3>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">
              Main content area for the ReconCore dashboard. Wire scan results,
              asset inventory, and vulnerability findings into this panel.
            </p>

            <div className="mt-8 rounded-lg border border-slate-800 bg-[#111827] p-6">
              <p className="text-sm text-slate-300">
                Placeholder panel — replace with live data views for{' '}
                <span className="font-medium text-white">{activeNav}</span>.
              </p>
            </div>
          </section>
        </main>
      </div>
    </div>
  )
}

export default App
