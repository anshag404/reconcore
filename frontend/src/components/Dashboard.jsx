import { useMemo } from 'react'

export default function Dashboard({ data, onNavigate }) {
  // Compute some high-level metrics if we have scan data
  const metrics = useMemo(() => {
    if (!data) return null

    let criticalCount = 0
    let highCount = 0
    let totalVulns = 0

    if (data.vulnerabilities) {
      data.vulnerabilities.forEach(service => {
        if (service.vulnerabilities) {
          totalVulns += service.vulnerabilities.length
          service.vulnerabilities.forEach(v => {
            const score = v.cvssV3?.score || v.cvssV2?.score || 0
            if (score >= 9.0) criticalCount++
            else if (score >= 7.0) highCount++
          })
        }
      })
    }

    return {
      hosts: data.runStats?.hostsUp || 0,
      totalVulns,
      criticalCount,
      highCount,
      duration: data.runStats?.elapsed ? `${data.runStats.elapsed}s` : '—',
      target: data.meta?.target || 'Unknown'
    }
  }, [data])

  return (
    <div className="space-y-6">
      {/* Welcome Banner */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-gradient-to-br from-[#0d1526] to-[#0a0f1c] p-8 shadow-2xl">
        <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-blue-500/10 blur-3xl mix-blend-screen" />
        <div className="absolute -bottom-32 -left-32 h-64 w-64 rounded-full bg-emerald-500/10 blur-3xl mix-blend-screen" />
        
        <div className="relative z-10">
          <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
            ReconCore <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400">Command Center</span>
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">
            Welcome to your centralized attack surface management platform. Initiate network sweeps, analyze topology, and aggregate vulnerability intelligence in real-time.
          </p>
          
          {!data && (
            <div className="mt-6 flex flex-wrap gap-4">
              <button
                onClick={() => onNavigate('scans')}
                className="group relative flex items-center gap-2 rounded-md bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white transition-all hover:bg-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              >
                Launch New Scan
                <svg className="h-4 w-4 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Dynamic Metrics */}
      {data ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard 
            title="Active Hosts" 
            value={metrics.hosts} 
            subtitle={`Target: ${metrics.target}`}
            icon={<svg className="h-5 w-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg>}
            color="border-blue-500/30 bg-blue-500/5"
          />
          <MetricCard 
            title="Total CVEs" 
            value={metrics.totalVulns} 
            subtitle="Across all services"
            icon={<svg className="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>}
            color="border-amber-400/30 bg-amber-400/5"
          />
          <MetricCard 
            title="Critical Risk" 
            value={metrics.criticalCount} 
            subtitle="CVSS >= 9.0"
            icon={<svg className="h-5 w-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" /></svg>}
            color="border-red-500/30 bg-red-500/5"
            glow={metrics.criticalCount > 0}
          />
          <MetricCard 
            title="Scan Duration" 
            value={metrics.duration} 
            subtitle="Pipeline execution time"
            icon={<svg className="h-5 w-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
            color="border-emerald-500/30 bg-emerald-500/5"
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <PlaceholderCard title="Network Assets" delay="0ms" />
          <PlaceholderCard title="Vulnerability Intel" delay="150ms" />
          <PlaceholderCard title="Security Posture" delay="300ms" />
        </div>
      )}
      
      {/* Quick Actions */}
      <div className="rounded-xl border border-slate-800 bg-[#0b1220] p-6">
        <h3 className="text-sm font-semibold text-slate-200">Quick Navigation</h3>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <ActionCard title="Topology Map" desc="Visualize network graph" icon="🕸️" onClick={() => onNavigate('assets')} />
          <ActionCard title="CVE Database" desc="Review extracted vulnerabilities" icon="🛡️" onClick={() => onNavigate('vulnerabilities')} />
          <ActionCard title="Full Report" desc="Export detailed scan data" icon="📄" onClick={() => onNavigate('reports')} />
          <ActionCard title="Preferences" desc="Configure API keys & engine" icon="⚙️" onClick={() => onNavigate('settings')} />
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, subtitle, icon, color, glow }) {
  return (
    <div className={`relative overflow-hidden rounded-xl border ${color} p-5 transition-all hover:-translate-y-1 hover:shadow-lg ${glow ? 'shadow-[0_0_15px_rgba(239,68,68,0.2)]' : ''}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
        <div className="rounded-md bg-slate-900/50 p-1.5">{icon}</div>
      </div>
      <div className="mt-4">
        <h4 className="text-3xl font-bold text-slate-100">{value}</h4>
        <p className="mt-1 text-xs text-slate-500 truncate">{subtitle}</p>
      </div>
    </div>
  )
}

function PlaceholderCard({ title, delay }) {
  return (
    <div 
      className="relative overflow-hidden rounded-xl border border-slate-800/60 bg-[#0d1526]/50 p-5 animate-pulse"
      style={{ animationDelay: delay }}
    >
      <div className="h-4 w-24 rounded bg-slate-800/80" />
      <div className="mt-6 h-8 w-16 rounded bg-slate-800/60" />
      <div className="mt-2 h-3 w-32 rounded bg-slate-800/40" />
    </div>
  )
}

function ActionCard({ title, desc, icon, onClick }) {
  return (
    <button
      onClick={onClick}
      className="group flex flex-col items-start rounded-lg border border-slate-800 bg-[#0d1526] p-4 text-left transition-all hover:border-slate-700 hover:bg-slate-800/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
    >
      <span className="text-2xl group-hover:scale-110 transition-transform">{icon}</span>
      <h4 className="mt-3 text-sm font-semibold text-slate-200">{title}</h4>
      <p className="mt-1 text-xs text-slate-500">{desc}</p>
    </button>
  )
}
