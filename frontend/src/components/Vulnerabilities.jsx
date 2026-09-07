import { useMemo } from 'react'

const RISK = {
  critical: { label: 'Critical', color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30' },
  high: { label: 'High', color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  medium: { label: 'Medium', color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30' },
  low: { label: 'Low', color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/30' },
  unknown: { label: 'Unknown', color: 'text-slate-400', bg: 'bg-slate-400/10', border: 'border-slate-400/30' }
}

function getRiskBand(score) {
  if (score == null) return RISK.unknown
  if (score >= 9.0) return RISK.critical
  if (score >= 7.0) return RISK.high
  if (score >= 4.0) return RISK.medium
  return RISK.low
}

export default function Vulnerabilities({ data }) {
  // Flatten the nested vulnerabilities array into a single list of CVEs
  const flatVulnerabilities = useMemo(() => {
    if (!data?.vulnerabilities) return []
    
    const allVulns = []
    
    data.vulnerabilities.forEach(serviceResult => {
      if (serviceResult.vulnerabilities && serviceResult.vulnerabilities.length > 0) {
        serviceResult.vulnerabilities.forEach(vuln => {
          allVulns.push({
            host: serviceResult.host,
            port: serviceResult.port,
            protocol: serviceResult.protocol,
            service: serviceResult.service,
            cveId: vuln.cveId,
            description: vuln.description,
            score: vuln.cvssV3?.score || vuln.cvssV2?.score || null,
            published: vuln.published ? new Date(vuln.published).toLocaleDateString() : 'Unknown'
          })
        })
      }
    })
    
    // Sort by CVSS score descending
    return allVulns.sort((a, b) => (b.score || 0) - (a.score || 0))
  }, [data])

  if (!data) {
    return (
      <div className="rounded-lg border border-slate-800 bg-[#0d1526] p-12 text-center shadow-lg shadow-black/30">
        <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-800">
          <svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </span>
        <h3 className="mt-4 text-sm font-semibold text-slate-200">No Scan Data</h3>
        <p className="mt-1 text-xs text-slate-500">Run a scan from the dashboard to populate vulnerabilities.</p>
      </div>
    )
  }

  if (flatVulnerabilities.length === 0) {
    return (
      <div className="rounded-lg border border-emerald-500/30 bg-[#0d1526] p-12 text-center shadow-lg shadow-black/30">
        <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/10">
          <svg className="h-6 w-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </span>
        <h3 className="mt-4 text-sm font-semibold text-emerald-400">Zero Vulnerabilities Found</h3>
        <p className="mt-1 text-xs text-slate-500">No known CVEs were detected for the services running on the target.</p>
      </div>
    )
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-[#0d1526] font-mono shadow-lg shadow-black/30 overflow-hidden flex flex-col h-[calc(100vh-12rem)]">
      {/* Terminal chrome */}
      <div className="flex items-center gap-2 border-b border-slate-800 bg-[#0f172a] px-4 py-2.5 shrink-0">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
        <span className="ml-2 truncate text-xs tracking-wide text-slate-500">
          reconcore@vulns — vulnerability inventory
        </span>
      </div>
      
      {/* Header */}
      <div className="p-4 sm:p-6 shrink-0 border-b border-slate-800">
        <h3 className="text-base font-semibold tracking-tight text-slate-100 flex items-center">
          <span className="mr-2 text-red-500">#</span>
          Discovered Vulnerabilities
          <span className="ml-3 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-300">
            {flatVulnerabilities.length} Total
          </span>
        </h3>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          Listing all CVEs identified from the National Vulnerability Database across all scanned hosts and services.
        </p>
      </div>

      {/* Table container (scrollable) */}
      <div className="flex-1 overflow-auto min-h-0 bg-[#080e1a]">
        <table className="w-full text-left text-sm text-slate-400 border-collapse">
          <thead className="sticky top-0 bg-[#0f172a] text-xs uppercase text-slate-500 shadow-[0_1px_0_0_#1e293b]">
            <tr>
              <th scope="col" className="px-6 py-3.5 font-medium whitespace-nowrap">CVE ID</th>
              <th scope="col" className="px-6 py-3.5 font-medium whitespace-nowrap">CVSS Score</th>
              <th scope="col" className="px-6 py-3.5 font-medium whitespace-nowrap">Host : Port</th>
              <th scope="col" className="px-6 py-3.5 font-medium whitespace-nowrap">Service</th>
              <th scope="col" className="px-6 py-3.5 font-medium">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {flatVulnerabilities.map((vuln, idx) => {
              const risk = getRiskBand(vuln.score)
              return (
                <tr 
                  key={`${vuln.cveId}-${vuln.host}-${vuln.port}-${idx}`} 
                  className="hover:bg-slate-800/20 transition-colors group"
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="font-semibold text-slate-200">{vuln.cveId}</span>
                    <div className="mt-1 text-[10px] text-slate-500">Pub: {vuln.published}</div>
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <div className={`flex h-8 w-10 items-center justify-center rounded-md border ${risk.border} ${risk.bg}`}>
                        <span className={`font-bold ${risk.color}`}>
                          {vuln.score ? vuln.score.toFixed(1) : '-'}
                        </span>
                      </div>
                      <span className={`text-xs font-medium uppercase tracking-wider ${risk.color}`}>
                        {risk.label}
                      </span>
                    </div>
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-slate-300">{vuln.host}</span>
                    <span className="text-slate-500 mx-1">:</span>
                    <span className="text-emerald-400">{vuln.port}</span>
                    <span className="text-slate-600 text-xs ml-1">/{vuln.protocol}</span>
                  </td>
                  
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="rounded bg-slate-800/50 px-2 py-1 text-xs text-slate-300 border border-slate-700/50">
                      {vuln.service}
                    </span>
                  </td>
                  
                  <td className="px-6 py-4">
                    <p className="text-xs leading-relaxed text-slate-400 line-clamp-2 group-hover:line-clamp-none transition-all">
                      {vuln.description}
                    </p>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
