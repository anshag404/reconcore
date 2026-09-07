import jsPDF from 'jspdf'
import 'jspdf-autotable'

export default function Reports({ data }) {
  const downloadReport = () => {
    if (!data || !data.hosts) return

    const doc = new jsPDF('landscape')
    const targetName = data.meta?.target || 'Unknown Target'
    
    // Add title and metadata
    doc.setFontSize(18)
    doc.text(`ReconCore Scan Report`, 14, 22)
    
    doc.setFontSize(11)
    doc.setTextColor(100)
    doc.text(`Target: ${targetName}`, 14, 32)
    doc.text(`Hosts Up: ${data.runStats?.hostsUp || 0}`, 14, 38)
    doc.text(`Scanner: Nmap ${data.scanInfo?.version || ''}`, 14, 44)
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 50)

    // Build Table Rows
    const tableRows = []
    data.hosts.forEach((host) => {
      const ip = host.addresses?.find(a => a.type === 'ipv4' || a.type === 'ipv6')?.addr || 'Unknown'
      const hostname = host.hostnames?.map(h => h.name).join('; ') || 'None'
      const os = host.os?.map(o => o.name).join('; ') || 'Unknown'
      
      if (!host.ports || host.ports.length === 0) {
        tableRows.push([ip, hostname, os, 'None', '-', '-', '-', '-', '-'])
        return
      }

      host.ports.forEach((port) => {
        tableRows.push([
          ip,
          hostname,
          os,
          port.portId?.toString() || '',
          port.protocol || '',
          port.state?.state || '',
          port.service?.name || '',
          port.service?.product || '',
          port.service?.version || ''
        ])
      })
    })

    // Generate Table
    doc.autoTable({
      startY: 58,
      head: [['IP Address', 'Hostname', 'OS', 'Port', 'Protocol', 'State', 'Service', 'Product', 'Version']],
      body: tableRows,
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: 255 },
      styles: { fontSize: 9, cellPadding: 3 },
      alternateRowStyles: { fillColor: [248, 250, 252] }
    })

    const safeTargetName = targetName.replace(/[^a-zA-Z0-9-]/g, '_')
    doc.save(`reconcore-${safeTargetName}-report.pdf`)
  }

  if (!data) {
    return (
      <div className="rounded-lg border border-slate-800 bg-[#0d1526] p-12 text-center shadow-lg shadow-black/30">
        <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-800">
          <svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </span>
        <h3 className="mt-4 text-sm font-semibold text-slate-200">No Scan Data</h3>
        <p className="mt-1 text-xs text-slate-500">Run a scan from the dashboard to generate a report.</p>
      </div>
    )
  }

  const hosts = data.hosts || []

  return (
    <section className="rounded-lg border border-slate-800 bg-[#0d1526] font-mono shadow-lg shadow-black/30 overflow-hidden flex flex-col h-[calc(100vh-12rem)]">
      {/* Terminal chrome */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-[#0f172a] px-4 py-2.5 shrink-0">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
          <span className="ml-2 truncate text-xs tracking-wide text-slate-500">
            reconcore@reports — detailed scan summary
          </span>
        </div>
        
        <button
          onClick={downloadReport}
          className="flex items-center gap-2 rounded bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Download PDF
        </button>
      </div>
      
      {/* Header */}
      <div className="p-4 sm:p-6 shrink-0 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-semibold tracking-tight text-slate-100 flex items-center">
            <span className="mr-2 text-blue-400">#</span>
            Scan Report
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">
            Full inventory of discovered devices, open ports, and services.
          </p>
        </div>
        
        <div className="flex flex-wrap gap-4 text-xs">
          <div className="flex flex-col">
            <span className="text-slate-500 uppercase tracking-wider text-[10px]">Target</span>
            <span className="text-slate-200 font-medium">{data.meta?.target || 'Unknown'}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-slate-500 uppercase tracking-wider text-[10px]">Hosts Up</span>
            <span className="text-slate-200 font-medium">{data.runStats?.hostsUp || 0}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-slate-500 uppercase tracking-wider text-[10px]">Scanner</span>
            <span className="text-slate-200 font-medium">Nmap {data.scanInfo?.version || ''}</span>
          </div>
        </div>
      </div>

      {/* Main content (scrollable) */}
      <div className="flex-1 overflow-auto bg-[#080e1a] p-4 sm:p-6 space-y-8">
        {hosts.map((host, index) => {
          const mainIp = host.addresses?.find(a => a.type === 'ipv4' || a.type === 'ipv6')?.addr || 'Unknown IP'
          const mac = host.addresses?.find(a => a.type === 'mac')
          const hostnames = host.hostnames?.map(h => h.name).join(', ') || 'No hostname'
          const osList = host.os?.map(o => o.name).join(' / ') || 'Unknown OS'
          
          return (
            <div key={`${mainIp}-${index}`} className="rounded-lg border border-slate-800 bg-[#0d1526] overflow-hidden">
              {/* Host Header */}
              <div className="bg-[#111c33] px-5 py-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-blue-500/10 border border-blue-500/20">
                    <svg className="h-5 w-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                    </svg>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-100">{mainIp}</h4>
                    <p className="text-xs text-slate-400">{hostnames}</p>
                  </div>
                </div>
                
                <div className="flex flex-col sm:items-end gap-1 text-xs">
                  {mac && (
                    <div className="text-slate-400">
                      MAC: <span className="text-slate-300 font-medium">{mac.addr}</span>
                      {mac.vendor && <span className="text-slate-500 ml-1">({mac.vendor})</span>}
                    </div>
                  )}
                  <div className="text-slate-400">
                    OS: <span className="text-slate-300 font-medium">{osList}</span>
                  </div>
                </div>
              </div>
              
              {/* Ports Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-400 border-collapse">
                  <thead className="bg-[#0f172a]/50 text-[11px] uppercase text-slate-500 border-b border-slate-800/50">
                    <tr>
                      <th scope="col" className="px-5 py-2.5 font-medium whitespace-nowrap">Port/Proto</th>
                      <th scope="col" className="px-5 py-2.5 font-medium whitespace-nowrap">State</th>
                      <th scope="col" className="px-5 py-2.5 font-medium whitespace-nowrap">Service</th>
                      <th scope="col" className="px-5 py-2.5 font-medium whitespace-nowrap">Version Info</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {host.ports?.length > 0 ? (
                      host.ports.map((port) => (
                        <tr key={`${port.portId}-${port.protocol}`} className="hover:bg-slate-800/20 transition-colors">
                          <td className="px-5 py-3 whitespace-nowrap">
                            <span className="text-emerald-400 font-medium">{port.portId}</span>
                            <span className="text-slate-500 ml-1">/{port.protocol}</span>
                          </td>
                          <td className="px-5 py-3 whitespace-nowrap">
                            <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide
                              ${port.state.state === 'open' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 
                                port.state.state === 'filtered' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 
                                'bg-slate-500/10 text-slate-400 border border-slate-500/20'}`}>
                              {port.state.state}
                            </span>
                          </td>
                          <td className="px-5 py-3 whitespace-nowrap">
                            <span className="text-slate-300">{port.service?.name || 'unknown'}</span>
                          </td>
                          <td className="px-5 py-3">
                            <div className="flex flex-col gap-0.5">
                              {port.service?.product ? (
                                <span className="text-slate-200">
                                  {port.service.product} {port.service.version || ''}
                                </span>
                              ) : (
                                <span className="text-slate-600 text-xs italic">No version detected</span>
                              )}
                              {port.service?.extraInfo && (
                                <span className="text-[11px] text-slate-500">{port.service.extraInfo}</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="4" className="px-5 py-4 text-center text-xs text-slate-500 italic">
                          No open ports detected for this host.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}
