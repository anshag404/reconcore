import { useState, useEffect } from 'react'

export default function Settings() {
  const [nvdKey, setNvdKey] = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [timeout, setTimeoutVal] = useState(120)
  const [isSaved, setIsSaved] = useState(false)

  // Load from local storage on mount (mock persistence for now)
  useEffect(() => {
    const savedNvd = localStorage.getItem('reconcore_nvd_key') || ''
    const savedShodan = localStorage.getItem('reconcore_shodan_key') || ''
    const savedTimeout = localStorage.getItem('reconcore_timeout') || '120'
    
    setNvdKey(savedNvd)
    setShodanKey(savedShodan)
    setTimeoutVal(parseInt(savedTimeout, 10))
  }, [])

  const handleSave = (e) => {
    e.preventDefault()
    
    // Save to local storage
    localStorage.setItem('reconcore_nvd_key', nvdKey)
    localStorage.setItem('reconcore_shodan_key', shodanKey)
    localStorage.setItem('reconcore_timeout', timeout.toString())
    
    // Note: To actually use the NVD key in the backend, it needs to be passed in the /api/scan POST payload
    // or sent to a dedicated backend config endpoint. For this demo, we're mocking the save interaction.
    
    setIsSaved(true)
    setTimeout(() => setIsSaved(false), 3000)
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h3 className="text-xl font-semibold tracking-tight text-white">Platform Settings</h3>
        <p className="mt-1 text-sm text-slate-400">Manage your API keys, scan engine preferences, and integrations.</p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* API Integrations */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1526] overflow-hidden">
          <div className="border-b border-slate-800 bg-[#0f172a] px-6 py-4">
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
              External Integrations
            </h4>
          </div>
          
          <div className="p-6 space-y-6">
            <div>
              <label htmlFor="nvd-key" className="block text-xs font-medium text-slate-300">NVD API Key (NIST)</label>
              <div className="mt-2">
                <input
                  type="password"
                  id="nvd-key"
                  value={nvdKey}
                  onChange={(e) => setNvdKey(e.target.value)}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  className="block w-full rounded-md border-slate-700 bg-[#080e1a] px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors border"
                />
              </div>
              <p className="mt-1.5 text-[11px] text-slate-500">
                Significantly increases your rate limits for CVE lookups from 5 to 50 requests per 30 seconds.
              </p>
            </div>

            <div>
              <label htmlFor="shodan-key" className="block text-xs font-medium text-slate-300">Shodan API Key</label>
              <div className="mt-2">
                <input
                  type="password"
                  id="shodan-key"
                  value={shodanKey}
                  onChange={(e) => setShodanKey(e.target.value)}
                  placeholder="Enter your Shodan API Key"
                  className="block w-full rounded-md border-slate-700 bg-[#080e1a] px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors border"
                />
              </div>
              <p className="mt-1.5 text-[11px] text-slate-500">
                Enables passive OSINT reconnaissance without sending active packets (Coming Soon).
              </p>
            </div>
          </div>
        </div>

        {/* Engine Preferences */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1526] overflow-hidden">
          <div className="border-b border-slate-800 bg-[#0f172a] px-6 py-4">
            <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <svg className="h-4 w-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              Scan Engine Limits
            </h4>
          </div>
          
          <div className="p-6">
            <label htmlFor="timeout-slider" className="block text-xs font-medium text-slate-300">
              Default Global Timeout: <span className="text-emerald-400 font-mono ml-2">{timeout} seconds</span>
            </label>
            <div className="mt-4 flex items-center gap-4">
              <span className="text-xs text-slate-500">30s</span>
              <input
                id="timeout-slider"
                type="range"
                min="30"
                max="300"
                step="10"
                value={timeout}
                onChange={(e) => setTimeoutVal(parseInt(e.target.value, 10))}
                className="w-full accent-blue-500"
              />
              <span className="text-xs text-slate-500">300s</span>
            </div>
            <p className="mt-4 text-[11px] text-slate-500">
              The maximum duration the Nmap child process is allowed to run before being killed. Set higher for slow / stealth scans on large subnets.
            </p>
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center justify-end gap-4">
          <span className={`text-sm text-emerald-400 transition-opacity duration-300 ${isSaved ? 'opacity-100' : 'opacity-0'}`}>
            ✓ Settings saved locally
          </span>
          <button
            type="submit"
            className="rounded-md bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          >
            Save Configuration
          </button>
        </div>
      </form>
    </div>
  )
}
