import { useEffect, useRef, useState } from 'react'
import { startScan, ScanRequestError, API_BASE_URL } from '../api/scanApi'

const SCAN_PROFILES = [
  {
    id: 'fast',
    label: 'Fast',
    tagline: 'Top 100 ports',
    description: 'Quick sweep of the most common ports. Loud but done in seconds.',
    flags: ['-T4', '-F'],
    accent: 'text-emerald-400',
  },
  {
    id: 'detailed',
    label: 'Detailed',
    tagline: 'Full port + version',
    description: 'All 65535 ports with service/version detection. Slow and thorough.',
    flags: ['-T4', '-p-', '-sV', '-sC'],
    accent: 'text-amber-400',
  },
  {
    id: 'stealth',
    label: 'Stealth',
    tagline: 'SYN, low & slow',
    description: 'Half-open SYN scan with throttled timing to stay under IDS thresholds.',
    flags: ['-T2', '-sS', '-Pn'],
    accent: 'text-sky-400',
  },
]

// Accepts a bare IPv4, an IPv4 CIDR block, or a hostname.
const IPV4 = '(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const TARGET_PATTERN = new RegExp(
  `^(?:${IPV4}(?:\\/(?:3[0-2]|[12]?\\d))?|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,})$`,
)

function validateTarget(value) {
  const trimmed = value.trim()

  if (!trimmed) return 'Target is required.'
  if (!TARGET_PATTERN.test(trimmed)) {
    return 'Enter a valid IPv4 address, CIDR subnet, or hostname.'
  }

  return null
}

const ERROR_TITLES = {
  network: 'Cannot reach the API',
  timeout: 'Request timed out',
  'not-found': 'Endpoint not found',
  server: 'Server error',
  parse: 'Malformed response',
  unknown: 'Scan failed',
}

function ScanConfiguration({ onScanComplete }) {
  const [target, setTarget] = useState('')
  const [profileId, setProfileId] = useState('fast')
  const [error, setError] = useState(null)
  const [status, setStatus] = useState('idle') // idle | loading | success | error
  const [requestError, setRequestError] = useState(null)
  const [result, setResult] = useState(null)

  // Cancel an in-flight scan if the component goes away mid-request.
  const abortRef = useRef(null)
  useEffect(() => () => abortRef.current?.abort(), [])

  const profile = SCAN_PROFILES.find((item) => item.id === profileId)
  const isLoading = status === 'loading'

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (isLoading) return

    const validationError = validateTarget(target)
    setError(validationError)
    if (validationError) return

    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setStatus('loading')
    setRequestError(null)
    setResult(null)

    try {
      const data = await startScan(
        { target: target.trim(), profile: profile.id, flags: profile.flags },
        { signal: controller.signal },
      )

      setStatus('success')
      setResult(data)
      onScanComplete?.(data)
    } catch (caught) {
      // An aborted request is a deliberate cancellation, not a failure.
      if (controller.signal.aborted && caught.kind !== 'timeout') return

      setStatus('error')
      setRequestError(
        caught instanceof ScanRequestError
          ? caught
          : new ScanRequestError('unknown', caught.message ?? 'Unexpected error.'),
      )
    }
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-[#0d1526] font-mono shadow-lg shadow-black/30">
      {/* Terminal chrome */}
      <div className="flex items-center gap-2 border-b border-slate-800 bg-[#0f172a] px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
        <span className="ml-2 truncate text-xs tracking-wide text-slate-500">
          reconcore@scan — configuration
        </span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6 p-4 sm:p-6" noValidate>
        <div>
          <h3 className="text-base font-semibold tracking-tight text-slate-100">
            <span className="mr-2 text-emerald-400">$</span>Scan Configuration
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">
            Define a target and pick an intensity profile before dispatching the
            scan engine.
          </p>
        </div>

        {/* Target */}
        <div>
          <label
            htmlFor="scan-target"
            className="block text-xs uppercase tracking-[0.18em] text-slate-500"
          >
            Target IP / Subnet
          </label>

          <div
            className={`mt-2 flex items-center rounded-md border bg-[#080e1a] px-3 transition-colors focus-within:border-emerald-500/70 focus-within:ring-1 focus-within:ring-emerald-500/30 ${
              error ? 'border-red-500/70' : 'border-slate-700'
            }`}
          >
            <span aria-hidden="true" className="select-none pr-2 text-emerald-400">
              &gt;
            </span>
            <input
              id="scan-target"
              name="target"
              type="text"
              value={target}
              onChange={(event) => {
                setTarget(event.target.value)
                if (error) setError(null)
              }}
              placeholder="192.168.1.0/24"
              autoComplete="off"
              spellCheck="false"
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'scan-target-error' : 'scan-target-hint'}
              className="w-full bg-transparent py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none"
            />
          </div>

          {error ? (
            <p id="scan-target-error" role="alert" className="mt-2 text-xs text-red-400">
              {error}
            </p>
          ) : (
            <p id="scan-target-hint" className="mt-2 text-xs text-slate-600">
              Single host, CIDR range, or hostname — e.g. 10.0.0.5, 10.0.0.0/24,
              scanme.nmap.org
            </p>
          )}
        </div>

        {/* Intensity profile */}
        <fieldset>
          <legend className="text-xs uppercase tracking-[0.18em] text-slate-500">
            Scan Intensity
          </legend>

          <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-3">
            {SCAN_PROFILES.map((item) => {
              const isActive = item.id === profileId

              return (
                <label
                  key={item.id}
                  className={`group flex cursor-pointer flex-col rounded-md border p-3.5 transition-colors ${
                    isActive
                      ? 'border-emerald-500/70 bg-emerald-500/5'
                      : 'border-slate-800 bg-[#080e1a] hover:border-slate-700 hover:bg-slate-900/60'
                  }`}
                >
                  <input
                    type="radio"
                    name="intensity"
                    value={item.id}
                    checked={isActive}
                    onChange={() => setProfileId(item.id)}
                    className="sr-only"
                  />

                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`text-sm font-semibold ${
                        isActive ? item.accent : 'text-slate-300'
                      }`}
                    >
                      {item.label}
                    </span>
                    <span
                      aria-hidden="true"
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        isActive ? 'bg-emerald-400' : 'bg-slate-700'
                      }`}
                    />
                  </div>

                  <span className="mt-0.5 text-[11px] uppercase tracking-wider text-slate-500">
                    {item.tagline}
                  </span>
                  <span className="mt-2 text-xs leading-relaxed text-slate-500">
                    {item.description}
                  </span>
                  <code className="mt-3 truncate text-[11px] text-slate-600">
                    nmap {item.flags.join(' ')}
                  </code>
                </label>
              )
            })}
          </div>
        </fieldset>

        {/* Command preview + submit */}
        <div className="flex flex-col gap-3 border-t border-slate-800 pt-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="min-w-0 text-xs text-slate-500">
            <span className="text-slate-600">preview:</span>{' '}
            <code className="break-all text-slate-400">
              nmap {profile.flags.join(' ')} {target.trim() || '<target>'}
            </code>
          </p>

          <button
            type="submit"
            disabled={isLoading}
            aria-busy={isLoading}
            className="flex w-full shrink-0 items-center justify-center gap-2 rounded-md bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-emerald-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0d1526] disabled:cursor-not-allowed disabled:bg-emerald-600/50 disabled:text-slate-950/70 sm:w-auto"
          >
            {isLoading && (
              <span
                aria-hidden="true"
                className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950"
              />
            )}
            {isLoading ? 'Scanning…' : 'Start Scan'}
          </button>
        </div>

        {/* Request outcome */}
        <div aria-live="polite" aria-atomic="true">
          {isLoading && (
            <p className="flex items-center gap-2 text-xs text-slate-500">
              <span
                aria-hidden="true"
                className="h-3 w-3 animate-spin rounded-full border-2 border-slate-700 border-t-emerald-400"
              />
              Dispatching scan to {API_BASE_URL} …
            </p>
          )}

          {status === 'error' && requestError && (
            <div className="rounded-md border border-red-500/50 bg-red-500/5 p-3">
              <p className="text-xs font-semibold text-red-400">
                {ERROR_TITLES[requestError.kind] ?? 'Scan failed'}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">
                {requestError.message}
              </p>
              {requestError.kind === 'network' && (
                <ul className="mt-2 list-inside list-disc space-y-0.5 text-[11px] text-slate-500">
                  <li>Confirm the API is listening on {API_BASE_URL}</li>
                  <li>
                    Set CORS_ORIGIN to this app’s origin ({window.location.origin}) on the
                    server
                  </li>
                  <li>Check the browser console — CORS rejections are only logged there</li>
                </ul>
              )}
            </div>
          )}

          {status === 'success' && result && (
            <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 p-3">
              <p className="text-xs font-semibold text-emerald-400">Scan accepted</p>
              <pre className="mt-1.5 max-h-40 overflow-auto text-[11px] leading-relaxed text-slate-400">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </form>
    </section>
  )
}

export default ScanConfiguration
