/**
 * Scan API client.
 *
 * Base URL comes from VITE_API_BASE_URL so the port isn't baked into the
 * bundle — see frontend/.env.example.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:3000'

/**
 * Abort a scan that never answers. Sits above the backend's own 120s nmap
 * timeout so the server gets the chance to return its error first.
 */
const REQUEST_TIMEOUT_MS = 150_000

/**
 * Error carrying a machine-readable `kind` so the UI can explain the failure
 * instead of printing a raw exception at the user.
 */
export class ScanRequestError extends Error {
  constructor(kind, message, { status = null, cause = null } = {}) {
    super(message)
    this.name = 'ScanRequestError'
    this.kind = kind
    this.status = status
    this.cause = cause
  }
}

export async function startScan({ target, flags }, { signal, onProgress } = {}) {
  // 1. Start the scan (returns a jobId immediately)
  const data = await request('/api/scan', { target, flags }, signal)
  
  if (!data || !data.jobId) {
    throw new ScanRequestError('server', 'Server did not return a jobId')
  }

  const { jobId } = data;

  // 2. Poll for results
  return await pollJob(jobId, { signal, onProgress });
}

async function pollJob(jobId, { signal, onProgress } = {}) {
  const pollIntervalMs = 2000; // poll every 2 seconds
  const startTime = Date.now();

  while (true) {
    if (signal?.aborted) {
      throw new ScanRequestError('aborted', 'Scan cancelled by user');
    }

    if (Date.now() - startTime > REQUEST_TIMEOUT_MS) {
      throw new ScanRequestError('timeout', `Scan took longer than ${REQUEST_TIMEOUT_MS / 1000}s`);
    }

    let response;
    try {
      response = await fetch(`${API_BASE_URL}/api/scan/${jobId}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal,
      });
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new ScanRequestError('aborted', 'Scan cancelled by user', { cause: error });
      }
      throw new ScanRequestError(
        'network',
        `Could not reach ${API_BASE_URL}. The server may be down, or rejecting this origin.`,
        { cause: error },
      );
    }

    if (!response.ok) {
      const detail = await readError(response)
      throw new ScanRequestError(
        response.status === 404 ? 'not-found' : 'server',
        detail ?? `Server responded ${response.status}.`,
        { status: response.status },
      )
    }

    let jobData;
    try {
      jobData = await response.json();
    } catch (error) {
      throw new ScanRequestError('parse', 'Server returned a response that was not valid JSON.', { cause: error })
    }

    if (onProgress) {
      onProgress(jobData.jobStatus);
    }

    if (jobData.jobStatus === 'completed') {
      return jobData.result;
    } else if (jobData.jobStatus === 'failed') {
      throw new ScanRequestError('server', jobData.error || 'Scan job failed');
    }

    // Wait before polling again
    await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
  }
}


async function request(path, body, externalSignal) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  // Let a caller-supplied signal (component unmount) also cancel the request.
  externalSignal?.addEventListener('abort', () => controller.abort(), { once: true })

  let response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new ScanRequestError('timeout', `No response after ${REQUEST_TIMEOUT_MS / 1000}s.`, {
        cause: error,
      })
    }

    throw new ScanRequestError(
      'network',
      `Could not reach ${API_BASE_URL}. The server may be down, on a different port, or rejecting this origin via CORS.`,
      { cause: error },
    )
  } finally {
    clearTimeout(timeout)
  }

  if (!response.ok && response.status !== 202) { // Allow 202 Accepted
    const detail = await readError(response)
    throw new ScanRequestError(
      response.status === 404 ? 'not-found' : 'server',
      detail ?? `Server responded ${response.status}.`,
      { status: response.status },
    )
  }

  try {
    return await response.json()
  } catch (error) {
    throw new ScanRequestError('parse', 'Server returned a response that was not valid JSON.', {
      cause: error,
    })
  }
}

/** Best-effort extraction of an error message; never throws. */
async function readError(response) {
  try {
    const data = await response.json()
    return data?.error ?? data?.message ?? null
  } catch {
    return null
  }
}

export { API_BASE_URL }
