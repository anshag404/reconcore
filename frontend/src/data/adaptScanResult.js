/**
 * Adapts backend scan output into the { nodes, links } shape TopologyMap wants.
 *
 * Input is whatever `parseNmapXml` produces (src/services/parser.js), optionally
 * enriched with CVE data from `lookupVulnerabilities` (src/services/vulnLookup.js).
 * Both enrichment shapes are accepted, since the two services aren't joined yet:
 *   host.vulnerabilities / host.cves = [{ cveId, cvssV3: { score, severity } }]
 *   ...or the already-flat [{ cveId, score, severity }]
 */

/** Pull a stable node id: prefer IPv4, else MAC, else first hostname. */
function hostId(host) {
  const ipv4 = host.addresses?.find((a) => a.type === 'ipv4')?.addr
  const mac = host.addresses?.find((a) => a.type === 'mac')?.addr

  return ipv4 ?? mac ?? host.hostnames?.[0]?.name ?? 'unknown'
}

/** nmap repeats a hostname across `user` and `PTR` records; show it once. */
function uniqueHostname(host) {
  const names = (host.hostnames ?? []).map((h) => h.name).filter(Boolean)

  return names.length > 0 ? [...new Set(names)][0] : null
}

function normaliseCves(host, scanVulnerabilities = []) {
  let raw = host.vulnerabilities ?? host.cves ?? []

  if (!raw.length && scanVulnerabilities?.length) {
    const hostAddrs = new Set((host.addresses ?? []).map((a) => a.addr).concat(hostId(host)))
    const matching = scanVulnerabilities.filter((v) => hostAddrs.has(v.host))
    raw = matching.flatMap((m) => m.vulnerabilities ?? [])
  }

  return raw
    .map((entry) => ({
      cveId: entry.cveId ?? entry.id ?? 'UNKNOWN',
      score: entry.score ?? entry.cvssV3?.score ?? entry.cvssV2?.score ?? null,
      severity: entry.severity ?? entry.cvssV3?.severity ?? null,
    }))
    .filter((cve) => cve.score !== null)
    .sort((a, b) => b.score - a.score)
}

export function adaptScanResult(scan, { includeFiltered = false } = {}) {
  const hosts = (scan?.hosts ?? []).filter((host) => host.status?.state !== 'down')

  const nodes = hosts.map((host) => {
    const ports = (host.ports ?? [])
      .filter((port) => includeFiltered || port.state?.state === 'open')
      .map((port) => ({
        port: port.portId,
        protocol: port.protocol,
        state: port.state?.state ?? 'unknown',
        service: port.service?.name ?? 'unknown',
        product: port.service?.product ?? null,
        version: port.service?.version ?? null,
      }))
      .sort((a, b) => a.port - b.port)

    const cves = normaliseCves(host, scan?.vulnerabilities)

    return {
      id: hostId(host),
      hostname: uniqueHostname(host),
      os: host.os?.[0]?.name ?? null,
      vendor: host.addresses?.find((a) => a.type === 'mac')?.vendor ?? null,
      ports,
      cves,
      maxCvss: cves.reduce((max, cve) => Math.max(max, cve.score ?? 0), 0),
    }
  })

  // nmap output carries no adjacency information, so links only exist if the
  // payload supplies them explicitly. Inferring edges here would put made-up
  // connections on screen, which is worse than showing none.
  const known = new Set(nodes.map((node) => node.id))
  const links = (scan?.links ?? []).filter(
    (link) => known.has(link.source) && known.has(link.target),
  )

  return { nodes, links }
}

export default adaptScanResult
