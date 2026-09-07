/**
 * Mock network topology for the TopologyMap component.
 *
 * PLACEHOLDER — replace with the real scan payload. The field names here mirror
 * the backend so the swap is mechanical:
 *   - `id` / `ports[]`  → src/services/parser.js  (hosts[].addresses[].addr,
 *                          hosts[].ports[].portId / .protocol / .service.*)
 *   - `cves[]`          → src/services/vulnLookup.js (cveId, cvssV3.score,
 *                          cvssV3.severity)
 *
 * `maxCvss` is the highest CVSS across a host's CVEs and drives node color and
 * radius. If the real payload omits it, derive it — see deriveMaxCvss() below.
 */

export const mockTopology = {
  nodes: [
    {
      id: '10.0.0.1',
      hostname: 'gw-edge-01',
      os: 'Linux 4.19',
      ports: [
        { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.2p1' },
        { port: 80, protocol: 'tcp', service: 'http', product: 'nginx', version: '1.18.0' },
        { port: 443, protocol: 'tcp', service: 'https', product: 'nginx', version: '1.18.0' },
      ],
      cves: [
        { cveId: 'CVE-2023-38408', score: 9.8, severity: 'CRITICAL' },
        { cveId: 'CVE-2021-23017', score: 7.7, severity: 'HIGH' },
      ],
      maxCvss: 9.8,
    },
    {
      id: '10.0.0.12',
      hostname: 'web-prod-01',
      os: 'Ubuntu 20.04',
      ports: [
        { port: 80, protocol: 'tcp', service: 'http', product: 'Apache httpd', version: '2.4.41' },
        { port: 443, protocol: 'tcp', service: 'https', product: 'Apache httpd', version: '2.4.41' },
        { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.2p1' },
      ],
      cves: [{ cveId: 'CVE-2024-6387', score: 8.1, severity: 'HIGH' }],
      maxCvss: 8.1,
    },
    {
      id: '10.0.0.23',
      hostname: 'db-prod-01',
      os: 'Debian 11',
      ports: [
        { port: 3306, protocol: 'tcp', service: 'mysql', product: 'MySQL', version: '8.0.32' },
        { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.4p1' },
      ],
      cves: [{ cveId: 'CVE-2023-21980', score: 7.5, severity: 'HIGH' }],
      maxCvss: 7.5,
    },
    {
      id: '10.0.0.37',
      hostname: 'file-srv-02',
      os: 'Windows Server 2019',
      ports: [
        { port: 445, protocol: 'tcp', service: 'microsoft-ds', product: 'Samba', version: '4.11.6' },
        { port: 139, protocol: 'tcp', service: 'netbios-ssn', product: 'Samba', version: '4.11.6' },
        { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', product: 'Microsoft Terminal Services', version: null },
      ],
      cves: [
        { cveId: 'CVE-2020-1472', score: 10.0, severity: 'CRITICAL' },
        { cveId: 'CVE-2021-44142', score: 9.9, severity: 'CRITICAL' },
      ],
      maxCvss: 10.0,
    },
    {
      id: '10.0.0.45',
      hostname: 'dev-box-07',
      os: 'Ubuntu 22.04',
      ports: [
        { port: 8080, protocol: 'tcp', service: 'http-proxy', product: 'Jetty', version: '9.4.44' },
        { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.9p1' },
      ],
      cves: [{ cveId: 'CVE-2022-22965', score: 5.3, severity: 'MEDIUM' }],
      maxCvss: 5.3,
    },
  ],
  links: [
    { source: '10.0.0.1', target: '10.0.0.12' },
    { source: '10.0.0.1', target: '10.0.0.37' },
    { source: '10.0.0.1', target: '10.0.0.45' },
    { source: '10.0.0.12', target: '10.0.0.23' },
    { source: '10.0.0.37', target: '10.0.0.23' },
  ],
}

/** Highest CVSS across a host's CVEs, for payloads that don't precompute it. */
export function deriveMaxCvss(node) {
  if (typeof node.maxCvss === 'number') return node.maxCvss
  if (!node.cves?.length) return 0

  return node.cves.reduce((max, cve) => Math.max(max, cve.score ?? 0), 0)
}

export default mockTopology
