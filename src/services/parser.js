const { parseStringPromise } = require("xml2js");

/**
 * Parses raw Nmap XML output into a structured JSON object.
 *
 * @param {string} xmlString - Raw XML from `nmap -oX -`
 * @returns {Promise<object>} Parsed scan result
 */
async function parseNmapXml(xmlString) {
  if (!xmlString || typeof xmlString !== "string") {
    throw new Error("XML input is required and must be a string.");
  }

  const raw = await parseStringPromise(xmlString, {
    explicitArray: false,   // don't wrap single elements in arrays
    mergeAttrs: true,       // flatten attributes into the node
    ignoreAttrs: false,
    trim: true,
  });

  const nmaprun = raw.nmaprun;
  if (!nmaprun) {
    throw new Error("Invalid Nmap XML: missing <nmaprun> root element.");
  }

  // ── Scan metadata ──────────────────────────────────────────────────
  const scanInfo = {
    scanner: nmaprun.scanner || "nmap",
    args: nmaprun.args || null,
    startTime: nmaprun.start ? new Date(Number(nmaprun.start) * 1000).toISOString() : null,
    version: nmaprun.version || null,
  };

  // ── Run stats ──────────────────────────────────────────────────────
  const finished = nmaprun.runstats?.finished || {};
  const hostsStats = nmaprun.runstats?.hosts || {};
  const runStats = {
    elapsed: finished.elapsed ? parseFloat(finished.elapsed) : null,
    summary: finished.summary || null,
    endTime: finished.time ? new Date(Number(finished.time) * 1000).toISOString() : null,
    hostsUp: hostsStats.up ? parseInt(hostsStats.up, 10) : 0,
    hostsDown: hostsStats.down ? parseInt(hostsStats.down, 10) : 0,
    hostsTotal: hostsStats.total ? parseInt(hostsStats.total, 10) : 0,
  };

  // ── Hosts ──────────────────────────────────────────────────────────
  const rawHosts = normalizeToArray(nmaprun.host);
  const hosts = rawHosts.map(parseHost);

  return {
    scanInfo,
    runStats,
    hosts,
  };
}

// ── Host parser ────────────────────────────────────────────────────────
function parseHost(host) {
  // Address(es)
  const addresses = normalizeToArray(host.address).map((a) => ({
    addr: a.addr,
    type: a.addrtype,
    vendor: a.vendor || null,
  }));

  // Hostnames
  const hostnames = normalizeToArray(host.hostnames?.hostname).map((h) => ({
    name: h.name,
    type: h.type,
  }));

  // Status
  const status = {
    state: host.status?.state || "unknown",
    reason: host.status?.reason || null,
  };

  // Ports
  const rawPorts = normalizeToArray(host.ports?.port);
  const ports = rawPorts.map(parsePort);

  // OS detection
  const os = parseOs(host.os);

  return {
    status,
    addresses,
    hostnames,
    ports,
    os,
  };
}

// ── Port parser ────────────────────────────────────────────────────────
function parsePort(port) {
  const service = port.service || {};
  const cpes = normalizeToArray(service.cpe);

  return {
    portId: parseInt(port.portid, 10),
    protocol: port.protocol || "tcp",
    state: {
      state: port.state?.state || "unknown",
      reason: port.state?.reason || null,
    },
    service: {
      name: service.name || null,
      product: service.product || null,
      version: service.version || null,
      extraInfo: service.extrainfo || null,
      osType: service.ostype || null,
      method: service.method || null,
      confidence: service.conf ? parseInt(service.conf, 10) : null,
      cpe: cpes.length > 0 ? cpes : null,
    },
  };
}

// ── OS parser ──────────────────────────────────────────────────────────
function parseOs(os) {
  if (!os) return null;

  const matches = normalizeToArray(os.osmatch).map((match) => {
    const classes = normalizeToArray(match.osclass).map((cls) => ({
      type: cls.type || null,
      vendor: cls.vendor || null,
      family: cls.osfamily || null,
      generation: cls.osgen || null,
      accuracy: cls.accuracy ? parseInt(cls.accuracy, 10) : null,
      cpe: normalizeToArray(cls.cpe),
    }));

    return {
      name: match.name || null,
      accuracy: match.accuracy ? parseInt(match.accuracy, 10) : null,
      classes,
    };
  });

  return matches.length > 0 ? matches : null;
}

// ── Utility ────────────────────────────────────────────────────────────
function normalizeToArray(val) {
  if (!val) return [];
  return Array.isArray(val) ? val : [val];
}

module.exports = { parseNmapXml };
