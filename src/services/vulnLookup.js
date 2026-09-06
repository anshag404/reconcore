const https = require("https");
const config = require("../config");

// ── NVD API v2.0 ─────────────────────────────────────────────────────
// Docs: https://nvd.nist.gov/developers/vulnerabilities
// Rate limits: 5 requests / 30s (no key), 50 requests / 30s (with key)
const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_API_KEY = process.env.NVD_API_KEY || null;

// ── Rate limiter ─────────────────────────────────────────────────────
const RATE_WINDOW_MS = 30_000;
const MAX_REQUESTS = NVD_API_KEY ? 45 : 4; // stay under ceiling
let requestTimestamps = [];

function waitForRateLimit() {
  return new Promise((resolve) => {
    const now = Date.now();
    requestTimestamps = requestTimestamps.filter((t) => now - t < RATE_WINDOW_MS);

    if (requestTimestamps.length < MAX_REQUESTS) {
      requestTimestamps.push(now);
      return resolve();
    }

    const oldest = requestTimestamps[0];
    const delay = RATE_WINDOW_MS - (now - oldest) + 500; // +500ms buffer
    console.log(`[vuln-lookup] Rate limit reached. Waiting ${delay}ms...`);
    setTimeout(() => {
      requestTimestamps.push(Date.now());
      resolve();
    }, delay);
  });
}

// ── HTTP GET (native, no deps) ───────────────────────────────────────
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const headers = { "User-Agent": "ReconCore/1.0" };
    if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

    https
      .get(url, { headers }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf-8");
          if (res.statusCode === 200) {
            try {
              resolve(JSON.parse(body));
            } catch {
              reject(new Error(`Invalid JSON from NVD: ${body.slice(0, 200)}`));
            }
          } else if (res.statusCode === 403) {
            reject(new Error("NVD rate limit exceeded (HTTP 403). Try again later or add NVD_API_KEY."));
          } else {
            reject(new Error(`NVD API returned HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
          }
        });
      })
      .on("error", reject);
  });
}

// ── Build search query ───────────────────────────────────────────────

/**
 * Converts CPE 2.2 (nmap format) to CPE 2.3 (NVD v2.0 format).
 * e.g. "cpe:/a:apache:http_server:2.4.49" → "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
 */
function cpe22to23(cpe22) {
  if (cpe22.startsWith("cpe:2.3:")) return cpe22; // already v2.3
  // Strip "cpe:/" prefix and split
  const parts = cpe22.replace(/^cpe:\//, "").split(":");
  // Pad to 11 fields with wildcards
  while (parts.length < 11) parts.push("*");
  return `cpe:2.3:${parts.join(":")}`;
}

function buildNvdUrl(service) {
  const params = new URLSearchParams();

  // Primary strategy: CPE match (most accurate — returns exact version matches)
  if (service.cpe && service.cpe.length > 0) {
    const appCpe = service.cpe.find((c) => c.includes(":a:")) || service.cpe[0];
    params.set("cpeName", cpe22to23(appCpe));
  } else if (service.product && service.version) {
    // Fallback: keyword search with simplified product name
    // NVD indexes "Apache 2.4.49" not "Apache httpd 2.4.49"
    const simplifiedProduct = service.product.split(/\s+/)[0]; // first word
    params.set("keywordSearch", `${simplifiedProduct} ${service.version}`);
  } else if (service.product) {
    params.set("keywordSearch", service.product);
  } else {
    return null; // can't search without product info
  }

  params.set("resultsPerPage", "10");
  return `${NVD_BASE}?${params.toString()}`;
}


// ── Parse NVD response ───────────────────────────────────────────────
function extractVulnerabilities(nvdResponse) {
  const vulns = [];

  if (!nvdResponse?.vulnerabilities?.length) return vulns;

  for (const item of nvdResponse.vulnerabilities) {
    const cve = item.cve;
    if (!cve) continue;

    // Extract CVSS — prefer v3.1, fall back to v3.0, then v2.0
    const metricsV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const metricsV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const metricsV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const cvss = metricsV31 || metricsV30 || null;
    const cvssV2 = metricsV2 || null;

    const description =
      cve.descriptions?.find((d) => d.lang === "en")?.value || "No description available.";

    vulns.push({
      cveId: cve.id,
      description: description.length > 300 ? description.slice(0, 297) + "..." : description,
      cvssV3: cvss
        ? {
            score: cvss.baseScore,
            severity: cvss.baseSeverity,
            vector: cvss.vectorString,
            version: cvss.version,
          }
        : null,
      cvssV2: cvssV2
        ? {
            score: cvssV2.baseScore,
            vector: cvssV2.vectorString,
          }
        : null,
      published: cve.published || null,
      references: (cve.references || []).slice(0, 3).map((r) => r.url),
    });
  }

  // Sort by best available CVSS score descending (v3 preferred, v2 fallback)
  vulns.sort((a, b) => {
    const scoreA = a.cvssV3?.score || a.cvssV2?.score || 0;
    const scoreB = b.cvssV3?.score || b.cvssV2?.score || 0;
    return scoreB - scoreA;
  });

  return vulns;
}

// ── Main: lookup vulns for a single service ──────────────────────────
/**
 * Queries NVD for known vulnerabilities matching a service.
 *
 * @param {{ name: string, product: string|null, version: string|null, cpe: string[]|null }} service
 * @returns {Promise<{ service: string, query: string, totalResults: number, vulnerabilities: object[] }>}
 */
async function lookupServiceVulns(service) {
  const label = `${service.product || service.name}${service.version ? " " + service.version : ""}`;
  const url = buildNvdUrl(service);

  if (!url) {
    return {
      service: label,
      query: null,
      totalResults: 0,
      vulnerabilities: [],
      error: "Insufficient service info for NVD query (no product/version/CPE).",
    };
  }

  await waitForRateLimit();
  console.log(`[vuln-lookup] Querying: ${label}`);

  try {
    const data = await httpGet(url);
    const vulns = extractVulnerabilities(data);

    return {
      service: label,
      query: url,
      totalResults: data.totalResults || 0,
      vulnerabilities: vulns,
    };
  } catch (err) {
    return {
      service: label,
      query: url,
      totalResults: 0,
      vulnerabilities: [],
      error: err.message,
    };
  }
}

// ── Batch: lookup vulns for all services from parsed scan ────────────
/**
 * Takes parsed Nmap JSON (from parser.js) and looks up vulnerabilities
 * for every detected service across all hosts.
 *
 * @param {object} parsedScan - Output from parseNmapXml()
 * @returns {Promise<object[]>} Array of vulnerability results per service
 */
async function lookupScanVulns(parsedScan) {
  const results = [];

  for (const host of parsedScan.hosts) {
    for (const port of host.ports) {
      // Skip ports without a service or that aren't open
      if (port.state.state !== "open") continue;
      if (!port.service.name) continue;

      const result = await lookupServiceVulns(port.service);
      result.port = port.portId;
      result.protocol = port.protocol;
      result.host = host.addresses[0]?.addr || "unknown";
      results.push(result);
    }
  }

  return results;
}

module.exports = { lookupServiceVulns, lookupScanVulns };
