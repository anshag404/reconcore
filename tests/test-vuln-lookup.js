/**
 * Test for the vulnerability lookup service.
 *
 * Usage:  node tests/test-vuln-lookup.js
 *
 * Queries the REAL NVD API with known-vulnerable services.
 * Requires internet access. Respects NVD rate limits.
 *
 * Optional: set NVD_API_KEY env var for higher rate limits.
 *   Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
 */
require("dotenv").config();
const { lookupServiceVulns, lookupScanVulns } = require("../src/services/vulnLookup");

// ── Mock services (known-vulnerable versions) ────────────────────────
const TEST_SERVICES = [
  {
    name: "http",
    product: "Apache httpd",
    version: "2.4.49",
    cpe: ["cpe:/a:apache:http_server:2.4.49"],
  },
  {
    name: "ssh",
    product: "OpenSSH",
    version: "6.6.1p1",
    cpe: ["cpe:/a:openbsd:openssh:6.6.1p1"],
  },
  {
    name: "nping-echo",
    product: "Nping echo",
    version: null,
    cpe: null,
  },
];

// ── Mock parsed scan (simulates parser.js output) ────────────────────
const MOCK_PARSED_SCAN = {
  scanInfo: { scanner: "nmap", version: "7.991" },
  runStats: { elapsed: 23.91, hostsUp: 1 },
  hosts: [
    {
      status: { state: "up" },
      addresses: [{ addr: "45.33.32.156", type: "ipv4" }],
      hostnames: [{ name: "scanme.nmap.org", type: "user" }],
      ports: [
        {
          portId: 80,
          protocol: "tcp",
          state: { state: "open", reason: "syn-ack" },
          service: TEST_SERVICES[0],
        },
        {
          portId: 22,
          protocol: "tcp",
          state: { state: "open", reason: "syn-ack" },
          service: TEST_SERVICES[1],
        },
        {
          portId: 25,
          protocol: "tcp",
          state: { state: "filtered", reason: "no-response" },
          service: { name: "smtp", product: null, version: null, cpe: null },
        },
        {
          portId: 9929,
          protocol: "tcp",
          state: { state: "open", reason: "syn-ack" },
          service: TEST_SERVICES[2],
        },
      ],
      os: null,
    },
  ],
};

// ── Test 1: Individual service lookup ────────────────────────────────
async function testSingleLookup() {
  console.log("═".repeat(60));
  console.log("  TEST 1: Single service lookup (Apache 2.4.49)");
  console.log("═".repeat(60));

  const result = await lookupServiceVulns(TEST_SERVICES[0]);

  console.log(`\n  Service       : ${result.service}`);
  console.log(`  Total CVEs    : ${result.totalResults}`);
  console.log(`  Returned      : ${result.vulnerabilities.length}`);

  if (result.error) {
    console.log(`  ⚠️  Error     : ${result.error}`);
  }

  if (result.vulnerabilities.length > 0) {
    console.log("\n  Top vulnerabilities:\n");
    for (const vuln of result.vulnerabilities.slice(0, 3)) {
      const score = vuln.cvssV3 ? `${vuln.cvssV3.score} (${vuln.cvssV3.severity})` : "N/A";
      console.log(`    ${vuln.cveId}  CVSS: ${score}`);
      console.log(`      ${vuln.description.slice(0, 100)}...`);
      console.log();
    }
  }

  return result;
}

// ── Test 2: Full scan lookup ─────────────────────────────────────────
async function testBatchLookup() {
  console.log("═".repeat(60));
  console.log("  TEST 2: Batch lookup from parsed scan");
  console.log("═".repeat(60));

  const results = await lookupScanVulns(MOCK_PARSED_SCAN);

  console.log(`\n  Services queried : ${results.length}`);
  console.log(`  (filtered ports skipped, no-product ports handled)\n`);

  for (const r of results) {
    const icon = r.vulnerabilities.length > 0 ? "🔴" : r.error ? "⚠️ " : "🟢";
    const score = r.vulnerabilities[0]?.cvssV3?.score || "—";
    console.log(`  ${icon}  ${r.host}:${r.port}/${r.protocol}  ${r.service}`);
    console.log(`      CVEs: ${r.totalResults}  |  Top CVSS: ${score}  ${r.error ? `| Error: ${r.error}` : ""}`);
  }

  return results;
}

// ── Test 3: Edge case — no product info ──────────────────────────────
async function testNoProductInfo() {
  console.log("\n" + "═".repeat(60));
  console.log("  TEST 3: Edge case — service with no product/version");
  console.log("═".repeat(60));

  const result = await lookupServiceVulns({
    name: "unknown",
    product: null,
    version: null,
    cpe: null,
  });

  const passed = result.error && result.vulnerabilities.length === 0;
  console.log(`\n  ${passed ? "✅" : "❌"}  Gracefully handled: ${result.error}`);
  return passed;
}

// ── Run all ──────────────────────────────────────────────────────────
(async () => {
  console.log("\n🔍  ReconCore — Vulnerability Lookup Tests");
  console.log(`   NVD API Key: ${process.env.NVD_API_KEY ? "configured ✅" : "not set (using public rate limit)"}\n`);

  try {
    await testSingleLookup();
    console.log();
    await testBatchLookup();
    await testNoProductInfo();

    console.log("\n" + "═".repeat(60));
    console.log("  ✅  All tests completed.");
    console.log("═".repeat(60) + "\n");
  } catch (err) {
    console.error(`\n❌  Test failed: ${err.message}`);
    console.error(err.stack);
    process.exit(1);
  }
})();
