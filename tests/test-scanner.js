/**
 * Quick smoke test for the scanner service.
 *
 * Usage:
 *   node tests/test-scanner.js              → scans scanme.nmap.org (default)
 *   node tests/test-scanner.js 192.168.1.1  → scans a custom target
 *
 * Requires nmap installed and on PATH.
 */
const { runNmapScan } = require("../src/services/scanner");

const target = process.argv[2] || "scanme.nmap.org";

(async () => {
  console.log(`\n🔍  Starting Nmap scan against: ${target}\n`);
  console.log("─".repeat(50));

  try {
    const result = await runNmapScan(target, { timeout: 60_000 });

    console.log(`\n✅  Scan completed  (exit code: ${result.code})`);
    console.log("─".repeat(50));

    // ── Show XML output ──────────────────────────────────────────────
    if (result.stdout) {
      console.log("\n📄  Raw XML output:\n");
      console.log(result.stdout);
    } else {
      console.log("\n⚠️   No stdout received from nmap.");
    }

    // ── Show stderr (warnings/progress) ──────────────────────────────
    if (result.stderr) {
      console.log("\n📝  Stderr (nmap progress/warnings):\n");
      console.log(result.stderr);
    }
  } catch (err) {
    console.error(`\n❌  Scan failed: ${err.message}`);
    process.exit(1);
  }
})();
