const { Router } = require("express");
const { runNmapScan } = require("../services/scanner");
const { parseNmapXml } = require("../services/parser");
const { lookupScanVulns } = require("../services/vulnLookup");

const router = Router();

// ── Input validation ─────────────────────────────────────────────────
const TARGET_REGEX =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$|^[a-fA-F0-9:]+$/;

/**
 * POST /api/scan
 *
 * Body: { "target": "192.168.1.1" }
 * Optional: { "target": "...", "flags": ["-p", "80,443"], "timeout": 60000, "skipVulnLookup": false }
 *
 * Pipeline: nmap scan → XML parse → CVE enrichment → enriched JSON
 */
router.post("/", async (req, res) => {
  const startTime = Date.now();

  // ── 1. Validate input ──────────────────────────────────────────────
  const { target, flags, timeout, skipVulnLookup } = req.body;

  if (!target || typeof target !== "string") {
    return res.status(400).json({
      status: 400,
      error: "Missing required field: 'target' (string)",
      example: { target: "192.168.1.1" },
    });
  }

  const sanitizedTarget = target.trim();
  if (!TARGET_REGEX.test(sanitizedTarget)) {
    return res.status(400).json({
      status: 400,
      error: `Invalid target: "${sanitizedTarget}". Must be a valid IPv4, IPv6, or hostname.`,
    });
  }

  try {
    // ── 2. Run Nmap scan ─────────────────────────────────────────────
    console.log(`[scan] Starting scan for: ${sanitizedTarget}`);

    const scanOptions = {};
    if (flags && Array.isArray(flags)) scanOptions.flags = flags;
    if (timeout && typeof timeout === "number") scanOptions.timeout = timeout;

    const nmapResult = await runNmapScan(sanitizedTarget, scanOptions);

    if (nmapResult.code !== 0 && !nmapResult.stdout) {
      return res.status(500).json({
        status: 500,
        error: "Nmap scan failed",
        details: nmapResult.stderr || "No output received from nmap",
      });
    }

    // ── 3. Parse XML → JSON ──────────────────────────────────────────
    const parsedScan = await parseNmapXml(nmapResult.stdout);

    if (!parsedScan.hosts || parsedScan.hosts.length === 0) {
      return res.status(200).json({
        status: 200,
        message: "Scan completed but no hosts were found (host may be down)",
        scanInfo: parsedScan.scanInfo,
        runStats: parsedScan.runStats,
        hosts: [],
        vulnerabilities: [],
        meta: {
          target: sanitizedTarget,
          duration: Date.now() - startTime,
        },
      });
    }

    // ── 4. CVE enrichment (optional) ─────────────────────────────────
    let vulnerabilities = [];
    if (!skipVulnLookup) {
      console.log(`[scan] Querying NVD for vulnerabilities...`);
      try {
        vulnerabilities = await lookupScanVulns(parsedScan);
      } catch (vulnErr) {
        // Non-fatal — return scan results even if CVE lookup fails
        console.error(`[scan] CVE lookup failed: ${vulnErr.message}`);
        vulnerabilities = [{ error: "CVE lookup failed", message: vulnErr.message }];
      }
    }

    // ── 5. Build enriched response ───────────────────────────────────
    const duration = Date.now() - startTime;
    console.log(`[scan] Completed for ${sanitizedTarget} in ${duration}ms`);

    return res.status(200).json({
      status: 200,
      scanInfo: parsedScan.scanInfo,
      runStats: parsedScan.runStats,
      hosts: parsedScan.hosts,
      vulnerabilities,
      meta: {
        target: sanitizedTarget,
        duration,
        nmapExitCode: nmapResult.code,
        nmapWarnings: nmapResult.stderr || null,
      },
    });
  } catch (err) {
    console.error(`[scan] Error: ${err.message}`);

    // Distinguish between known error types
    if (err.message.includes("Failed to start nmap")) {
      return res.status(500).json({
        status: 500,
        error: "Nmap is not installed or not on PATH",
        details: err.message,
      });
    }

    if (err.message.includes("timed out")) {
      return res.status(504).json({
        status: 504,
        error: "Scan timed out",
        details: err.message,
      });
    }

    return res.status(500).json({
      status: 500,
      error: "Internal server error",
      details: process.env.NODE_ENV !== "production" ? err.message : undefined,
    });
  }
});

module.exports = router;
