const { Router } = require("express");
const { runNmapScan } = require("../services/scanner");
const { parseNmapXml } = require("../services/parser");
const { lookupScanVulns } = require("../services/vulnLookup");
const jobManager = require("../services/jobManager");

const router = Router();

// ── Input validation ─────────────────────────────────────────────────
const TARGET_REGEX =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d))?$|^[a-fA-F0-9:]+(?:\/(?:12[0-8]|1[01]\d|\d{1,2}))?$/;

/**
 * Helper to run the scan pipeline asynchronously
 */
async function executeScanPipeline(jobId, target, flags, timeout, skipVulnLookup) {
  const startTime = Date.now();
  try {
    // 1. Scan
    jobManager.updateJob(jobId, { status: "scanning" });
    const scanOptions = {};
    if (flags && Array.isArray(flags)) scanOptions.flags = flags;
    if (timeout && typeof timeout === "number") scanOptions.timeout = timeout;

    const nmapResult = await runNmapScan(target, scanOptions);
    if (nmapResult.code !== 0 && !nmapResult.stdout) {
      throw new Error(`Nmap failed: ${nmapResult.stderr || "No output"}`);
    }

    // 2. Parse
    jobManager.updateJob(jobId, { status: "parsing" });
    const parsedScan = await parseNmapXml(nmapResult.stdout);

    if (!parsedScan.hosts || parsedScan.hosts.length === 0) {
      jobManager.updateJob(jobId, {
        status: "completed",
        result: {
          message: "Scan completed but no hosts were found (host may be down)",
          scanInfo: parsedScan.scanInfo,
          runStats: parsedScan.runStats,
          hosts: [],
          vulnerabilities: [],
          meta: { target, duration: Date.now() - startTime },
        },
      });
      return;
    }

    // 3. Enrich
    let vulnerabilities = [];
    if (!skipVulnLookup) {
      jobManager.updateJob(jobId, { status: "enriching" });
      try {
        vulnerabilities = await lookupScanVulns(parsedScan);
      } catch (vulnErr) {
        console.error(`[scan] CVE lookup failed for job ${jobId}: ${vulnErr.message}`);
        vulnerabilities = [{ error: "CVE lookup failed", message: vulnErr.message }];
      }
    }

    // 4. Complete
    const duration = Date.now() - startTime;
    jobManager.updateJob(jobId, {
      status: "completed",
      result: {
        scanInfo: parsedScan.scanInfo,
        runStats: parsedScan.runStats,
        hosts: parsedScan.hosts,
        vulnerabilities,
        meta: {
          target,
          duration,
          nmapExitCode: nmapResult.code,
          nmapWarnings: nmapResult.stderr || null,
        },
      },
    });
  } catch (err) {
    console.error(`[scan] Job ${jobId} failed: ${err.message}`);
    jobManager.updateJob(jobId, { status: "failed", error: err.message });
  }
}

/**
 * POST /api/scan
 * Triggers an async scan and returns a Job ID.
 */
router.post("/", (req, res) => {
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

  // Create job
  const jobId = jobManager.createJob(sanitizedTarget);

  // Start background pipeline (fire and forget)
  executeScanPipeline(jobId, sanitizedTarget, flags, timeout, skipVulnLookup);

  return res.status(202).json({
    status: 202,
    message: "Scan job created successfully",
    jobId,
  });
});

/**
 * GET /api/scan/:jobId
 * Retrieves the status and/or result of a scan job.
 */
router.get("/:jobId", (req, res) => {
  const job = jobManager.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({
      status: 404,
      error: "Job not found",
    });
  }

  return res.status(200).json({
    status: 200,
    jobId: job.id,
    target: job.target,
    jobStatus: job.status, // pending, scanning, parsing, enriching, completed, failed
    result: job.result,
    error: job.error,
    createdAt: job.createdAt,
  });
});

module.exports = router;
