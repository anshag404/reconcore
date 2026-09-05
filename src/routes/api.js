const { Router } = require("express");
const router = Router();

// ── Health check ─────────────────────────────────────────────────────
router.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ── API info ─────────────────────────────────────────────────────────
router.get("/", (_req, res) => {
  res.status(200).json({
    name: "ReconCore",
    version: "1.0.0",
    description: "Network reconnaissance and security scanning API",
    endpoints: {
      health: "/api/health",
      // scan endpoints will be added here
    },
  });
});

module.exports = router;
