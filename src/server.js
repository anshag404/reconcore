const express = require("express");
const config = require("./config");
const applyMiddleware = require("./middleware/security");
const apiRoutes = require("./routes/api");

// ── Bootstrap ────────────────────────────────────────────────────────
const app = express();

// Apply security & logging middleware
applyMiddleware(app);

// Mount routes
app.use("/api", apiRoutes);

// ── 404 handler ──────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ status: 404, error: "Route not found" });
});

// ── Global error handler ─────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  const message =
    config.nodeEnv === "production"
      ? "Internal server error"
      : err.message || "Internal server error";

  console.error(`[ERROR] ${err.stack || err}`);
  res.status(status).json({ status, error: message });
});

// ── Start ────────────────────────────────────────────────────────────
app.listen(config.port, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║          R E C O N C O R E              ║
  ║──────────────────────────────────────────║
  ║  Status  : Running                      ║
  ║  Port    : ${String(config.port).padEnd(29)}║
  ║  Env     : ${config.nodeEnv.padEnd(29)}║
  ║  Health  : /api/health                  ║
  ╚══════════════════════════════════════════╝
  `);
});

module.exports = app;
