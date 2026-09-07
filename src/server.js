const express = require("express");
const config = require("./config");
const applyMiddleware = require("./middleware/security");
const apiRoutes = require("./routes/api");
const scanRoutes = require("./routes/scan");

// ── Bootstrap ────────────────────────────────────────────────────────
const app = express();

// Apply security & logging middleware
applyMiddleware(app);

// Mount routes
app.use("/api", apiRoutes);
app.use("/api/scan", scanRoutes);

const path = require("path");

// ── 404 handler for API routes ───────────────────────────────────────
app.use("/api", (_req, res) => {
  res.status(404).json({ status: 404, error: "API Route not found" });
});

// ── Serve Frontend SPA ───────────────────────────────────────────────
// In production (or Docker), serve the built React app
const frontendDistPath = path.join(__dirname, "../frontend/dist");
app.use(express.static(frontendDistPath));

app.get("*", (req, res) => {
  res.sendFile(path.join(frontendDistPath, "index.html"));
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
  ║  Scan    : POST /api/scan               ║
  ╚══════════════════════════════════════════╝
  `);
});

module.exports = app;
