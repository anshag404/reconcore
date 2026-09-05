const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const config = require("../config");

/**
 * Applies all security and logging middleware to the Express app.
 * Helmet  → sets secure HTTP headers (XSS, clickjacking, MIME sniffing, etc.)
 * CORS    → restricts cross-origin requests to allowed origins
 * Morgan  → HTTP request logger (dev format in dev, combined in prod)
 * Rate-limit → prevents brute-force / abuse on all routes
 */
function applyMiddleware(app) {
  // ── Security headers ───────────────────────────────────────────────
  app.use(helmet());

  // ── CORS ───────────────────────────────────────────────────────────
  app.use(
    cors({
      origin: config.cors.origin,
      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );

  // ── Request logging ────────────────────────────────────────────────
  const logFormat = config.nodeEnv === "production" ? "combined" : "dev";
  app.use(morgan(logFormat));

  // ── Rate limiting ──────────────────────────────────────────────────
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false,  // Disable `X-RateLimit-*` headers
    message: {
      status: 429,
      error: "Too many requests. Please try again later.",
    },
  });
  app.use(limiter);

  // ── Body parsers ───────────────────────────────────────────────────
  app.use(require("express").json({ limit: "10kb" }));
  app.use(require("express").urlencoded({ extended: true, limit: "10kb" }));
}

module.exports = applyMiddleware;
