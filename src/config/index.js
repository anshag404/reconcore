const dotenv = require("dotenv");
dotenv.config();

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || "development",
  cors: {
    // Comma-separated list, so the API can serve the Vite dev server and any
    // other front end at once. Defaults to Vite's dev origin, which is where
    // the React app actually runs — the API's own port is not a browser origin.
    origin: (process.env.CORS_ORIGIN || "http://localhost:5173,http://localhost:4173")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  },
};

module.exports = config;
