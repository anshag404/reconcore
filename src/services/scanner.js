const { spawn } = require("child_process");

// ── Input validation ─────────────────────────────────────────────────
// Strict whitelist: IPv4, IPv6, or hostname only. Prevents command injection.
const TARGET_REGEX =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$|^[a-fA-F0-9:]+$/;

const DEFAULT_TIMEOUT_MS = 120_000; // 2 minutes

/**
 * Executes `nmap -sV -oX - <target>` as a child process.
 *
 * @param {string} target        - IPv4, IPv6, or hostname to scan
 * @param {object} [options]     - Optional overrides
 * @param {number} [options.timeout] - Kill after N ms (default 120 000)
 * @param {string[]} [options.flags] - Extra nmap flags (e.g. ['-p', '80,443'])
 * @returns {Promise<{ stdout: string, stderr: string, code: number|null }>}
 */
function runNmapScan(target, options = {}) {
  return new Promise((resolve, reject) => {
    // ── Validate target ──────────────────────────────────────────────
    if (!target || typeof target !== "string") {
      return reject(new Error("Target is required and must be a string."));
    }

    const sanitized = target.trim();
    if (!TARGET_REGEX.test(sanitized)) {
      return reject(
        new Error(
          `Invalid target "${sanitized}". Must be a valid IPv4, IPv6, or hostname.`
        )
      );
    }

    const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    const extraFlags = Array.isArray(options.flags) ? options.flags : [];

    // ── Build args ───────────────────────────────────────────────────
    // -sV   : service/version detection
    // -oX - : XML output to stdout
    const args = ["-sV", "-oX", "-", ...extraFlags, sanitized];

    console.log(`[scanner] Spawning: nmap ${args.join(" ")}`);

    // ── Spawn ────────────────────────────────────────────────────────
    // No shell: true → no injection vector
    const child = spawn("nmap", args, {
      shell: false,
      windowsHide: true,
    });

    const stdoutChunks = [];
    const stderrChunks = [];

    child.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    child.stderr.on("data", (chunk) => stderrChunks.push(chunk));

    // ── Timeout guard ────────────────────────────────────────────────
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(`Nmap scan timed out after ${timeout}ms for target: ${sanitized}`)
      );
    }, timeout);

    // ── Exit handling ────────────────────────────────────────────────
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start nmap: ${err.message}`));
    });

    child.on("close", (code) => {
      clearTimeout(timer);

      const stdout = Buffer.concat(stdoutChunks).toString("utf-8");
      const stderr = Buffer.concat(stderrChunks).toString("utf-8");

      if (stderr) {
        // Nmap writes progress & warnings to stderr — log but don't fail
        console.warn(`[scanner] stderr:\n${stderr}`);
      }

      resolve({ stdout, stderr, code });
    });
  });
}

module.exports = { runNmapScan };
