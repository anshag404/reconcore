const { spawn } = require("child_process");

// ── Input validation ─────────────────────────────────────────────────
// Strict whitelist: IPv4, IPv6, or hostname only. Prevents command injection.
const TARGET_REGEX =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d))?$|^[a-fA-F0-9:]+(?:\/(?:12[0-8]|1[01]\d|\d{1,2}))?$/;

const DEFAULT_TIMEOUT_MS = 120_000; // 2 minutes

// ── Flag allowlist ───────────────────────────────────────────────────
// Callers may pass extra nmap flags, so treat them as untrusted input: an
// unrestricted list would let a caller write files anywhere this process can
// (-oN/-oA), read arbitrary target lists (-iL), or run NSE scripts (--script).
// Anything not named here is refused, including bare words, which nmap would
// otherwise read as additional scan targets.
const ALLOWED_FLAGS = new Set([
  // Timing templates
  "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
  // Host discovery
  "-Pn", "-sn", "-n", "-R",
  // Scan techniques
  "-sS", "-sT", "-sU", "-sV", "-sC", "-sA", "-sW",
  // Port selection shorthands
  "-F", "-p-", "-r",
  // Detection
  "-O", "-A",
  // Output verbosity (structured output stays owned by this module)
  "-v", "-vv", "--open", "--reason",
  // Address family
  "-4", "-6",
]);

// Flags that take a separate value argument, with the shape that value must have.
const ALLOWED_VALUE_FLAGS = new Map([
  ["-p", /^[\d,\-]{1,64}$/],
  ["--top-ports", /^\d{1,5}$/],
  ["--max-retries", /^\d{1,2}$/],
  ["--host-timeout", /^\d{1,7}m?s?$/],
]);

// Combined forms such as "-p80,443" or "-p1-1000".
const INLINE_PORT_FLAG = /^-p[\d,\-]{1,64}$/;

/**
 * Validates caller-supplied nmap flags against the allowlist.
 *
 * @param {string[]} flags
 * @returns {string[]} the same flags, when every one is permitted
 * @throws {Error} naming the first flag that is not
 */
function validateFlags(flags) {
  if (!Array.isArray(flags)) return [];

  for (let i = 0; i < flags.length; i += 1) {
    const flag = flags[i];

    if (typeof flag !== "string") {
      throw new Error(`Disallowed nmap flag: expected a string, received ${typeof flag}`);
    }

    if (ALLOWED_FLAGS.has(flag) || INLINE_PORT_FLAG.test(flag)) continue;

    if (ALLOWED_VALUE_FLAGS.has(flag)) {
      const value = flags[i + 1];
      const pattern = ALLOWED_VALUE_FLAGS.get(flag);

      if (typeof value !== "string" || !pattern.test(value)) {
        throw new Error(`Disallowed nmap flag: "${flag}" has a missing or invalid value`);
      }

      i += 1; // consume the value
      continue;
    }

    throw new Error(`Disallowed nmap flag: "${flag}"`);
  }

  return flags;
}

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
    let extraFlags;
    try {
      extraFlags = validateFlags(options.flags);
    } catch (flagError) {
      return reject(flagError);
    }

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

module.exports = { runNmapScan, validateFlags, ALLOWED_FLAGS };
