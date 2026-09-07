const crypto = require("crypto");

/**
 * In-memory job store.
 * Keys are job IDs, values are job objects:
 * {
 *   id: "string",
 *   target: "string",
 *   status: "pending" | "scanning" | "parsing" | "enriching" | "completed" | "failed",
 *   createdAt: Date,
 *   result: object | null,
 *   error: string | null
 * }
 */
const jobs = new Map();

/**
 * Creates a new job and returns its ID.
 */
function createJob(target) {
  const id = crypto.randomUUID();
  const job = {
    id,
    target,
    status: "pending",
    createdAt: new Date(),
    result: null,
    error: null,
  };
  jobs.set(id, job);
  return id;
}

/**
 * Retrieves a job by ID.
 */
function getJob(id) {
  return jobs.get(id) || null;
}

/**
 * Updates a job's status and optional result or error.
 */
function updateJob(id, updates) {
  const job = jobs.get(id);
  if (!job) return false;

  Object.assign(job, updates);
  jobs.set(id, job);
  return true;
}

module.exports = {
  createJob,
  getJob,
  updateJob,
};
