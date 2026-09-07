# ReconCore 🎯

ReconCore is a centralized attack surface management and network reconnaissance platform. It combines the power of active Nmap network sweeps with real-time vulnerability intelligence (NVD) to provide actionable insights, visual network topologies, and comprehensive security reports.

## Architecture Flow

ReconCore is built on a split architecture separating the presentation layer from the heavy network scanning engine.

1. **Frontend (React/Vite)**: 
   - Provides a responsive, cyberpunk-themed UI.
   - Polls the backend API asynchronously to prevent UI freezes during long scans.
   - Renders interactive network maps using `react-force-graph-2d` and handles PDF/CSV reporting.
2. **Backend (Express/Node.js)**: 
   - Acts as an asynchronous job queue.
   - Spawns local `nmap` child processes to execute network sweeps.
   - Parses the XML output from Nmap using `xml2js`.
   - Queries the National Vulnerability Database (NVD) via a rate-limited HTTP client to cross-reference discovered services with known CVEs.

## Setup Instructions

### Prerequisites
- **Node.js** (v18+)
- **Nmap**: Must be installed and accessible in your system's PATH. (On Windows, installing Nmap with Npcap is recommended).

### Installation

1. **Clone the repository** (if you haven't already).
2. **Install Backend Dependencies**:
   ```bash
   cd reconcore
   npm install
   ```
3. **Install Frontend Dependencies**:
   ```bash
   cd reconcore/frontend
   npm install
   ```
4. **Environment Variables**:
   In the root of `reconcore`, create a `.env` file:
   ```env
   PORT=3000
   # Optional: Add your NVD API key to increase rate limits (from 5 to 50 req/30s)
   NVD_API_KEY=your_nvd_api_key_here
   ```
   In the `reconcore/frontend` directory, create a `.env` file:
   ```env
   VITE_API_BASE_URL=http://localhost:3000
   ```

### Running the Application

Open two terminal windows.

**Terminal 1 (Backend):**
```bash
cd reconcore
npm run dev
```

**Terminal 2 (Frontend):**
```bash
cd reconcore/frontend
npm run dev
```

Navigate to `http://localhost:5173` in your browser to access the ReconCore Command Center.

---

## API Documentation

The backend exposes an asynchronous job queue for handling long-running network scans to prevent gateway timeouts.

### 1. Initiate a Scan

**Endpoint:** `POST /api/scan`

Starts a new Nmap scan job in the background and returns a unique Job ID.

**Request Body (JSON):**
```json
{
  "target": "scanme.nmap.org",
  "profile": "detailed" 
}
```
*Note: Valid profiles are `fast`, `detailed`, and `stealth`.*

**Response (202 Accepted):**
```json
{
  "message": "Scan queued successfully",
  "jobId": "c88f03d6-9311-4550-8429-9194ddef63d1"
}
```

### 2. Poll Scan Status

**Endpoint:** `GET /api/scan/:jobId`

Retrieves the current status of the scan, and the final results if the scan is completed.

**Response (200 OK) - Pending/Scanning:**
```json
{
  "id": "c88f03d6-9311-4550-8429-9194ddef63d1",
  "target": "scanme.nmap.org",
  "status": "scanning",
  "progress": {
    "percent": 45,
    "timeRemaining": 12,
    "task": "SYN Stealth Scan"
  }
}
```

**Response (200 OK) - Completed:**
```json
{
  "id": "c88f03d6-9311-4550-8429-9194ddef63d1",
  "target": "scanme.nmap.org",
  "status": "completed",
  "result": {
    "meta": { "target": "scanme.nmap.org" },
    "scanInfo": { "version": "7.94" },
    "runStats": { "hostsUp": 1, "elapsed": "16.8" },
    "hosts": [ ... ],
    "vulnerabilities": [ ... ]
  }
}
```

**Response (404 Not Found):**
If the `jobId` does not exist in memory.
```json
{
  "error": "Job not found"
}
```