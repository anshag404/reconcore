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

### Option A: Running with Docker (Recommended)
This is the easiest way to run ReconCore. It automatically bundles the Node.js backend, the built React frontend, and the required Nmap binaries into an isolated container.

**Prerequisites:**
- **Docker** and **Docker Compose**

1. **Clone the repository**:
   ```bash
   git clone https://github.com/anshag404/reconcore.git
   cd reconcore
   ```
2. **(Optional) Add NVD API Key**:
   Create a `.env` file in the root directory to increase CVE lookup rate limits:
   ```env
   NVD_API_KEY=your_key_here
   ```
3. **Build and Start**:
   ```bash
   docker-compose up --build
   ```
Navigate to `http://localhost:3000` in your browser.

### Option B: Local Development
If you want to modify the code and run the split frontend/backend architecture locally:

**Prerequisites:**
- **Node.js** (v18+)
- **Nmap**: Must be installed on your host machine and accessible in your PATH.

1. **Install Backend Dependencies**:
   ```bash
   npm install
   ```
2. **Install Frontend Dependencies**:
   ```bash
   cd frontend
   npm install
   ```
3. **Run the Application**:
   Open two terminal windows:
   - Terminal 1 (Backend): `npm run dev` (from root directory)
   - Terminal 2 (Frontend): `npm run dev` (from `frontend/` directory)
   
Navigate to `http://localhost:5173` in your browser.

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