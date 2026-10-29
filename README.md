# 🛡️ CyberVigil AI - Advanced Threat Intelligence & Payload Sandbox Hub
> **BCA Final Year Project | Cybersecurity & Threat Modeling Capstone**  
> *Full-Stack Threat Intelligence Platform featuring Heuristic URL Analysis, Byte-Entropy Payload Sandboxing, Real-Time Cloud Telemetry with MongoDB Atlas, and a Futuristic Cyber-Command Dashboard.*

---

## 📋 Table of Contents
1. [Project Overview & Key Highlights](#-project-overview--key-highlights)
2. [Folder Structure](#-folder-structure)
3. [Technology Stack](#-technology-stack)
4. [Step-by-Step Installation & Setup](#-step-by-step-installation--setup)
5. [Connecting to MongoDB Atlas (Cloud Database)](#-connecting-to-mongodb-atlas-cloud-database)
6. [Core Architectural Features](#-core-architectural-features)
   - [Zero-Friction Access & Trust Banner](#1-zero-friction-access--trust-banner)
   - [URL Heuristic & Phishing Scanner](#2-url-heuristic--phishing-scanner)
   - [File & Payload Static Analyzer](#3-file--payload-static-analyzer)
   - [Real-Time Telemetry & Cloud Audit Trail](#4-real-time-telemetry--cloud-audit-trail)
   - [Cybersecurity Awareness & Academy](#5-cybersecurity-awareness--academy)
7. [REST API Documentation](#-rest-api-documentation)
8. [🎓 BCA Final Year Project Viva & Presentation Guide](#-bca-final-year-project-viva--presentation-guide)

---

## 🌟 Project Overview & Key Highlights

**CyberVigil AI** is a next-generation web-based cybersecurity intelligence platform designed to address the surging threat of spearphishing campaigns, credential theft, and weaponized payload scripts.

### Key Highlights:
- **Zero-Friction Direct Access:** No mandatory sign-up walls; instant access to enterprise-grade threat scanning tools.
- **Futuristic 'Cyber-Command' Dark UI:** Engineered with Tailwind CSS, neon cyan/green/crimson accents, interactive SVG gauges, scanlines, and audio synthesizers via Web Audio API.
- **Dual Heuristic Engines:**
  - **URL / Phishing Engine:** Detects homograph punycode attacks (`xn--`), brand impersonation, high-abuse TLDs, IP literal targets, algorithmic domain fluxing (DGA), and bait keywords.
  - **File Payload Analyzer:** Computes cryptographic hashes (MD5, SHA-1, SHA-256), calculates **Shannon Byte Entropy (0.0 - 8.0)** to detect packed/encrypted malware, spots masqueraded double extensions (`.pdf.exe`), and matches PowerShell download cradles, process hollowing, and ransomware shadow-copy deletion signatures.
- **Cloud Database (MongoDB Atlas) with Zero-Downtime Fallback:** Synchronizes all audit logs with cloud MongoDB Atlas while maintaining a resilient in-memory fallback engine so the app **never crashes** if cloud connectivity is interrupted during an evaluation.
- **MITRE ATT&CK® Framework Mapping:** Automatically tags threats with formal industry adversary techniques (e.g. `T1566.002`, `T1036.007`, `T1059.001`, `T1027`).

---

## 📁 Folder Structure

```
CyberVigil AI/
├── config/
│   └── db.js                 # MongoDB Atlas cloud connection & graceful in-memory fallback
├── models/
│   └── ScanLog.js            # Mongoose schema + transparent database abstraction layer
├── routes/
│   └── scanRoutes.js         # Express REST API routes for URL, File, History, and Stats
├── services/
│   ├── urlScanner.js         # Advanced URL heuristic scanner, entropy, brand checks
│   └── fileScanner.js        # Payload byte analyzer, Shannon entropy, signature matching
├── public/
│   ├── css/
│   │   └── style.css         # Futuristic cyber-command theme, radar sweeps & glow effects
│   ├── js/
│   │   └── app.js            # Frontend logic, Web Audio synthesizer & multi-page handlers
│   ├── index.html            # Page 1: Landing & Welcome Page (/)
│   ├── scanner.html          # Page 2: Threat Scanner Console (/scanner)
│   ├── official-links.html   # Page 3: Official Test Links Hub (/official-links)
│   ├── session-history.html  # Page 4: Temporary Session Scan History (/session-history)
│   └── security-academy.html # Page 5: Defensive Intelligence Security Academy (/security-academy)
├── .env                      # Active environment configuration
├── .env.example              # Template configuration
├── package.json              # Project metadata and dependencies
├── server.js                 # Express server bootstrap, multi-page view routes & middleware
└── README.md                 # Complete project documentation and viva preparation guide
```
│   │   └── app.js            # Frontend logic, Web Audio synthesizer, live gauges, toast alerts
│   └── index.html            # Single Page Application (Hero, Scanners, Audit Trail, Academy)
├── .env                      # Active environment configuration
├── .env.example              # Template configuration
├── package.json              # Project metadata and dependencies
├── server.js                 # Express server bootstrap, middleware, and health probes
└── README.md                 # Complete project documentation and viva preparation guide
```

---

## 🛠️ Technology Stack

| Layer | Technologies Used |
|---|---|
| **Frontend** | HTML5, Tailwind CSS, FontAwesome 6, Google Fonts (Orbitron & JetBrains Mono), Web Audio API |
| **Backend** | Node.js, Express.js, Multer (streaming memory buffer uploads) |
| **Security & Middleware** | Helmet, CORS, Morgan |
| **Database** | MongoDB Atlas (Cloud NoSQL) via Mongoose (with auto in-memory fallback) |
| **Cryptography & Algorithms** | Node Crypto (MD5, SHA-1, SHA-256), Shannon Entropy Formula ($H(X) = -\sum P(x) \log_2 P(x)$), MITRE ATT&CK Taxonomy |

---

## 🚀 Step-by-Step Installation & Setup

### 1. Prerequisites
- **Node.js** (v18.0.0 or higher recommended)
- **npm** (comes bundled with Node.js)

### 2. Install Dependencies
Open PowerShell or your preferred terminal in the project directory:
```powershell
npm install
```

### 3. Configure Environment Variables
Verify your `.env` file exists in the root folder (a template is provided in `.env.example`):
```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/cybervigil?retryWrites=true&w=majority
DB_FALLBACK=true
```

### 4. Start the Application
Run the start command:
```powershell
npm start
```

For live code auto-reload during development:
```powershell
npm run dev
```

### 5. Access the Web Application
Open your browser and navigate to:
```
http://localhost:5000
```

---

## ☁️ Connecting to MongoDB Atlas (Cloud Database)

CyberVigil AI is built to connect to a free MongoDB Atlas cloud cluster:

1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) and sign in or create a free account.
2. Create a free **M0 Shared Cluster**.
3. Under **Database Access**, create a database user (e.g., username `admin`, choose a secure password).
4. Under **Network Access**, click **Add IP Address** and select **Allow Access from Anywhere** (`0.0.0.0/0`) or your local IP.
5. In your cluster dashboard, click **Connect** -> **Drivers** (Node.js).
6. Copy the connection string and paste it into your `.env` file:
   ```env
   MONGODB_URI=mongodb+srv://admin:YourPasswordHere@cluster0.abcde.mongodb.net/cybervigil?retryWrites=true&w=majority
   ```
7. Restart the server with `npm start`. You will see:
   ```
   ✓ [MongoDB Atlas] Connected securely to host: cluster0-shard-00-00.abcde.mongodb.net
   ```

> **Note for Evaluators:** If `MONGODB_URI` contains placeholder values or is left unset, CyberVigil AI automatically activates its **High-Performance Resilient In-Memory Engine**. All scan logging, audit trails, and statistics work seamlessly out of the box with zero runtime errors!

---

## 🎯 Core Architectural Features

### 1. Zero-Friction Access & Trust Banner
- Users land directly onto the Cyber-Command Console without forced registration.
- Prominently showcases the **"100% Trusted & Secure Threat Intelligence Hub"** badge with live DEFCON status, pulse animations, and real-time security telemetry.

### 2. URL Heuristic & Phishing Scanner
- **Target Normalization:** Parses complex URL schemes, ports, and paths.
- **Brand Impersonation Detection:** Flags unauthorized usage of high-value brands (PayPal, Microsoft, Apple, Google, Chase Bank, Netflix, Binance, Steam, etc.).
- **Shannon Entropy Analysis:** Computes domain and path entropy to catch Domain Generation Algorithms (DGA).
- **Abuse TLD Auditing:** Identifies high-risk disposable TLDs (`.xyz`, `.top`, `.tk`, `.click`, `.buzz`, etc.).
- **IP-Literal Detection:** Flags raw IPv4/IPv6 addresses used to bypass DNS domain blocking.
- **Punycode / Homograph Attack Detection:** Alerts on internationalized character spoofing (`xn--`).
- **Action Triggers:** Flags urgent social engineering keywords (`verify`, `suspend`, `wallet`, `kyc`, `password-reset`).

### 3. File & Payload Static Analyzer
- **Drag-and-Drop / Browse Interface:** Upload files up to 25MB directly into memory for sandbox inspection.
- **Safe Simulated Test Vectors:** Included buttons allow evaluators to instantly test clean vs malicious payloads without needing actual virus files!
- **Cryptographic Signatures:** Generates MD5, SHA-1, and SHA-256 hashes with one-click clipboard copying.
- **Byte Shannon Entropy (0.0 to 8.0):** Detects cryptographic packing (e.g. UPX), encrypted secondary shellcodes, and ransomware blobs.
- **Double Extension Detection:** Intercepts classic spearphishing vectors like `invoice.pdf.exe` or `report.docx.bat`.
- **Deep Signature Matching:** Detects PowerShell download cradles, Windows process injection APIs (`VirtualAlloc`, `CreateRemoteThread`), anti-debugging tricks, and ransomware shadow-copy deletion (`vssadmin delete shadows`).

### 4. Real-Time Telemetry & Cloud Audit Trail
- Synchronous persistence to MongoDB Atlas.
- Live feed displays target, timestamp, threat score, and verdict.
- **JSON Export:** Download full telemetry logs for SOC reporting and academic documentation.

### 5. Cybersecurity Awareness & Academy
- **How to Identify Phishing Links:** Anatomy breakdown of deceptive URLs.
- **Common Email & Social Engineering Scams:** Spearphishing, BEC, and urgent scareware analysis.
- **Password Safety Matrix:** Password hygiene and multi-factor authentication principles.
- **Interactive Password Entropy Calculator:** Live client-side calculation of bits of entropy ($L \times \log_2(N)$) and brute-force time estimates.
- **Incident Response Checklist:** Practical step-by-step containment protocol.

---

## 📡 REST API Documentation

### 1. Scan URL
- **Endpoint:** `POST /api/scan/url`
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "url": "http://secure-paypal-verification.servehttp.com/login.php"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "targetType": "url",
    "target": "http://secure-paypal-verification.servehttp.com/login.php",
    "threatScore": 100,
    "status": "MALICIOUS",
    "riskLevel": "CRITICAL",
    "summary": "CRITICAL THREAT DETECTED: This URL exhibits severe indicators...",
    "indicators": {
      "clean": ["Valid DNS FQDN Addressing"],
      "suspicious": ["Unencrypted Transport", "High Hostname Entropy"],
      "malicious": ["Brand Impersonation Target: PayPal"]
    },
    "hashes": {
      "sha256": "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72"
    },
    "heuristics": [...],
    "mitreAttack": ["T1036.007 - Masquerading", "T1566.002 - Spearphishing Link"]
  }
  ```

### 2. Scan File Payload
- **Endpoint:** `POST /api/scan/file`
- **Headers:** `multipart/form-data`
- **Body:** `payload` (File stream, max 25MB)
- **Response:** Returns threat score, entropy ($0.0 - 8.0$), MD5, SHA-1, SHA-256 hashes, and matched exploit signatures.

### 3. Get Recent Scans History
- **Endpoint:** `GET /api/scans/history?limit=25`
- **Response:** Array of historical scan objects stored in MongoDB Atlas.

### 4. Get Telemetry Statistics
- **Endpoint:** `GET /api/scans/stats`
- **Response:** Counters for total scans, threats neutralized, clean targets, and cloud DB status.

### 5. Health Probe
- **Endpoint:** `GET /api/health`
- **Response:** Engine status and database connection details.

---

## 🎓 BCA Final Year Project Viva & Presentation Guide

### 1. Project Title & Problem Statement
- **Title:** *CyberVigil AI: An Intelligent Multi-Vector Threat Intelligence & Payload Sandbox Engine.*
- **Problem Statement:** Traditional antivirus solutions rely heavily on static signature databases that fail against zero-day phishing domains and obfuscated scripts. CyberVigil AI applies heuristic pattern extraction, Shannon entropy evaluation, and brand masquerading detection to uncover unknown threats before execution.

### 2. Key Theoretical Concepts to Explain

#### A. Shannon Entropy in Cybersecurity
- **Formula:** $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$
- **Application:** Measures the randomness of bytes in a payload or characters in a domain name.
  - Normal text / code has an entropy of ~`2.0` to `5.5`.
  - Obfuscated, encrypted, or packed malware (e.g. UPX, Cobalt Strike beacons) has an entropy of **`> 7.0`**, indicating non-natural distribution.

#### B. Heuristics vs. Signature Matching
- **Signatures:** Match exact byte sequences or hashes (e.g., MD5/SHA-256). Fast, but fail if an attacker changes a single byte.
- **Heuristics:** Analyze structural attributes, behavior patterns, and linguistic indicators (e.g., presence of `powershell -enc`, double extensions, IP literals, punycode).

#### C. MITRE ATT&CK® Framework
- An internationally recognized knowledge base of adversary tactics and techniques based on real-world observations.
- In CyberVigil AI, we map detected heuristics directly to MITRE IDs (e.g., `T1566.002` for Spearphishing Link, `T1036.007` for Masquerading Double File Extensions).

### 3. Top Expected Viva Questions & Answers

**Q1: How does CyberVigil AI detect phishing links that haven't been reported yet?**  
*Answer:* Through multi-layered heuristic analysis. We dissect the domain into root and subdomains, compute character entropy, inspect the TLD abuse rating, check if trusted brand names appear outside their legitimate root domains, and detect punycode (`xn--`) homograph tricks.

**Q2: What is the purpose of computing SHA-256 and MD5 hashes?**  
*Answer:* Cryptographic hashing produces a unique digital fingerprint of the target or payload. If the file is altered by even one bit, the hash changes completely (avalanche effect). These hashes allow threat analysts to query global threat databases (like VirusTotal or AlienVault OTX) without uploading the original sensitive payload.

**Q3: How does the application handle database failures?**  
*Answer:* CyberVigil AI implements a resilient Repository Pattern in `models/ScanLog.js` and `config/db.js`. If MongoDB Atlas is unreachable or the connection string is omitted, it automatically falls back to an in-memory data store, ensuring 100% uninterrupted uptime during evaluation.

**Q4: Why is Multer memory storage used instead of saving files to the hard drive?**  
*Answer:* Storing untrusted executable payloads directly on the server's disk presents a severe security risk (drive-by execution or unauthorized web access). By reading files directly into a memory buffer (`multer.memoryStorage()`), the engine performs static analysis safely in volatile RAM without persisting malicious binaries to the host filesystem.

---

### 🛡️ Developed for Academic Excellence & Practical Cyber Defense
*CyberVigil AI — BCA Final Year Project 2026.*

