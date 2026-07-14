# WebShield SDK 🛡️

A plug-and-play, enterprise-grade security SDK, Web Application Firewall (WAF), and Threat Intelligence client designed to secure Node.js (Express) backends against malicious requests, unauthorized access, and credential leakage.

---

## 🚀 Key Upgrades & Features Built

### 1. Core Threat Scoring Engine (`src/core/threatScore.js`)
* **Heuristics Scanner**: Scans query parameters, request bodies, and headers for XSS scripts, SQL injection strings, and NoSQL mongo operators.
* **Risk Classifications**: Dynamically computes request threat scores (0–100) and groups requests into risk tiers:
  * **LOW**: Request flows normally.
  * **MEDIUM**: Triggers authorization challenges / CAPTCHA responses.
  * **CRITICAL**: Triggers immediate IP blocking.
* **Secret Leak Scanner**: Detects patterns for sensitive secrets (Google API Keys, AWS credentials, JWT tokens, Stripe live keys, Slack tokens) to prevent key leaks.
* **Fingerprinting**: Generates browser/device MD5 request fingerprints based on headers (User-Agent, languages, encoding) and IP data.

### 2. Custom Web Application Firewall (`src/core/engine.js`)
* **WAF Rules Engine**: Allows registering custom rules to block specific routing paths, malicious header values, or unwanted request parameters before full scoring runs.
* **Security Headers**: Inject helmet-like defensive headers (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Content-Security-Policy`).

### 3. Advanced Rate Limiting & Honeypots
* **Sliding Window Rate Limiting (`src/middleware/rateLimiter.js`)**: Tracks requests within sliding windows to protect against flood attacks, supporting user-based throttling.
* **Burst Detection**: Blocks IPs showing sudden, rapid bursts of requests in sub-second windows.
* **Honeypot Decoy Traps (`src/middleware/honeypot.js`)**: Configures standard trap paths (e.g. `/.env`, `/admin`, `/wp-admin`). Accessing any trap triggers instant IP blacklisting.

### 4. IP Intelligence & Network Security (`src/middleware/ipBlocker.js` & `src/services/ipIntel.js`)
* **Accurate IP Resolution**: Uses the `request-ip` library to extract actual client IPs (bypassing proxies, load balancers, or Cloudflare proxies).
* **Geo-location Blocks**: Uses `geoip-lite` to automatically resolve country locations and block regions (e.g. `RU`, `CN`).
* **CIDR Range Blocks**: Integrates `ip-range-check` to match IP addresses against single entries or custom CIDR subnets (e.g., `203.0.113.0/24`).
* **Reputation Intelligence**: Caches VPN, Tor, and Abuse IP signatures.

### 5. Extensible Plugin Marketplace (`src/index.js`)
* Plug-in customized security behaviors (e.g., custom `ddosPlugin`, `botDetectionPlugin`, `sqlInjectionPlugin`) seamlessly.

### 6. SaaS Sync & Smart Alerts
* **Real-time SaaS Sync (`src/services/cloudSync.js`)**: Integrates socket.io clients to asynchronously stream security logs to centralized dashboards.
* **Smart Alert Notifier (`src/services/alertService.js`)**: Connects to Nodemailer and webhooks to trigger high-priority alerts on critical threats.

---

## ⚡ Ultra-Advanced Upgrades

* **Redis-Backed Distributed Rate Limiting (`src/middleware/rateLimiter.js`)**: Integrated `ioredis` support to synchronize rate limits and banned lists across multiple nodes with automatic in-memory fallback.
* **IP Allowlist Protection**: Added an allowlist system to prevent false positives and bypass scanning checks for trusted administration IPs.
* **SHA-256 Fingerprinting (`src/core/threatScore.js`)**: Upgraded MD5 calculations to cryptographic SHA-256 for request signatures.
* **Log Volume Sampling (`src/core/logger.js`)**: Implemented log sampling rate logic to drop redundant info logs during attack floods and protect write capabilities.
* **Request Correlation IDs**: Generates unique Request IDs (`req.id`) for all incoming connection streams and logs.
* **JWT & API Abuse Protection (`src/core/threatScore.js`)**: Real-time JWT structure anomaly scanning, token expiration monitoring, and endpoint-specific brute-force checking (e.g. `/login`, `/otp`).
* **Dynamic Ban Durations (`src/middleware/rateLimiter.js`)**: Ban length dynamically scales based on threat complexity (`banTime = baseTime * (threatScore / 10)`).
* **Live Security Dashboard Viewer (`src/core/engine.js`)**: Real-time event log streaming visualizer served directly on `/webshield/dashboard`.
* **Dynamic & Customizable CORS (`src/middleware/corsGuard.js`)**: Resolves CORS errors for npm users by implementing smart dynamic checks supporting regular expressions, wildcards, server-to-server bypass, and dev-mode auto-allows.
* **Zero-Trust System Isolation Mode (`src/core/engine.js`)**: Emergency lockdown option (`isolated: true`) that blocks all incoming requests with a 503 response, excluding those coming from the administrative IP `allowlist`.

---

## 📁 Directory Structure

```bash
webshield-sdk/
│
├── src/
│   ├── core/
│   │   ├── config.js         # Configuration loader & defaults
│   │   ├── engine.js         # WAF rules, middleware orchestrator
│   │   ├── logger.js         # Winston logger configuration
│   │   ├── threatScore.js    # Threat score calculator & secret scanner
│   │
│   ├── middleware/
│   │   ├── csrfGuard.js      # CSRF verification
│   │   ├── honeypot.js       # Honeypot decoy blocks
│   │   ├── ipBlocker.js      # Geo-blocking, CIDR range verification
│   │   ├── rateLimiter.js    # Sliding window rate limiter & IP banning
│   │   ├── xssGuard.js       # XSS payload sanitizer
│   │
│   ├── services/
│   │   ├── alertService.js   # Nodemailer and webhook alerts
│   │   ├── cloudSync.js      # Socket.io cloud telemetry sync
│   │   ├── ipIntel.js        # IP reputation and VPN/Tor detection
│   │
│   ├── plugins/
│   │   ├── botDetection.js   # Scraper/crawler blocks
│   │   ├── ddosPlugin.js     # DDoS flood filters
│   │   ├── sqlInjection.js   # Advanced SQLi checking
│   │
│   ├── utils/
│   │   ├── helpers.js        # Client IP extraction & validator helpers
│   │
│   └── index.js              # Entrypoint file
│
├── package.json              # Full production dependencies list
├── test_app.js               # Demonstration Express test server
└── README.md                 # Document overview
```

---

## ⚡ Integration Workflow

```js
const express = require('express');
const { webShield, plugins } = require('webshield-sdk');

const app = express();
app.use(express.json());

// Enable WebShield security
app.use(webShield({
  apiKey: "your_prod_key",
  mode: "strict",
  
  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true
  },
  
  waf: {
    enabled: true,
    rules: [
      { type: 'path', action: 'block', value: '/confidential' }
    ]
  },
  
  rateLimit: {
    windowMs: 60000,
    max: 100
  },
  
  honeypot: {
    enabled: true,
    paths: ['/.env', '/admin']
  },
  
  plugins: [
    plugins.botDetectionPlugin({ blockCrawlers: true })
  ]
}));
```

---

## 🛠️ Testing Verification

To run and verify:

1. **Install dependencies**:
   ```bash
   npm install
   ```
2. **Run Automated Unit Tests**:
   ```bash
   npm test
   ```
   *(Executes [test.js](file:///Users/laptopbazaar/Desktop/Rakshak%20AI/test.js) checking Threat Scoring heuristics and Dynamic CORS policies)*

3. **Start the test server**:
   ```bash
   npm start
   ```
4. **Verify manual actions**:
   * Visit `http://localhost:3000/admin` to trigger honeypot blacklisting.
   * Visit `http://localhost:3000/confidential` to trigger WAF blocking.
   * Send a POST request to `http://localhost:3000/submit` containing a simulated Google API Key `AIzaSyB123abc456def789...` to test Secret Leak Blocking.

---

## 🚀 CI/CD Pipeline
An automated GitHub Actions CI/CD configuration is located in [.github/workflows/ci.yml](file:///Users/laptopbazaar/Desktop/Rakshak%20AI/.github/workflows/ci.yml). It automatically runs on pulls/pushes targeting `main` or `master` across multiple Node.js environments (v18, v20, v22).
