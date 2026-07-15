# WebShield SDK 🛡️

An enterprise-grade, plug-and-play Security SDK, Web Application Firewall (WAF), and Threat Intelligence middleware designed to secure Node.js (Express) backends against malicious requests, brute-force exploits, automated scrapers, and sensitive credential leakage.

```bash
npm install webshield-sdk
```

---

## 🎁 What You Get (Features & Layout)

By installing WebShield, you get a comprehensive, unified security suite that integrates features traditionally requiring 10+ separate npm packages:

*   **🛡️ Core Threat Scoring Engine (`src/core/threatScore.js`)**: Real-time heuristics scanning (XSS tags, SQL Injection sequences, NoSQL operators) that maps request threat levels (0–100) and triggers automated responses.
*   **🌐 WAF & Security Headers (`src/core/engine.js`)**: Injects helmet-like defensive headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, etc.) and evaluates custom routing firewall rules.
*   **🚦 Distributed Rate Limiting (`src/middleware/rateLimiter.js`)**: Sliding window rate limiting backed by Redis (using `ioredis`) for multi-server setups with automatic in-memory fallback.
*   **🪓 Decoy Honeypot Traps (`src/middleware/honeypot.js`)**: Instantly bans attackers attempting to scan directories like `/.env` or `/wp-admin`.
*   **🌎 Geo-Location & CIDR IP Intelligence (`src/middleware/ipBlocker.js`)**: Restricts access from specific countries (via `geoip-lite`) and blocks custom IP CIDR ranges (e.g., `203.0.113.0/24`).
*   **🔐 Secret Leak Guard**: Automatically scans, blocks, and redacts leaked API keys (AWS, Google APIs, Stripe Live Keys, JWT structures) inside query strings or body data.
*   **📊 Live Event Logs Visualizer**: A real-time dashboard served directly at `/webshield/dashboard` on your local server.
*   **🧬 Dynamic CORS Engine (`src/middleware/corsGuard.js`)**: Safe dynamic origin evaluations using RegEx or IP checks to eliminate client integration errors.
*   **🔒 Zero-Trust System Isolation Mode**: Emergency lockdown (`isolated: true`) that restricts your server only to IP allowlists during active incident responses.

---

## 🌟 Key Benefits of WebShield SDK

1.  **Unified Middleware footprint**: Replaces `helmet`, `cors`, `express-rate-limit`, `express-mongo-sanitize`, `xss-clean`, and `hpp` with a single, highly-optimized client stack.
2.  **Adaptive Security Tiers**: Instead of simple binary blocking, requests are graded into Low, Medium, and Critical risks. Medium risks can be configured to request CAPTCHAs or MFA challenge triggers, preserving customer experience.
3.  **Distributed & Fault-Tolerant**: Real-time rate limits sync across nodes using Redis. If Redis goes down, WebShield automatically reverts to in-memory mode, keeping your API online while sending alert emails to the admin.
4.  **Zero-Trust Honeypots**: Traps standard bot scanning paths to ban malicious scanner IPs before they hit your real business routes.
5.  **Tamper-Resistant Runtime**: Uses `Object.freeze` to lock active security configurations in memory, preventing prototype pollution or runtime memory exploits.

---

## ⚡ How to Use

Setting up WebShield in your Express application is simple and requires only a few lines of code.

### 1. Basic Integration

```javascript
const express = require('express');
const { webShield } = require('webshield-sdk');

const app = express();
app.use(express.json());

// Enable WebShield with Default Options
app.use(webShield({
  apiKey: "your_license_key_here",
  mode: "strict" // "strict" to block threats instantly, "monitor" to log only
}));

app.listen(3000, () => console.log('Secure server running on port 3000'));
```

### 2. Advanced Enterprise Configuration

```javascript
const express = require('express');
const { webShield, plugins } = require('webshield-sdk');

const app = express();
app.use(express.json());

app.use(webShield({
  apiKey: "live_security_key_12345",
  mode: "strict",
  isolated: false, // True to trigger emergency lockdown mode (allowlist only)

  // Whitelisted IPs that bypass WAF rules and Rate Limits
  allowlist: ['127.0.0.1', '192.168.1.50'],

  // Distributed Rate Limit Configuration
  redis: {
    enabled: true,
    host: '127.0.0.1',
    port: 6379,
    keyPrefix: 'webshield:'
  },

  // Core Security Settings
  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true,
    secureCookies: true,
    headers: true
  },

  // Threat Limits
  rateLimit: {
    windowMs: 60000, // 1 minute
    max: 100,        // Max 100 requests per window
    burstMax: 10     // Max 10 requests per second (DDoS block)
  },

  // Traps for malicious crawler bots
  honeypot: {
    enabled: true,
    paths: ['/.env', '/admin', '/wp-admin', '/config.json']
  },

  // Custom CORS Controls
  cors: {
    mode: 'dynamic',
    allowedOrigins: ['https://my-app.com', /^https:\/\/.*\.vercel\.app$/]
  },

  // Active Plugins
  plugins: [
    plugins.botDetectionPlugin({ blockCrawlers: true }),
    plugins.ddosPlugin({ limit: 150 })
  ]
}));
```

---

## 🛠️ Testing & Verification

To verify that your installation is working correctly, you can run the built-in demo server:

1.  **Install dependencies**:
    ```bash
    npm install
    ```
2.  **Run the automated test suite**:
    ```bash
    npm test
    ```
    *(Executes the unit tests in [test.js](file:///Users/laptopbazaar/Desktop/Rakshak%20AI/test.js) validating WAF heuristics and CORS behaviors)*
3.  **Start the visual server**:
    ```bash
    npm start
    ```
    *(Launches the test application on port 3000)*
4.  **Simulate attack scenarios**:
    *   **Honeypot Trigger**: Go to `http://localhost:3000/admin` in your browser. The engine will instantly ban your IP and block subsequent requests.
    *   **Custom WAF Rules**: Go to `http://localhost:3000/confidential` to see custom WAF blocks in action.
    *   **Secret Leak Scanning**: Send a POST request containing an API key `AIzaSyB123abc456def789...` to `http://localhost:3000/submit` to see payload blocking.

---

## 🚀 CI/CD Pipeline

WebShield features a built-in CI/CD workflow located in [.github/workflows/ci.yml](file:///Users/laptopbazaar/Desktop/Rakshak%20AI/.github/workflows/ci.yml). It automatically runs checks across Node.js v18, v20, and v22 on every pull request or push.

---

## 🔐 Privacy & Telemetry

WebShield runs completely locally within your server node infrastructure. Refer to the [PRIVACY.md](file:///Users/laptopbazaar/Desktop/Rakshak%20AI/PRIVACY.md) file for more information regarding IP scanning, log volume sampling, and cloud-sync settings.
