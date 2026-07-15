# Privacy Policy - WebShield SDK 🛡️

This Privacy Policy describes how the **WebShield SDK** handles data, logs, and telemetry.

---

## 1. Data Collection & Processing

WebShield SDK is a self-hosted security middleware package. All request filtering, WAF evaluations, and rate-limiting operations are executed **locally on your servers**. 

By default, the SDK processes the following data inputs in memory to calculate threat scores:
* **Client IP Addresses** (to execute rate limiting, geoblocking, and honeypot routing controls).
* **HTTP Headers** (including User-Agent strings to identify crawlers/scrapers, and Authorization headers to check JWT syntax validity).
* **Request URL Paths & Payloads** (to check for XSS, NoSQL, and SQL injection strings).

---

## 2. Remote Cloud Sync Telemetry (Optional)

If you explicitly enable SaaS Remote Cloud Sync (`cloudSync: { enabled: true }`) in your options:
* Only security threat logs and blocked events are transmitted to your configured telemetry endpoint.
* No raw query payloads or personal user session data are synced unless they are part of a detected attack signature.
* Pushed events are transferred securely over WebSockets using your custom `apiKey` auth token.

---

## 3. Data Protection Measures

To ensure enterprise-grade data security, WebShield SDK implements:
* **In-Memory Cache**: Banned lists and request counts are kept in volatile local memory (or your private Redis cluster if configured).
* **No Local DB Logging**: Logs are directed to console output or localized log files (`webshield-security.log`) under your control.
* **Sensitive Secret Scrubber**: Scans for leaked keys (Stripe, Slack, AWS, Google APIs) in request bodies and blocks/redacts them before any logs are saved.

---

## 4. Compliance (GDPR / CCPA)

Because WebShield SDK runs locally within your infrastructure, **you are the Data Controller** for any client data processed. The SDK acts as a security filter processing incoming network telemetry to defend your application. If cloud synchronization is active, ensure your privacy policy discloses the secure transmission of security logs to your SaaS analytics provider.
