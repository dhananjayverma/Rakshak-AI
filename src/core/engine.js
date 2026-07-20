const { v4: uuidv4 } = require('uuid');
const { defaultConfig, mergeConfigs } = require('./config');
const { initializeLogger, logger } = require('./logger');
const { calculateThreatScore } = require('./threatScore');
const { ipBlockerMiddleware, staticBlacklist } = require('../middleware/ipBlocker');
const { rateLimiterMiddleware } = require('../middleware/rateLimiter');
const { honeypotMiddleware } = require('../middleware/honeypot');
const { csrfGuardMiddleware } = require('../middleware/csrfGuard');
const { corsGuardMiddleware } = require('../middleware/corsGuard');
const { initCloudSync, sendSyncLog } = require('../services/cloudSync');
const { initAlerts, sendAlert } = require('../services/alertService');
const { initForensics, logForensicEvent } = require('../services/forensics');
const { initPatchEngine } = require('../services/patchEngine');
const { recordAttackPath, predictNextTarget } = require('../services/attackGraph');
const { dynamicHoneypotMiddleware } = require('../middleware/dynamicHoneypot');
const { consciousnessMiddleware } = require('../middleware/consciousness');
const { stealthModeMiddleware } = require('../middleware/stealthMode');
const graphqlGuard = require('../middleware/graphqlGuard');
const schemaGuard = require('../middleware/schemaGuard');
const challengeMiddleware = require('../middleware/challenge');
const { behavioralTrackerMiddleware } = require('../middleware/behavioralTracker');

// Memory store to keep last 50 threat logs for Dashboard viewer
const dashboardLogs = [];

class WebShield {
  constructor(options = {}) {
    this.config = mergeConfigs(defaultConfig, options);
    
    // Deep freeze active configuration to prevent runtime tampering
    Object.freeze(this.config);
    if (this.config.protection) Object.freeze(this.config.protection);
    if (this.config.rateLimit) Object.freeze(this.config.rateLimit);
    if (this.config.ip) Object.freeze(this.config.ip);
    if (this.config.waf) Object.freeze(this.config.waf);
    if (this.config.riskBasedAccess) Object.freeze(this.config.riskBasedAccess);
    if (this.config.cors) Object.freeze(this.config.cors);
    if (this.config.graphql) Object.freeze(this.config.graphql);
    if (this.config.schemaValidation) Object.freeze(this.config.schemaValidation);
    if (this.config.challenge) Object.freeze(this.config.challenge);
    if (this.config.forensics) Object.freeze(this.config.forensics);
    if (this.config.websocketGuard) Object.freeze(this.config.websocketGuard);
    if (this.config.ddosSmartMode) Object.freeze(this.config.ddosSmartMode);

    // Initialize Logger
    initializeLogger(this.config);
    logger.info(`WebShield Engine Initialized in [${this.config.mode}] mode.`);
    
    // Initialize Alerting Services
    initAlerts(this.config);
    
    // Initialize Remote Cloud Syncing
    initCloudSync(this.config);

    // Initialize Forensics Service
    initForensics(this.config);
    
    // Setup Global Threat Network Syncing
    if (this.config.globalThreatNetwork && this.config.globalThreatNetwork.enabled) {
      this.startGlobalThreatSync();
    }
    
    // Load custom plugins
    this.plugins = this.config.plugins || [];
    logger.info(`Loaded ${this.plugins.length} active plugins.`);

    // Compile dynamic rules list (which can be hot-patched in memory by autoPatch)
    this.activeRules = [...(this.config.waf.rules || [])];

    // Initialize Auto-Patch Engine
    if (this.config.autoPatch && this.config.autoPatch.enabled) {
      initPatchEngine(this.config, this);
    }

    // Load configurations from Vault
    const { loadSecretsFromVault } = require('../services/vault');
    loadSecretsFromVault(this.config).catch(err => {
      logger.warn(`Vault initialization warning: ${err.message}`);
    });
  }

  startGlobalThreatSync() {
    logger.info(`Global Threat Sharing Sync started. Fetching every ${this.config.globalThreatNetwork.syncIntervalMs}ms.`);
    
    setInterval(() => {
      // Simulate pulling malicious IPs shared from other networks
      const simulatedSharedIps = ['198.51.100.42', '203.0.113.111'];
      simulatedSharedIps.forEach(ip => {
        if (!staticBlacklist.includes(ip)) {
          staticBlacklist.push(ip);
          logger.info(`[Global Threat Sharing] Synced and blocked malicious IP from global list: ${ip}`);
        }
      });
    }, this.config.globalThreatNetwork.syncIntervalMs);
  }

  evaluateWafRules(req, res) {
    const config = req.webShieldConfig || this.config;
    if (!config.waf || !config.waf.enabled) return false;
    
    const path = req.path || req.url;
    const { getClientIp } = require('../utils/helpers');
    const ip = getClientIp(req);

    const rules = config.waf.rules || this.activeRules;

    for (const rule of rules) {
      if (typeof rule === 'string') {
        const { evaluateDslRule } = require('./ruleEngine');
        const triggered = evaluateDslRule(rule, req, res);
        if (triggered) {
          return true; // Already handled by rule engine
        }
        continue;
      }

      if (rule.type === 'path' && path === rule.value) {
        logger.warn(`[Req ID: ${req.id}] WAF Rule block triggered on path match: ${path}`);
        return true;
      }
      if (rule.type === 'header' && req.headers[rule.key] && req.headers[rule.key].includes(rule.value)) {
        logger.warn(`[Req ID: ${req.id}] WAF Rule block triggered on header [${rule.key}] match: ${rule.value}`);
        return true;
      }
      if (rule.type === 'ip' && ip === rule.value) {
        logger.warn(`[Req ID: ${req.id}] WAF Rule block triggered on IP match: ${ip}`);
        return true;
      }
    }
    return false;
  }

  serveDashboard(req, res) {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>WebShield Security Dashboard 🛡️</title>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; }
          h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }
          .log-card { background: #1e293b; border-left: 4px solid #f43f5e; padding: 15px; margin-bottom: 12px; border-radius: 4px; }
          .log-header { font-weight: bold; color: #e2e8f0; margin-bottom: 5px; }
          .meta { font-size: 0.85em; color: #94a3b8; }
          .reason { color: #fca5a5; margin-top: 5px; }
        </style>
      </head>
      <body>
        <h1>WebShield Security Event Stream</h1>
        <p>Real-time threat alerts from live network traffic.</p>
        <div id="logs-container">
          ${dashboardLogs.map(log => `
            <div class="log-card" style="border-left-color: ${log.threatScore > 75 ? '#ef4444' : '#f59e0b'}">
              <div class="log-header">[Threat Level: ${log.riskLevel}] Request to ${log.url} - Score ${log.threatScore}</div>
              <div class="meta">IP: ${log.ip} | ID: ${log.id} | Timestamp: ${log.timestamp}</div>
              <div class="reason">Threat Pattern Reason(s): ${log.reasons.join(', ')}</div>
            </div>
          `).join('')}
          ${dashboardLogs.length === 0 ? '<p>No security threats logged yet.</p>' : ''}
        </div>
      </body>
      </html>
    `;
    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(html);
  }

  middleware() {
    return async (req, res, next) => {
      // 1. Generate Correlation ID
      req.id = uuidv4();

      // Serve basic log visualizer endpoint
      if (req.path === '/webshield' || req.path === '/webshield/dashboard') {
        return this.serveDashboard(req, res);
      }

      // Serve client-side Canvas/WebGL device fingerprinting tag
      if (req.path === '/webshield/fp.js') {
        const { getFingerprintScript } = require('./fingerprintTag');
        res.setHeader('Content-Type', 'application/javascript');
        return res.status(200).send(getFingerprintScript());
      }

      // Handle Verification Challenge submission
      if (req.path === '/webshield/challenge-verify' && req.method === 'POST') {
        const { verifyChallenge } = require('../middleware/challenge');
        return verifyChallenge(req, res, this.config.challenge);
      }

      // If the request has passed the challenge, bypass WAF checks
      if (req.headers.cookie && req.headers.cookie.includes('webshield-verified=true')) {
        return next();
      }

      // Resolve Tenant Config dynamics
      const { tenantResolverMiddleware } = require('../middleware/tenantResolver');
      const resolveTenant = tenantResolverMiddleware(this.config);
      await new Promise(resolve => resolveTenant(req, res, resolve));

      // 2. System Isolation Check (Zero-Trust lockdown mode)
      if (req.webShieldConfig.isolated) {
        const { getClientIp } = require('../utils/helpers');
        const ip = getClientIp(req);
        if (!req.webShieldConfig.allowlist || !req.webShieldConfig.allowlist.includes(ip)) {
          logger.warn(`[Req ID: ${req.id}] Blocked request from ${ip} due to Active System Isolation Mode.`);
          return res.status(503).send('Service Temporarily Unavailable: System is isolated for security incident response.');
        }
      }

      try {
        // Initialize State for Request Lifecycle
        req.webShieldState = {
          ipFlagged: false,
          honeypotHit: false,
          rateLimitExceeded: false,
          burstLimitExceeded: false,
          blocked: false
        };

        // 2. Injected Security Headers (Helmet-like)
        if (req.webShieldConfig.protection.headers) {
          res.setHeader('X-Content-Type-Options', 'nosniff');
          res.setHeader('X-Frame-Options', 'DENY');
          res.setHeader('X-XSS-Protection', '1; mode=block');
          res.setHeader('Referrer-Policy', 'no-referrer');
          res.setHeader('Content-Security-Policy', "default-src 'self'");
          if (req.webShieldConfig.protection.secureCookies) {
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
          }
        }

        // 3. Dynamic CORS evaluation
        try {
          const runCors = corsGuardMiddleware(req.webShieldConfig);
          await new Promise((resolve, reject) => {
            runCors(req, res, (err) => {
              if (err) return reject(err);
              resolve();
            });
          });
        } catch (corsErr) {
          logger.warn(`[Req ID: ${req.id}] CORS blocked request: ${corsErr.message}`);
          return res.status(403).send('Forbidden: CORS block.');
        }

        // 3.1. Mapped Attacker sequences tracking & forecasting
        const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
        recordAttackPath(clientIp, req.path || req.url);
        predictNextTarget(clientIp);

        // Run Behavioral pattern tracking (spike + navigation)
        const tracker = behavioralTrackerMiddleware(req.webShieldConfig.behavioralTracker);
        tracker(req, res, () => {});

        // 3.2. Consciousness click trajectory telemetries check
        const runConsciousness = consciousnessMiddleware(req.webShieldConfig);
        await new Promise(resolve => runConsciousness(req, res, resolve));

        // 4. Custom WAF evaluation
        if (this.evaluateWafRules(req, res)) {
          req.webShieldState.blocked = true;
          
          // Sandboxed rule mutation triggering
          const { analyzeAndMutate } = require('../services/sandboxEngine');
          analyzeAndMutate(req.path || req.url, 'WAF');

          // Trigger Stealth mode tarpit check if configured
          const runStealth = stealthModeMiddleware(req.webShieldConfig);
          return runStealth(req, res, () => res.status(403).send('Forbidden: WAF rule enforcement.'));
        }

        // 4.1. Adaptive Honeypot 2.0 dynamic configuration blocks
        if (req.webShieldConfig.honeypot.enabled) {
          const honeyBlock = dynamicHoneypotMiddleware(req.webShieldConfig);
          await new Promise(resolve => honeyBlock(req, res, resolve));
          if (req.webShieldState.blocked) return;
        }

        // 5. IP Blocklist & Geo Blocking
        const ipBlock = ipBlockerMiddleware(req.webShieldConfig);
        await ipBlock(req, res);
        if (req.webShieldState.blocked) return;

        // 6. Rate Limiter (IP + User + Burst)
        const rateLimit = rateLimiterMiddleware(req.webShieldConfig);
        await rateLimit(req, res);
        if (req.webShieldState.blocked) return;

        // 7. CSRF Check
        if (req.webShieldConfig.protection.csrf) {
          const csrfGuard = csrfGuardMiddleware(req.webShieldConfig);
          await csrfGuard(req, res);
          if (req.webShieldState.blocked) {
            logForensicEvent(req, 40, ['CSRF token mismatch or missing']);
            return;
          }
        }

        // 7.1. GraphQL Protection (Depth limit check)
        if (req.webShieldConfig.graphql.enabled) {
          const runGraphql = graphqlGuard(req.webShieldConfig.graphql);
          runGraphql(req, res);
          if (req.webShieldState.blocked) {
            logForensicEvent(req, 60, ['GraphQL query depth complexity exceeded']);
            return;
          }
        }

        // 7.2. API Schema Validation check
        if (req.webShieldConfig.schemaValidation.enabled) {
          const runSchema = schemaGuard(req.webShieldConfig.schemaValidation);
          runSchema(req, res);
          if (req.webShieldState.blocked) {
            logForensicEvent(req, 50, ['Payload schema validation failed']);
            return;
          }
        }

        // 8. Request Size Limit Enforcement
        if (req.webShieldConfig.protection.requestSizeLimit) {
          const limitStr = req.webShieldConfig.protection.requestSizeLimit.toLowerCase();
          let limitBytes = 2 * 1024 * 1024; // Default 2mb
          if (limitStr.endsWith('kb')) {
            limitBytes = parseInt(limitStr) * 1024;
          } else if (limitStr.endsWith('mb')) {
            limitBytes = parseInt(limitStr) * 1024 * 1024;
          }
          
          const contentLength = req.headers['content-length'];
          if (contentLength && parseInt(contentLength) > limitBytes) {
            logger.warn(`[Req ID: ${req.id}] Request size limit exceeded from IP: ${req.ip || req.connection.remoteAddress}`);
            return res.status(413).send('Payload Too Large');
          }
        }

        // 9. Plugin hook (Pre-scoring)
        for (const plugin of this.plugins) {
          if (typeof plugin === 'function') {
            await plugin(req, res, req.webShieldConfig);
            if (req.webShieldState.blocked) return;
          }
        }

        // 10. Run Threat Engine calculation
        const threat = calculateThreatScore(req, req.webShieldConfig);
        req.webShieldThreat = threat;

        // Run DDoS Smart Mode throttle delay
        const { ddosSmartModeMiddleware } = require('../middleware/ddosSmartMode');
        const runDdosSmart = ddosSmartModeMiddleware(req.webShieldConfig.ddosSmartMode);
        await new Promise(resolve => runDdosSmart(req, res, resolve));

        // Print debug WAF telemetries to stdout
        if (req.webShieldConfig.debug) {
          console.log(`\x1b[33m[WebShield Debug]\x1b[0m ${req.method} ${req.path || req.url} | IP: ${clientIp} | Score: ${threat.score} (${threat.riskLevel}) | Blocks: ${threat.reasons.join('; ') || 'None'}`);
        }

        // 11. Risk-Based response handling (Captcha vs Block)
        if (req.webShieldConfig.riskBasedAccess.enabled && threat.needsCaptcha) {
          logger.warn(`[Req ID: ${req.id}] Risk evaluation triggered CAPTCHA challenge. Threat Score: ${threat.score}`);
          return res.status(401).json({
            status: 'auth_challenge',
            message: 'Suspicious request activity detected. Please complete CAPTCHA verification.',
            threatScore: threat.score,
            fingerprint: threat.fingerprint
          });
        }

        // 11.1. Adaptive Captcha / Challenge check
        if (req.webShieldConfig.challenge.enabled) {
          const runChallenge = challengeMiddleware(req.webShieldConfig.challenge);
          runChallenge(req, res, threat.score);
          if (req.webShieldState.blocked) {
            logForensicEvent(req, threat.score, ['Adaptive math challenge served']);
            return;
          }
        }

        // 12. Auto-Response Engine block execution
        if (threat.score >= 70 || threat.isMalicious) {
          const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
          logger.warn(`[Req ID: ${req.id}] Threat detected! IP: ${ip} - Score: ${threat.score}. Reasons: ${threat.reasons.join(', ')}`);
          
          // Log Forensics incident
          logForensicEvent(req, threat.score, threat.reasons);

          // Append to memory log queue for dashboard visualization
          dashboardLogs.unshift({
            id: req.id,
            ip,
            url: req.originalUrl || req.url,
            threatScore: threat.score,
            riskLevel: threat.riskLevel,
            reasons: threat.reasons,
            timestamp: new Date().toLocaleTimeString()
          });

          // Keep log count within bound
          if (dashboardLogs.length > 50) dashboardLogs.pop();

          // Trigger Alerts in Background Queue (Asynchronous)
          setImmediate(() => {
            sendAlert(`Security Threat Alert: Score ${threat.score}`, {
              id: req.id,
              ip,
              threatScore: threat.score,
              reasons: threat.reasons,
              url: req.originalUrl || req.url,
              method: req.method
            });
          });

          // Sync with SaaS dashboard in background
          sendSyncLog({
            id: req.id,
            ip,
            threatScore: threat.score,
            attackType: threat.reasons.join('; '),
            url: req.originalUrl || req.url
          });

          if (req.webShieldConfig.mode === 'strict' && req.webShieldConfig.autoResponse.block) {
            req.webShieldState.blocked = true;

            // Trigger self-healing rule adaptation
            const selfHealing = require('../services/selfHealing');
            selfHealing.analyzeAndHeal(req, threat.score, threat.reasons, this);

            // Trigger dynamic rule mutations inside sandbox
            const { analyzeAndMutate } = require('../services/sandboxEngine');
            analyzeAndMutate(req.originalUrl || req.url, 'ScoringEngine');

            // Trigger Stealth mode tarpit check if configured
            const runStealth = stealthModeMiddleware(req.webShieldConfig);
            return runStealth(req, res, () => res.status(403).send(req.webShieldConfig.autoResponse.customBlockResponse));
          }
        }

        next();
      } catch (err) {
        logger.error(`[Req ID: ${req.id}] Error in WebShield Middleware: ${err.message}`);
        next(err);
      }
    };
  }
}

module.exports = WebShield;
