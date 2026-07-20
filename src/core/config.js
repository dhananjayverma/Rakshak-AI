/**
 * Default Configuration for WebShield SDK
 */
const defaultConfig = {
  apiKey: null,
  // Smart Auto Mode: Default to strict in production, monitor in dev
  mode: process.env.NODE_ENV === 'production' ? 'strict' : 'monitor',
  debug: false, // Verbose console trace logs
  isolated: false, // Zero-Trust Isolation Mode: blocks all non-allowlisted traffic
  
  // Redis store configuration for distributed rate limiting & global blacklist
  redis: {
    enabled: false,
    host: '127.0.0.1',
    port: 6379,
    password: null,
    keyPrefix: 'webshield:'
  },

  // IP Allowlist to prevent false positives for admins/authorized systems
  allowlist: [
    '127.0.0.1',
    '::1'
  ],

  // Configurable CORS settings
  cors: {
    mode: 'dynamic', // 'strict' | 'dynamic' | 'open'
    allowedOrigins: [] // array of strings or RegEx patterns
  },

  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true,
    secureCookies: false,
    headers: true,
    requestSizeLimit: '2mb' // e.g. '2mb', '500kb', or false
  },

  // Secret Leak Detection config
  secretLeak: {
    enabled: true,
    patterns: [
      /xox[bapr]-[0-9]{12}/i,                     // Slack Token
      /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}/i,       // Amazon MWS Auth Token
      /AIza[0-9A-Za-z-_]{35}/i,                    // Google API Key
      /sk_live_[0-9a-zA-Z]{24}/i,                  // Stripe Live Secret Key
      /access_token\$production\$[0-9a-f]{32}/i,   // PayPal Access Token
      /ey[a-zA-Z0-9-_]+\.ey[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/ // JWT Tokens (Basic check)
    ]
  },

  rateLimit: {
    windowMs: 60000, // 1 minute window
    max: 100, // max requests per window per IP
    userMax: 50, // max requests per window per authenticated user (if req.user.id exists)
    burstMax: 15, // max requests within a small sub-window to detect sudden bursts
    burstWindowMs: 5000, // 5 seconds sub-window
    banDuration: 3600 // ban duration in seconds (1 hour)
  },

  ip: {
    blockMalicious: true,
    geoBlock: [], // array of country codes, e.g. ['CN', 'RU']
    vpnBlock: false,
    torBlock: true,
    abuseScoreThreshold: 80 // AbuseIPDB score threshold (0-100) to auto-block
  },

  // Custom WAF rules engine configuration
  waf: {
    enabled: true,
    rules: [
      // Custom DSL Logic check rule
      'if (path.includes("forbidden")) block()'
    ]
  },

  // Global Threat Sharing Network integration
  globalThreatNetwork: {
    enabled: true,
    shareThreats: true,
    syncIntervalMs: 60000 // sync list with cloud sharing server every 1 min
  },

  // Fingerprint verification configuration
  fingerprinting: {
    enabled: true,
    mismatchScoreContribution: 40 // score contribution if UA and connection fingerprint disagree
  },

  // Risk-based access control setup
  riskBasedAccess: {
    enabled: true,
    captchaThreshold: 50, // trigger captcha request if threatScore >= 50
    blockThreshold: 75    // completely block request if threatScore >= 75
  },

  // Behavioral anomaly tracking configuration
  behavioralTracker: {
    windowMs: 5000,
    spikeThreshold: 30
  },

  // WebSocket Flood protection settings
  websocketGuard: {
    enabled: true,
    windowMs: 1000,
    maxMessages: 50
  },

  // DDoS Smart Mode dynamic tar-pit settings
  ddosSmartMode: {
    enabled: true
  },

  honeypot: {
    enabled: true,
    paths: ['/admin', '/.env', '/wp-admin', '/config', '/setup.php', '/actuator/health', '/__trap'],
    banDuration: 86400 // 24 hours for honeypot hits
  },

  alerts: {
    email: {
      enabled: false,
      transport: null, // nodemailer transport config
      to: null,
      from: 'alerts@webshield-sdk.local'
    },
    webhook: {
      enabled: false,
      url: null
    }
  },

  autoResponse: {
    block: true,
    banDuration: 3600, // 1 hour
    customBlockResponse: 'Access Denied: WebShield Security Block'
  },

  logging: {
    enabled: true,
    level: 'info', // 'info', 'warn', 'error'
    console: true,
    file: false,
    filePath: 'webshield-security.log',
    // Log sampling to prevent volume explosions in production (logs only 10% of standard info messages)
    samplingEnabled: false,
    samplingRate: 0.1
  },

  cloudSync: {
    enabled: false,
    endpoint: 'https://api.webshield-saas.com',
    syncIntervalMs: 5000
  },

  // GraphQL query protection settings
  graphql: {
    enabled: false,
    maxDepth: 7, // Depth limit
    depthBanThreshold: 10 // Instantly ban if depth is excessively high
  },

  // Request schema validation rules (Zod-like JSON validation)
  schemaValidation: {
    enabled: false,
    schemas: {} // format: { '/api/route': { requiredFields: ['email'], allowedFields: ['email', 'name'] } }
  },

  // Adaptive Challenge configuration (Medium threat score responses)
  challenge: {
    enabled: false,
    captchaUrl: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
    thresholdMin: 50,
    thresholdMax: 74
  },

  // Forensics reporting and local request logging
  forensics: {
    enabled: true,
    logPath: 'webshield-forensics.json',
    maxLogs: 100
  },

  // Auto Patch rules synchronization
  autoPatch: {
    enabled: false,
    feedUrl: 'https://rules.webshield-sdk.com/signatures.json',
    intervalMs: 300000 // 5 minutes
  },

  // Stealth masking tarpit
  stealthMode: false,

  // Human vs Bot consciousness coordinate verification
  consciousnessCheck: false,

  plugins: []
};

/**
 * Merges user options with default configurations deep-wise
 */
function mergeConfigs(target, source) {
  if (!source) return target;
  
  const output = { ...target };
  
  for (const key of Object.keys(source)) {
    // Prevent Prototype Pollution
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      output[key] = mergeConfigs(target[key] || {}, source[key]);
    } else {
      output[key] = source[key];
    }
  }
  
  return output;
}

// Freeze defaultConfig to prevent runtime tampering of default templates
Object.freeze(defaultConfig);
Object.freeze(defaultConfig.protection);
Object.freeze(defaultConfig.rateLimit);
Object.freeze(defaultConfig.ip);
Object.freeze(defaultConfig.waf);
Object.freeze(defaultConfig.riskBasedAccess);
Object.freeze(defaultConfig.graphql);
Object.freeze(defaultConfig.schemaValidation);
Object.freeze(defaultConfig.challenge);
Object.freeze(defaultConfig.forensics);
Object.freeze(defaultConfig.autoPatch);

module.exports = {
  defaultConfig,
  mergeConfigs
};
