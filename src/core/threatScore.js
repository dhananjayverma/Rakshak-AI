const { logger } = require('./logger');

/**
 * Checks for common SQL injection patterns
 */
function checkSqlInjection(value) {
  if (typeof value !== 'string') return 0;
  const sqlPatterns = [
    /\b(select|union|insert|update|delete|drop|alter|create|truncate|replace)\b/i,
    /('|")\s*(or|and)\s*('|"|\d)/i,
    /--/,
    /\/\*/,
    /exec\s*\(/i,
    /xp_cmdshell/i
  ];
  
  let score = 0;
  for (const pattern of sqlPatterns) {
    if (pattern.test(value)) {
      score += 35;
    }
  }
  return Math.min(score, 100);
}

/**
 * Checks for common NoSQL injection patterns
 */
function checkNoSqlInjection(obj) {
  if (!obj || typeof obj !== 'object') return 0;
  
  let score = 0;
  const str = JSON.stringify(obj);
  
  // Look for MongoDB operators
  const operators = ['"$gt"', '"$lt"', '"$ne"', '"$eq"', '"$regex"', '"$where"', '"$nin"', '"$in"'];
  for (const op of operators) {
    if (str.includes(op)) {
      score += 30;
    }
  }
  
  return Math.min(score, 100);
}

/**
 * Checks for common XSS patterns
 */
function checkXss(value) {
  if (typeof value !== 'string') return 0;
  const xssPatterns = [
    /<script[^>]*>([\s\S]*?)<\/script>/i,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /onclick\s*=/i,
    /<iframe[^>]*>/i,
    /eval\s*\(/i,
    /document\.cookie/i
  ];

  let score = 0;
  for (const pattern of xssPatterns) {
    if (pattern.test(value)) {
      score += 40;
    }
  }
  return Math.min(score, 100);
}

/**
 * Checks for API credentials/secrets leakage in request
 */
function checkSecretLeaks(value, config) {
  if (!config.secretLeak || !config.secretLeak.enabled || typeof value !== 'string') return false;
  
  for (const pattern of config.secretLeak.patterns) {
    if (pattern.test(value)) {
      return true;
    }
  }
  return false;
}

/**
 * Computes request fingerprint for verification
 */
function getRequestFingerprint(req) {
  const { getClientIp } = require('../utils/helpers');
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const lang = req.headers['accept-language'] || '';
  const encoding = req.headers['accept-encoding'] || '';
  
  // Secure hash calculation
  const rawFingerprint = `${ip}|${ua}|${lang}|${encoding}`;
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(rawFingerprint).digest('hex');
}

/**
 * Validates JWT payload structures for anomalies
 */
function inspectJwtToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return { score: 0, reason: null };
  const token = authHeader.split(' ')[1];
  
  // A JWT consists of three base64url parts separated by dots
  const segments = token.split('.');
  if (segments.length !== 3) {
    return { score: 40, reason: 'Malformed Authorization JWT header structure' };
  }

  try {
    // Check if payload part can be parsed
    const payloadSegment = Buffer.from(segments[1], 'base64').toString('utf8');
    const payload = JSON.parse(payloadSegment);
    
    // Check expiration claim
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return { score: 25, reason: 'Expired Authorization JWT token signature' };
    }
  } catch (err) {
    return { score: 30, reason: 'Unable to parse Authorization JWT token payload' };
  }
  return { score: 0, reason: null };
}

// Token IP store for detecting token abuse (token sharing across multiple IPs)
const tokenIpStore = new Map();
// Simple cleanup for token IP store
setInterval(() => {
  tokenIpStore.clear();
}, 300000); // clear every 5 mins

function decodeAndInspect(val, scanFunc) {
  if (typeof val !== 'string') return 0;
  
  let maxScore = scanFunc(val);

  // 1. URL decoding
  try {
    const decodedUrl = decodeURIComponent(val);
    if (decodedUrl !== val) {
      maxScore = Math.max(maxScore, scanFunc(decodedUrl));
    }
  } catch (e) {}

  // 2. HTML Entity decoding (basic)
  const decodedHtml = val.replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#x27;/gi, "'").replace(/&amp;/gi, '&');
  if (decodedHtml !== val) {
    maxScore = Math.max(maxScore, scanFunc(decodedHtml));
  }

  // 3. Base64 attack detection & decoding
  if (val.length >= 8 && /^[A-Za-z0-9+/=]+$/.test(val)) {
    try {
      const decodedBase64 = Buffer.from(val, 'base64').toString('utf8');
      // Verify if decoded string contains printable ASCII / common characters
      if (/^[ -~]+$/.test(decodedBase64)) {
        maxScore = Math.max(maxScore, scanFunc(decodedBase64));
      }
    } catch (e) {}
  }

  return maxScore;
}

function deepScanObject(obj, scanFunc) {
  if (typeof obj === 'string') {
    return decodeAndInspect(obj, scanFunc);
  }
  if (!obj || typeof obj !== 'object') {
    return 0;
  }
  let maxScore = 0;
  if (Array.isArray(obj)) {
    for (const item of obj) {
      maxScore = Math.max(maxScore, deepScanObject(item, scanFunc));
    }
  } else {
    for (const key in obj) {
      maxScore = Math.max(maxScore, deepScanObject(obj[key], scanFunc));
    }
  }
  return maxScore;
}

/**
 * Calculate Threat Score (0 - 100)
 */
function calculateThreatScore(req, config) {
  let score = 0;
  const reasons = [];

  // Generate request fingerprint
  const fingerprint = getRequestFingerprint(req);
  req.webShieldState.fingerprint = fingerprint;

  // 1. IP Blacklist check (if flagged by other layers)
  if (req.webShieldState && req.webShieldState.ipFlagged) {
    score += 50;
    reasons.push('IP flagged in blocklist / geo-blocked');
  }

  // 2. Honeypot hit
  if (req.webShieldState && req.webShieldState.honeypotHit) {
    score += 85;
    reasons.push('Honeypot trap route triggered');
  }

  // 3. Rate Limit Exceeded
  if (req.webShieldState && req.webShieldState.rateLimitExceeded) {
    score += 40;
    reasons.push('Rate limit threshold exceeded');
  }
  if (req.webShieldState && req.webShieldState.burstLimitExceeded) {
    score += 30;
    reasons.push('Burst limit threshold exceeded');
  }

  // 3.1. Bot detected via consciousness telemetry check
  if (req.webShieldState && req.webShieldState.botDetected) {
    score += 55;
    reasons.push('Automation scripting patterns detected (consciousness click telemetry failed)');
  }

  // 3.2. Behavioral Tracking Spike & abnormal navigation check
  if (req.webShieldState && req.webShieldState.requestSpikeDetected) {
    score += 40;
    reasons.push('Behavioral anomaly: Sudden request spike detected');
  }
  if (req.webShieldState && req.webShieldState.abnormalNavigationDetected) {
    score += 30;
    reasons.push('Behavioral anomaly: Abnormal/bot-like navigation path');
  }

  // 3.3. API Abuse - Token sharing / Token abuse check
  const authHeader = req.headers['authorization'] || req.headers['x-api-key'] || '';
  if (authHeader) {
    const { getClientIp } = require('../utils/helpers');
    const ip = getClientIp(req);
    if (!tokenIpStore.has(authHeader)) {
      tokenIpStore.set(authHeader, new Set());
    }
    const ipSet = tokenIpStore.get(authHeader);
    ipSet.add(ip);
    if (ipSet.size > 3) {
      score += 50;
      reasons.push(`API Abuse: Token shared across ${ipSet.size} distinct IP addresses`);
    }
  }

  // 3.4. API Abuse - Data Scraping Pattern check (sequential IDs)
  const path = req.path || req.url || '';
  if (/\/(users|products|posts|items)\/\d+$/i.test(path)) {
    const { trackingStore } = require('../middleware/behavioralTracker');
    const { getClientIp } = require('../utils/helpers');
    const ip = getClientIp(req);
    const tracking = trackingStore.get(ip);
    if (tracking && tracking.paths.length >= 3) {
      // Check if last 3 paths have consecutive integer IDs at the end
      const lastPaths = tracking.paths.slice(-3);
      const matches = lastPaths.map(p => {
        const m = p.match(/\/(\d+)$/);
        return m ? parseInt(m[1], 10) : null;
      });
      if (matches.every(m => m !== null)) {
        const diff1 = matches[1] - matches[0];
        const diff2 = matches[2] - matches[1];
        if (Math.abs(diff1) === 1 && Math.abs(diff2) === 1) {
          score += 45;
          reasons.push('API Abuse: Data scraping pattern detected (sequential resource ID harvesting)');
        }
      }
    }
  }

  // 4. JWT Authorization Security Inspection
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const jwtResult = inspectJwtToken(authHeader);
    if (jwtResult.score > 0) {
      score += jwtResult.score;
      reasons.push(jwtResult.reason);
    }
  }

  // 4.1. Behavioral Header Anomaly Scan (Headless bot / Scraper detection)
  const uaString = req.headers['user-agent'] || '';
  if (uaString) {
    const isChrome = uaString.toLowerCase().includes('chrome');
    // If user-agent claims Chrome, it MUST have modern SEC headers. Otherwise, it is a headless script/bot.
    if (isChrome && !req.headers['sec-ch-ua']) {
      score += 25;
      reasons.push('Anomalous Chrome Request: Missing browser verification header (sec-ch-ua)');
    }
    // Flag common raw scrapers and bot scripting user-agents
    if (/axios|needle|node-fetch|python|curl|wget|postman|scrapy|puppeteer/i.test(uaString)) {
      score += 35;
      reasons.push(`Automated client / scraper agent fingerprint matched: ${uaString.split('/')[0]}`);
    }
    // Mismatched browser parameters (real human browsers always send accept-language headers)
    if (!req.headers['accept-language'] && !/curl|wget|axios/i.test(uaString)) {
      score += 20;
      reasons.push('Fingerprint mismatch: Missing accept-language header');
    }
  }

  // 4.2. Canvas + WebGL Hardware Device Fingerprint check
  const clientDeviceId = req.headers['x-webshield-device-id'];
  if (clientDeviceId) {
    req.webShieldState.deviceId = clientDeviceId;
    
    // Flag suspicious/obfuscated fingerprint attempts (e.g. anti-fingerprinting browser configs blocking canvas)
    if (clientDeviceId === 'canvas-blocked' || clientDeviceId === 'webgl-blocked') {
      score += 15;
      reasons.push('Anomalous Hardware Signature: Client side canvas/webgl fingerprinting obfuscation detected');
    }
  }

  // 5. Business API Abuse protection (Endpoint-specific analysis)
  const sensitiveEndpoints = ['/login', '/otp', '/register', '/reset-password'];
  const matchedEndpoint = sensitiveEndpoints.find(end => path.endsWith(end));
  if (matchedEndpoint) {
    // If hitting sensitive login/otp routes with rate limit flags, apply a heavy business abuse penalty
    if (req.webShieldState.rateLimitExceeded || req.webShieldState.burstLimitExceeded) {
      score += 30;
      reasons.push(`Potential brute-force abuse on sensitive auth endpoint: ${matchedEndpoint}`);
    }
  }

  // 6. Secret Leak Detection
  if (config.secretLeak.enabled) {
    let leakDetected = false;
    
    // Check body parameters (with deep inspection)
    if (req.body && typeof req.body === 'object') {
      const bodyStr = JSON.stringify(req.body);
      if (checkSecretLeaks(bodyStr, config)) {
        leakDetected = true;
      }
    }
    
    // Check URL parameters
    for (const key in req.query) {
      if (checkSecretLeaks(req.query[key], config)) {
        leakDetected = true;
        break;
      }
    }

    if (leakDetected) {
      score += 45;
      reasons.push('Sensitive key/API credential leak attempt detected');
    }
  }

  // 7. Inspect payload (Body, Query, Headers) with Deep Inspection
  if (config.protection.sqlInjection) {
    let sqlScore = 0;
    // Check query params
    for (const key in req.query) {
      sqlScore = Math.max(sqlScore, decodeAndInspect(req.query[key], checkSqlInjection));
    }
    // Check body params (recursive)
    if (req.body && typeof req.body === 'object') {
      sqlScore = Math.max(sqlScore, deepScanObject(req.body, checkSqlInjection));
    }
    if (sqlScore > 0) {
      score += sqlScore;
      reasons.push(`SQL Injection patterns detected (Score contribution: ${sqlScore})`);
    }
  }

  if (config.protection.nosqlInjection && req.body && typeof req.body === 'object') {
    const nosqlScore = checkNoSqlInjection(req.body);
    if (nosqlScore > 0) {
      score += nosqlScore;
      reasons.push(`NoSQL Injection operators detected (Score contribution: ${nosqlScore})`);
    }
  }

  if (config.protection.xss) {
    let xssScore = 0;
    // Check query params
    for (const key in req.query) {
      xssScore = Math.max(xssScore, decodeAndInspect(req.query[key], checkXss));
    }
    // Check body params (recursive)
    if (req.body && typeof req.body === 'object') {
      xssScore = Math.max(xssScore, deepScanObject(req.body, checkXss));
    }
    if (xssScore > 0) {
      score += xssScore;
      reasons.push(`XSS payloads/tags detected (Score contribution: ${xssScore})`);
    }
  }

  // 8. User-Agent abnormalities / Bot detection
  const suspiciousUas = [/curl/i, /wget/i, /python/i, /postman/i, /nikto/i, /sqlmap/i, /nmap/i];
  for (const sUa of suspiciousUas) {
    if (sUa.test(uaString)) {
      score += 25;
      reasons.push(`Suspicious User-Agent detected: ${uaString}`);
      break;
    }
  }

  // Cap score at 100
  const finalScore = Math.min(score, 100);

  // Dynamic Risk Classification
  let riskLevel = 'LOW';
  if (finalScore >= 75) {
    riskLevel = 'CRITICAL';
  } else if (finalScore >= 50) {
    riskLevel = 'MEDIUM';
  }

  return {
    score: finalScore,
    reasons,
    riskLevel,
    fingerprint,
    isMalicious: finalScore >= (config.riskBasedAccess.blockThreshold || 75),
    needsCaptcha: finalScore >= (config.riskBasedAccess.captchaThreshold || 50) && finalScore < (config.riskBasedAccess.blockThreshold || 75)
  };
}

module.exports = {
  calculateThreatScore,
  getRequestFingerprint
};
