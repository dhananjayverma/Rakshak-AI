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

  // 4. JWT Authorization Security Inspection
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const jwtResult = inspectJwtToken(authHeader);
    if (jwtResult.score > 0) {
      score += jwtResult.score;
      reasons.push(jwtResult.reason);
    }
  }

  // 5. Business API Abuse protection (Endpoint-specific analysis)
  const path = req.path || req.url || '';
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
    
    // Check body parameters
    if (req.body && typeof req.body === 'object') {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string' && checkSecretLeaks(req.body[key], config)) {
          leakDetected = true;
          break;
        }
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

  // 7. Inspect payload (Body, Query, Headers)
  if (config.protection.sqlInjection) {
    let sqlScore = 0;
    // Check query params
    for (const key in req.query) {
      sqlScore = Math.max(sqlScore, checkSqlInjection(req.query[key]));
    }
    // Check body params
    if (req.body && typeof req.body === 'object') {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
          sqlScore = Math.max(sqlScore, checkSqlInjection(req.body[key]));
        }
      }
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
      xssScore = Math.max(xssScore, checkXss(req.query[key]));
    }
    // Check body params
    if (req.body && typeof req.body === 'object') {
      for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
          xssScore = Math.max(xssScore, checkXss(req.body[key]));
        }
      }
    }
    if (xssScore > 0) {
      score += xssScore;
      reasons.push(`XSS payloads/tags detected (Score contribution: ${xssScore})`);
    }
  }

  // 8. User-Agent abnormalities / Bot detection
  const ua = req.headers['user-agent'] || '';
  const suspiciousUas = [/curl/i, /wget/i, /python/i, /postman/i, /nikto/i, /sqlmap/i, /nmap/i];
  for (const sUa of suspiciousUas) {
    if (sUa.test(ua)) {
      score += 25;
      reasons.push(`Suspicious User-Agent detected: ${ua}`);
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
