const { logger } = require('../core/logger');

/**
 * Recursive sanitizer for XSS and basic injection payload values
 */
function sanitizeValue(val) {
  if (typeof val !== 'string') return val;

  // Basic script clean, event handlers clean, HTML tags clean
  return val
    .replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/onerror\s*=/gi, 'no-error=')
    .replace(/onload\s*=/gi, 'no-load=')
    .replace(/onclick\s*=/gi, 'no-click=')
    .replace(/eval\s*\(/gi, 'no-eval(')
    .trim();
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;

  for (const key in obj) {
    if (typeof obj[key] === 'object') {
      obj[key] = sanitizeObject(obj[key]);
    } else if (typeof obj[key] === 'string') {
      obj[key] = sanitizeValue(obj[key]);
    }
  }
  return obj;
}

function xssGuardMiddleware(config) {
  return (req, res, next) => {
    if (config.protection.xss) {
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body);
      }
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query);
      }
    }
    next();
  };
}

module.exports = {
  xssGuardMiddleware,
  sanitizeValue,
  sanitizeObject
};
