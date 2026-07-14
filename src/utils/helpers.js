/**
 * Helper utility methods for WebShield SDK
 */

/**
 * Checks if value is empty/null/undefined
 */
function isEmpty(val) {
  return val === undefined || val === null || (typeof val === 'string' && val.trim().length === 0);
}

const requestIp = require('request-ip');

/**
 * Gets clean remote client IP address from request headers or socket details
 */
function getClientIp(req) {
  return requestIp.getClientIp(req) || '127.0.0.1';
}

module.exports = {
  isEmpty,
  getClientIp
};
