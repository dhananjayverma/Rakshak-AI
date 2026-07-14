const { logger } = require('../core/logger');
const { blacklistedIps } = require('./rateLimiter');

const geoip = require('geoip-lite');
const ipRangeCheck = require('ip-range-check');

// Static IP blacklist (can contain single IPs or CIDR ranges like '192.168.1.0/24')
const staticBlacklist = ['1.2.3.4', '203.0.113.0/24'];

function ipBlockerMiddleware(config) {
  return (req, res) => {
    const { getClientIp } = require('../utils/helpers');
    const ip = getClientIp(req);
    // Bypass check if IP is in allowlist
    if (config.allowlist && config.allowlist.includes(ip)) {
      return;
    }
    // 1. Static blacklist check (supports CIDR ranges)
    if (ipRangeCheck(ip, staticBlacklist)) {
      req.webShieldState.blocked = true;
      req.webShieldState.ipFlagged = true;
      logger.warn(`Blocked IP via range/static blacklist: ${ip}`);
      return res.status(403).send('Forbidden: Your IP is blacklisted.');
    }

    // 2. Geoblocking check using geoip-lite
    if (config.ip.geoBlock && config.ip.geoBlock.length > 0) {
      const geo = geoip.lookup(ip);
      const countryCode = geo ? geo.country : (req.headers['x-country-code'] || 'US');
      
      if (config.ip.geoBlock.includes(countryCode.toUpperCase())) {
        req.webShieldState.blocked = true;
        req.webShieldState.ipFlagged = true;
        logger.warn(`Blocked IP ${ip} due to Geoblocking rules for country: ${countryCode}`);
        return res.status(403).send('Forbidden: Access not allowed from your region.');
      }
    }
  };
}

module.exports = {
  ipBlockerMiddleware,
  staticBlacklist
};
