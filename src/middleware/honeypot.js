const { logger } = require('../core/logger');
const { blacklistedIps } = require('./rateLimiter');

function honeypotMiddleware(config) {
  return (req, res) => {
    const path = req.path || req.url;
    const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';

    if (config.honeypot.paths.includes(path)) {
      req.webShieldState.honeypotHit = true;
      req.webShieldState.blocked = true;

      // Ban IP for honeypot ban duration
      const banDurationMs = (config.honeypot.banDuration || 86400) * 1000;
      const banExpiry = Date.now() + banDurationMs;
      blacklistedIps.set(ip, banExpiry);

      logger.warn(`HONEYPOT TRIGGERED! IP ${ip} requested trapped path: ${path}. IP banned for ${config.honeypot.banDuration}s.`);
      
      return res.status(403).send('Forbidden: Security honeypot triggered.');
    }
  };
}

module.exports = {
  honeypotMiddleware
};
