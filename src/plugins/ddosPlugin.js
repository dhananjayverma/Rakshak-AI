const { logger } = require('../core/logger');

/**
 * Custom DDOS protection plugin example
 */
function ddosPlugin(options = {}) {
  const threshold = options.threshold || 50;

  return async (req, res, config) => {
    // Dynamic plugin rule: check if headers indicate proxies or excessive concurrent requests
    const connectionHeader = req.headers['connection'] || '';
    
    // Simulate detecting a DDOS request signature
    if (connectionHeader.toLowerCase() === 'keep-alive' && req.webShieldState.rateLimitExceeded) {
      logger.warn('[Plugin: DDOS] Potential HTTP Keep-Alive flood detected.');
      req.webShieldState.blocked = true;
      res.status(503).send('Service Temporarily Unavailable (DDOS Shield Active)');
    }
  };
}

module.exports = ddosPlugin;
