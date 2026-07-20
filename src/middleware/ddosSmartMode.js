const { logger } = require('../core/logger');

function ddosSmartModeMiddleware(config = {}) {
  return (req, res, next) => {
    if (!config.enabled) {
      return next();
    }

    const threat = req.webShieldThreat;
    if (!threat) {
      return next();
    }

    // 1. Slow down suspicious requests (Medium risk)
    if (threat.score >= 50 && threat.score < 75) {
      const delayMs = Math.min((threat.score - 50) * 80, 2000); // Max 2 seconds delay
      if (delayMs > 0) {
        logger.info(`[DDoS Smart Mode] Injecting ${delayMs}ms tar-pit latency to throttle suspicious request (IP: ${req.ip || req.connection.remoteAddress}, Threat Score: ${threat.score})`);
        
        req.webShieldState.throttledMs = delayMs;
        
        return setTimeout(() => {
          next();
        }, delayMs);
      }
    }

    next();
  };
}

module.exports = {
  ddosSmartModeMiddleware
};
