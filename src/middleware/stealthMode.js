const { logger } = require('../core/logger');

/**
 * stealthMode tar-pits blocked connections and returned masked 200 OKs to confuse port/vuln scanners
 */
function stealthModeMiddleware(config) {
  return (req, res, next) => {
    const isBlocked = req.webShieldState && req.webShieldState.blocked;
    
    // Mask block alerts if stealthMode parameter is enabled in config
    if (isBlocked && config.stealthMode) {
      logger.info(`[Stealth Mode] Masking block action on path: "${req.path}". Serving delayed dummy 200 OK.`);

      // Delay response by 2-4 seconds (tar-pit) to exhaust scraper connection pools
      const delayMs = Math.floor(Math.random() * 2000) + 2000;
      
      setTimeout(() => {
        res.setHeader('Content-Type', 'application/json');
        // Serve a fake success JSON array instead of a firewall warning page
        res.status(200).send(JSON.stringify({
          status: 'success',
          data: [],
          count: 0
        }));
      }, delayMs);
      
      return;
    }

    next();
  };
}

module.exports = {
  stealthModeMiddleware
};
