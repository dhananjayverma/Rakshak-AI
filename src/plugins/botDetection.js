const { logger } = require('../core/logger');

function botDetectionPlugin(options = {}) {
  const customBlockedBots = options.blockedBots || [];

  return async (req, res, config) => {
    const userAgent = req.headers['user-agent'] || '';
    
    // Check common bots
    const botRegex = /googlebot|bingbot|yandexbot|duckduckgo|baiduspider|screaming frog|semrushbot|ia_archiver/i;
    
    if (botRegex.test(userAgent)) {
      logger.info(`[Plugin: BotDetection] Crawler bot detected: ${userAgent}`);
      
      // Let standard search bots pass unless configuration explicitly bans them
      if (options.blockCrawlers) {
        req.webShieldState.blocked = true;
        return res.status(403).send('Bots are not allowed.');
      }
    }

    // Check custom blocked bots list
    for (const blockedBot of customBlockedBots) {
      if (userAgent.toLowerCase().includes(blockedBot.toLowerCase())) {
        logger.warn(`[Plugin: BotDetection] Blocked bot user-agent: ${userAgent}`);
        req.webShieldState.blocked = true;
        return res.status(403).send('Access Denied (Bot Blocked).');
      }
    }
  };
}

module.exports = botDetectionPlugin;
