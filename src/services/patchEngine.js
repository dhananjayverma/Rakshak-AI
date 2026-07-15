const axios = require('axios');
const { logger } = require('../core/logger');

let patchInterval = null;

/**
 * Background auto-patch service that retrieves live threat signatures dynamically
 */
function initPatchEngine(config, wafEngine) {
  const autoPatch = config.autoPatch || {};
  if (!autoPatch.enabled) return;

  const intervalMs = autoPatch.intervalMs || 300000;
  const feedUrl = autoPatch.feedUrl || 'https://rules.webshield-sdk.com/signatures.json';

  logger.info(`[Patch Engine] Initialized dynamic signature sync: ${feedUrl}`);

  patchInterval = setInterval(async () => {
    try {
      logger.info('[Patch Engine] Checking for security pattern updates...');
      
      // Perform HTTP request to pull latest WAF signatures
      const response = await axios.get(feedUrl, { timeout: 3000 });
      if (response.data && Array.isArray(response.data.rules)) {
        let addedCount = 0;
        
        response.data.rules.forEach(rule => {
          if (wafEngine.activeRules && !wafEngine.activeRules.includes(rule)) {
            wafEngine.activeRules.push(rule);
            addedCount++;
          }
        });

        if (addedCount > 0) {
          logger.info(`[Patch Engine] Security database patched successfully: +${addedCount} patterns applied.`);
        }
      }
    } catch (err) {
      // Graceful fallback to local definitions on network / DNS failures
      logger.warn(`[Patch Engine] Signature sync bypassed (Using cached definitions): ${err.message}`);
    }
  }, intervalMs);
}

module.exports = {
  initPatchEngine
};
