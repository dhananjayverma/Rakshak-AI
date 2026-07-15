const { logger } = require('../core/logger');

/**
 * Consciousness check scans cursor coordinate trajectory slopes to identify Selenium/Puppeteer click automations
 */
function consciousnessMiddleware(config) {
  return (req, res, next) => {
    // Check if the check is active in settings
    if (!config.consciousnessCheck) return next();

    const trajectoryHeader = req.headers['x-webshield-trajectory'];

    if (req.method === 'POST') {
      if (!trajectoryHeader) {
        logger.warn('[Consciousness Test] Telemetry missing on write request. Raising bot probability.');
        req.webShieldState.botDetected = true;
        return next();
      }

      try {
        const points = JSON.parse(trajectoryHeader); // Array structure: [[x, y, timestamp], ...]
        if (points.length < 3) {
          logger.warn('[Consciousness Test] Telemetry coordinate density too low. Flagged as automated script.');
          req.webShieldState.botDetected = true;
          return next();
        }

        // Compute slope variance. Real humans have jitter/curves. Robots move in perfectly linear vectors.
        let isLinear = true;
        const initialSlope = (points[1][1] - points[0][1]) / (points[1][0] - points[0][0] || 1);
        
        for (let i = 2; i < points.length; i++) {
          const currentSlope = (points[i][1] - points[i-1][1]) / (points[i][0] - points[i-1][0] || 1);
          if (Math.abs(currentSlope - initialSlope) > 0.05) {
            isLinear = false; // Normal human cursor variance detected
            break;
          }
        }

        if (isLinear) {
          logger.warn('[Consciousness Test] Perfectly linear cursor coordinates matched. Flagged as Puppeteer execution.');
          req.webShieldState.botDetected = true;
        }
      } catch (err) {
        logger.warn('[Consciousness Test] Failed decoding trajectory payload: ' + err.message);
        req.webShieldState.botDetected = true;
      }
    }

    next();
  };
}

module.exports = {
  consciousnessMiddleware
};
