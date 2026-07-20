const { logger } = require('../core/logger');
const { getClientIp } = require('../utils/helpers');

// In-memory store for tracking IP request history
// Structure: ip -> { timestamps: [], paths: [], lastAccess: Date }
const trackingStore = new Map();

// Cleanup expired tracking sessions every 2 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of trackingStore.entries()) {
    if (now - data.lastAccess > 60000 * 5) { // 5 minutes inactivity
      trackingStore.delete(ip);
    }
  }
}, 120000);

function behavioralTrackerMiddleware(config = {}) {
  const windowMs = config.windowMs || 5000; // 5 seconds window
  const spikeThreshold = config.spikeThreshold || 30; // Max requests in 5 seconds
  const allowedTransitionRatio = 0.2; // Threshold for abnormal path jumps

  return (req, res, next) => {
    const ip = getClientIp(req);
    const path = req.path || req.url;
    const now = Date.now();

    if (!trackingStore.has(ip)) {
      trackingStore.set(ip, {
        timestamps: [],
        paths: [],
        lastAccess: now
      });
    }

    const data = trackingStore.get(ip);
    data.lastAccess = now;
    data.timestamps.push(now);
    data.paths.push(path);

    // Filter timestamps to only keep those within the sliding window
    data.timestamps = data.timestamps.filter(t => now - t <= windowMs);

    // 1. Sudden Request Spike detection
    if (data.timestamps.length > spikeThreshold) {
      req.webShieldState.requestSpikeDetected = true;
      logger.warn(`[Behavioral Tracker] Sudden request spike detected from IP: ${ip} (${data.timestamps.length} reqs in ${windowMs}ms)`);
    }

    // 2. Abnormal Navigation / Bot-like movement detection
    // Example: human visits home/product/checkout vs bot jumping straight to /.env or /config
    const suspiciousPaths = ['/admin', '/.env', '/config.json', '/wp-admin', '/setup', '/config'];
    
    // If the very first paths visited contain a trap, or they hit multiple config/admin routes consecutively
    const pathCount = data.paths.length;
    if (pathCount <= 3) {
      const hits = data.paths.filter(p => suspiciousPaths.some(sp => p.includes(sp)));
      if (hits.length >= 1 && pathCount === 1) {
        req.webShieldState.abnormalNavigationDetected = true;
        logger.warn(`[Behavioral Tracker] Bot-like movement: Jumped directly to sensitive path: ${path}`);
      }
    }

    // Keep path history capped at last 10 paths to avoid memory bloat
    if (data.paths.length > 10) {
      data.paths.shift();
    }

    if (next && typeof next === 'function') next();
  };
}

module.exports = {
  behavioralTrackerMiddleware,
  trackingStore
};
