const { logger } = require('../core/logger');
const { sendAlert } = require('../services/alertService');

// In-memory fallback stores
const ipWindows = new Map();
const userWindows = new Map();
const blacklistedIps = new Map(); // IP -> banExpiryTime

// Redis client holder
let redisClient = null;
let redisWarningSent = false;

function getRedisClient(config) {
  if (!config.redis || !config.redis.enabled) return null;
  if (redisClient) return redisClient;

  try {
    const Redis = require('ioredis');
    redisClient = new Redis({
      host: config.redis.host || '127.0.0.1',
      port: config.redis.port || 6379,
      password: config.redis.password || undefined,
      keyPrefix: config.redis.keyPrefix || 'webshield:',
      maxRetriesPerRequest: 1
    });

    redisClient.on('error', (err) => {
      logger.error(`[Redis] Connection Error: ${err.message}. Falling back to In-Memory store.`);
      
      // Send critical alert notification if not sent yet
      if (!redisWarningSent) {
        redisWarningSent = true;
        setImmediate(() => {
          sendAlert('CRITICAL: Redis Connection Failure - Switched to Memory Mode', {
            error: err.message,
            timestamp: new Date().toISOString(),
            status: 'in_memory_fallback_active'
          });
        });
      }
      redisClient = null;
    });

    logger.info('[Redis] Distributed Rate Limiting store initialized.');
    return redisClient;
  } catch (err) {
    logger.warn(`[Redis] Could not load ioredis client: ${err.message}. Falling back to In-Memory store.`);
    return null;
  }
}

function rateLimiterMiddleware(config) {
  const client = getRedisClient(config);

  return async (req, res) => {
    const { getClientIp } = require('../utils/helpers');
    const ip = getClientIp(req);
    const now = Date.now();

    // Bypass check if IP is in allowlist
    if (config.allowlist && config.allowlist.includes(ip)) {
      return;
    }

    // Dynamic Ban Duration calculation based on threat levels (baseDuration * multiplier)
    const getDynamicBanDuration = () => {
      const baseDuration = config.rateLimit.banDuration || 3600;
      const score = req.webShieldThreat ? req.webShieldThreat.score : 50; // default medium threat if unknown yet
      const multiplier = Math.max(1, Math.floor(score / 10)); // e.g. 90 score -> 9x multiplier
      return baseDuration * multiplier;
    };

    if (client) {
      try {
        const blacklistKey = `blacklist:${ip}`;
        const isBanned = await client.get(blacklistKey);
        
        if (isBanned) {
          req.webShieldState.blocked = true;
          req.webShieldState.rateLimitExceeded = true;
          logger.warn(`[Req ID: ${req.id}] [Redis Block] Request blocked from banned IP: ${ip}`);
          return res.status(429).send('Your IP is temporarily banned.');
        }

        const ipKey = `ip:${ip}`;
        const userKey = req.user && req.user.id ? `user:${req.user.id}` : null;

        // Add current timestamp to Redis sorted set (ZSET)
        await client.zadd(ipKey, now, now);
        // Clean old records outside sliding window
        const windowStart = now - config.rateLimit.windowMs;
        await client.zremrangebyscore(ipKey, 0, windowStart);
        // Get active requests count
        const activeRequestsCount = await client.zcard(ipKey);

        // Burst check
        const burstStart = now - config.rateLimit.burstWindowMs;
        const burstRequests = await client.zcount(ipKey, burstStart, now);
        if (burstRequests > config.rateLimit.burstMax) {
          req.webShieldState.burstLimitExceeded = true;
          logger.warn(`[Req ID: ${req.id}] [Redis Burst] Limit triggered by IP: ${ip} (${burstRequests} requests in 5s)`);
        }

        // Standard IP limit
        if (activeRequestsCount > config.rateLimit.max) {
          req.webShieldState.rateLimitExceeded = true;
          logger.warn(`[Req ID: ${req.id}] [Redis Limit] Rate limit exceeded by IP: ${ip} (${activeRequestsCount} requests in window)`);
          
          if (config.autoResponse.block) {
            const dynamicBanSec = getDynamicBanDuration();
            // Ban in Redis
            await client.setex(blacklistKey, dynamicBanSec, '1');
            req.webShieldState.blocked = true;
            return res.status(429).send(config.autoResponse.customBlockResponse);
          }
        }

        // User limit
        if (userKey) {
          await client.zadd(userKey, now, now);
          await client.zremrangebyscore(userKey, 0, windowStart);
          const userRequests = await client.zcard(userKey);
          if (userRequests > config.rateLimit.userMax) {
            logger.warn(`[Req ID: ${req.id}] [Redis User Limit] Rate limit exceeded by User ID: ${req.user.id}`);
            req.webShieldState.rateLimitExceeded = true;
          }
        }
        return;
      } catch (err) {
        logger.error(`[Redis Error] Rate limiting lookup failed: ${err.message}. Falling back to In-Memory.`);
      }
    }

    // In-Memory Fallback Implementation
    if (blacklistedIps.has(ip)) {
      const expiry = blacklistedIps.get(ip);
      if (now < expiry) {
        req.webShieldState.blocked = true;
        req.webShieldState.rateLimitExceeded = true;
        logger.warn(`[Req ID: ${req.id}] Blocked request from banned IP: ${ip}`);
        return res.status(429).send('Your IP is temporarily banned.');
      } else {
        blacklistedIps.delete(ip);
      }
    }

    if (!ipWindows.has(ip)) {
      ipWindows.set(ip, []);
    }
    const timestamps = ipWindows.get(ip);
    const windowStart = now - config.rateLimit.windowMs;
    const activeTimestamps = timestamps.filter(ts => ts > windowStart);
    activeTimestamps.push(now);
    ipWindows.set(ip, activeTimestamps);

    const burstStart = now - config.rateLimit.burstWindowMs;
    const burstTimestamps = activeTimestamps.filter(ts => ts > burstStart);
    if (burstTimestamps.length > config.rateLimit.burstMax) {
      req.webShieldState.burstLimitExceeded = true;
      logger.warn(`[Req ID: ${req.id}] Burst limit triggered by IP: ${ip} (${burstTimestamps.length} requests in 5s)`);
    }

    if (activeTimestamps.length > config.rateLimit.max) {
      req.webShieldState.rateLimitExceeded = true;
      logger.warn(`[Req ID: ${req.id}] Rate limit exceeded by IP: ${ip} (${activeTimestamps.length} requests in window)`);
      
      if (config.autoResponse.block) {
        const dynamicBanSec = getDynamicBanDuration();
        const banExpiry = now + (dynamicBanSec * 1000);
        blacklistedIps.set(ip, banExpiry);
        logger.warn(`[Req ID: ${req.id}] IP ${ip} blacklisted dynamically for ${dynamicBanSec}s until ${new Date(banExpiry).toISOString()}`);
        
        req.webShieldState.blocked = true;
        return res.status(429).send(config.autoResponse.customBlockResponse);
      }
    }

    if (req.user && req.user.id) {
      const userId = req.user.id;
      if (!userWindows.has(userId)) {
        userWindows.set(userId, []);
      }
      const userTimestamps = userWindows.get(userId);
      const userActive = userTimestamps.filter(ts => ts > windowStart);
      userActive.push(now);
      userWindows.set(userId, userActive);

      if (userActive.length > config.rateLimit.userMax) {
        logger.warn(`[Req ID: ${req.id}] User Rate limit exceeded by User ID: ${userId}`);
        req.webShieldState.rateLimitExceeded = true;
      }
    }
  };
}

module.exports = {
  rateLimiterMiddleware,
  blacklistedIps
};
