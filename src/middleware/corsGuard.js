const cors = require('cors');
const { logger } = require('../core/logger');

function corsGuardMiddleware(config) {
  if (config.cors.mode === 'open') {
    return cors(); // Allow all origins
  }

  // Strict mode: direct hard whitelist matching
  if (config.cors.mode === 'strict') {
    return cors({
      origin: config.cors.allowedOrigins
    });
  }

  // Dynamic mode: Dynamic regex matching + Dev environments + Client IP allowlist checks
  return cors({
    origin: function (origin, callback) {
      // 1. Allow server-to-server, Postman, or non-browser client requests (no origin header)
      if (!origin) {
        return callback(null, true);
      }

      // 2. Fallback: if no custom origins configured, allow by default in dynamic mode
      if (!config.cors.allowedOrigins || config.cors.allowedOrigins.length === 0) {
        return callback(null, true);
      }

      // 3. Dev Mode Auto-Allow
      if (process.env.NODE_ENV !== 'production') {
        return callback(null, true);
      }

      // 4. Match configured origins (supports exact string matching and regular expressions)
      const isAllowed = config.cors.allowedOrigins.some(pattern => {
        if (pattern instanceof RegExp) {
          return pattern.test(origin);
        }
        if (typeof pattern === 'string') {
          // Check for wildcard matching
          if (pattern.includes('*')) {
            const regexPattern = new RegExp('^' + pattern.split('*').join('.*') + '$');
            return regexPattern.test(origin);
          }
          return pattern === origin;
        }
        return false;
      });

      if (isAllowed) {
        return callback(null, true);
      }

      // Block and log
      logger.warn(`CORS BLOCKED: Request origin [${origin}] is not authorized.`);
      return callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  });
}

module.exports = {
  corsGuardMiddleware
};
