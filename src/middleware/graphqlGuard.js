const { logger } = require('../core/logger');

/**
 * GraphQL Query Depth Protection middleware
 */
function graphqlGuard(options = {}) {
  const maxDepth = options.maxDepth || 7;
  const depthBanThreshold = options.depthBanThreshold || 10;

  return (req, res) => {
    let queryStr = '';

    // Extract query string from request body or query string parameters
    if (req.method === 'POST' && req.body && req.body.query) {
      queryStr = req.body.query;
    } else if (req.query && req.query.query) {
      queryStr = req.query.query;
    }

    if (!queryStr) return;

    // Compute maximum brace nesting depth
    let currentDepth = 0;
    let maxFoundDepth = 0;

    for (let i = 0; i < queryStr.length; i++) {
      const char = queryStr[i];
      if (char === '{') {
        currentDepth++;
        if (currentDepth > maxFoundDepth) {
          maxFoundDepth = currentDepth;
        }
      } else if (char === '}') {
        currentDepth = Math.max(0, currentDepth - 1);
      }
    }

    if (maxFoundDepth > maxDepth) {
      logger.warn(`[Req ID: ${req.id}] GraphQL Query Depth Limit Exceeded: Depth is ${maxFoundDepth} (limit: ${maxDepth})`);
      req.webShieldState.blocked = true;

      // If the query depth is excessively high, mark the IP for instant ban in rate limiter context
      if (maxFoundDepth >= depthBanThreshold) {
        logger.error(`[Req ID: ${req.id}] Critical GraphQL complexity threshold triggered. IP marked for block.`);
        req.webShieldState.criticalBanTriggered = true;
      }

      return res.status(400).json({
        success: false,
        error: 'GraphQL validation failed: query exceeds depth limit.'
      });
    }
  };
}

module.exports = graphqlGuard;
