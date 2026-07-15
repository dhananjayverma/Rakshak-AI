const { logger } = require('./logger');
const { getClientIp } = require('../utils/helpers');

/**
 * Evaluates custom logical rule expressions (WAF DSL)
 * Example: if (path.includes("confidential")) block()
 */
function evaluateDslRule(ruleStr, req, res) {
  try {
    const trimmed = ruleStr.trim();
    // Match syntax: if (expression) action()
    const match = trimmed.match(/^if\s*\((.+?)\)\s*(block|challenge|allow)\(\)$/i);
    if (!match) {
      logger.error(`[Rule Engine] Failed to parse rule format: "${trimmed}"`);
      return false;
    }

    const [, expression, action] = match;

    // Define sandbox variables for execution scope
    const ip = getClientIp(req);
    const path = req.path || req.url || '';
    const method = req.method || 'GET';
    const headers = req.headers || {};
    const query = req.query || {};
    const body = req.body || {};

    // Execute logic check inside a local scoped context
    const evaluator = new Function('ip', 'path', 'method', 'headers', 'query', 'body', `
      try {
        return Boolean(${expression});
      } catch (e) {
        return false;
      }
    `);

    const result = evaluator(ip, path, method, headers, query, body);

    if (result) {
      logger.warn(`[Rule Engine] Request matched custom policy: "${trimmed}" -> Triggered: ${action}()`);

      if (action === 'block') {
        req.webShieldState.blocked = true;
        res.status(403).send('Forbidden: Access blocked by custom security policy.');
        return true;
      }

      if (action === 'challenge') {
        req.webShieldState.blocked = true;
        const challengeMiddleware = require('../middleware/challenge');
        const runChallenge = challengeMiddleware();
        // Fire captcha template with medium score (60)
        runChallenge(req, res, 60);
        return true;
      }

      if (action === 'allow') {
        // Flag to skip all WAF scanning algorithms for trusted pathways
        req.webShieldState.bypassAll = true;
        return false;
      }
    }
  } catch (err) {
    logger.error(`[Rule Engine] Fault encountered while evaluating rule: ${err.message}`);
  }
  return false;
}

module.exports = {
  evaluateDslRule
};
