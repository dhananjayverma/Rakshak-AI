const { logger } = require('../core/logger');

function sqlInjectionPlugin(options = {}) {
  const strictMode = options.strict !== false;

  return async (req, res, config) => {
    // Advanced check in addition to core threat engine rules
    const sqlRegex = /\b(select|union|insert|update|delete|drop|alter|create|truncate|replace|grant)\b/i;
    
    const checkValue = (val) => {
      if (typeof val === 'string' && sqlRegex.test(val)) {
        return true;
      }
      return false;
    };

    let sqlDetected = false;
    
    // Check url path
    if (checkValue(req.path) || checkValue(req.url)) {
      sqlDetected = true;
    }

    // Check query params
    for (const key in req.query) {
      if (checkValue(req.query[key])) {
        sqlDetected = true;
      }
    }

    if (sqlDetected) {
      logger.warn(`[Plugin: SQLi] Potential SQL injection signature matched in URL/Parameters.`);
      
      if (strictMode) {
        req.webShieldState.blocked = true;
        return res.status(403).send('Forbidden: SQL Injection Attempt Detected.');
      }
    }
  };
}

module.exports = sqlInjectionPlugin;
