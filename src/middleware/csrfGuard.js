const { logger } = require('../core/logger');

function csrfGuardMiddleware(config) {
  return (req, res) => {
    // Only check state-changing methods
    const methods = ['POST', 'PUT', 'DELETE', 'PATCH'];
    if (!methods.includes(req.method)) return;

    const origin = req.headers['origin'];
    const referer = req.headers['referer'];
    const csrfHeader = req.headers['x-csrf-token'];
    const host = req.headers['host'];

    // If custom CSRF token is provided, consider it valid (in basic mode)
    if (csrfHeader) return;

    // Check host matching in Origin/Referer
    if (origin) {
      const originHost = new URL(origin).host;
      if (originHost !== host) {
        logger.warn(`CSRF Origin mismatch: ${originHost} vs ${host}`);
        req.webShieldState.blocked = true;
        return res.status(403).send('Forbidden: CSRF verification failed (Origin mismatch).');
      }
      return;
    }

    if (referer) {
      const refererHost = new URL(referer).host;
      if (refererHost !== host) {
        logger.warn(`CSRF Referer mismatch: ${refererHost} vs ${host}`);
        req.webShieldState.blocked = true;
        return res.status(403).send('Forbidden: CSRF verification failed (Referer mismatch).');
      }
      return;
    }

    // Require Origin or Referer for state-changing operations
    logger.warn('CSRF validation blocked request: Missing Origin and Referer headers.');
    req.webShieldState.blocked = true;
    res.status(403).send('Forbidden: CSRF validation failed.');
  };
}

module.exports = {
  csrfGuardMiddleware
};
