const { logger } = require('../core/logger');

/**
 * Lightweight JSON schema payload protector
 */
function schemaGuard(options = {}) {
  const schemas = options.schemas || {};

  return (req, res) => {
    const route = req.path || '';
    const schema = schemas[route];

    // If no validation schema is registered for the current route, bypass checks
    if (!schema) return;

    const body = req.body || {};
    const keys = Object.keys(body);

    // 1. Check for missing required fields
    if (schema.requiredFields) {
      for (const field of schema.requiredFields) {
        if (body[field] === undefined) {
          logger.warn(`[Req ID: ${req.id}] Schema Failure on [${route}]: Missing required key [${field}]`);
          req.webShieldState.blocked = true;
          return res.status(400).json({
            success: false,
            error: `Payload Validation Error: Missing required parameter '${field}'`
          });
        }
      }
    }

    // 2. Enforce allowed parameter boundary keys (prevent parameter pollution / mass assignment)
    if (schema.allowedFields) {
      for (const key of keys) {
        if (!schema.allowedFields.includes(key)) {
          logger.warn(`[Req ID: ${req.id}] Schema Failure on [${route}]: Forbidden parameter key [${key}]`);
          req.webShieldState.blocked = true;
          return res.status(400).json({
            success: false,
            error: `Payload Validation Error: Parameter '${key}' is not permitted`
          });
        }
      }
    }
  };
}

module.exports = schemaGuard;
