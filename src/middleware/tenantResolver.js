const { logger } = require('../core/logger');

// In-memory tenant settings catalog (simulating database records lookup)
const tenantRegistry = {
  'client-saas-a': {
    mode: 'strict',
    rateLimit: {
      max: 3 // Ultra strict throttling policy
    },
    waf: {
      enabled: true,
      rules: [
        'if (path.includes("tenant-block")) block()'
      ]
    }
  },
  'client-saas-b': {
    mode: 'monitor', // Monitor only
    rateLimit: {
      max: 5000
    },
    waf: {
      enabled: false
    }
  }
};

/**
 * Resolves request metadata to isolate WAF configuration scopes per tenant
 */
function tenantResolverMiddleware(globalConfig) {
  return (req, res, next) => {
    const tenantId = req.headers['x-tenant-id'] || req.hostname;
    
    if (tenantId && tenantRegistry[tenantId]) {
      // Dynamic config merging for isolated tenant contexts
      req.webShieldConfig = {
        ...globalConfig,
        ...tenantRegistry[tenantId],
        protection: {
          ...globalConfig.protection,
          ...(tenantRegistry[tenantId].protection || {})
        }
      };
      
      logger.info(`[Multi-Tenant] Swapped configurations dynamic range targeting client: ${tenantId}`);
    } else {
      // Default: Fallback to global configuration
      req.webShieldConfig = globalConfig;
    }

    next();
  };
}

module.exports = {
  tenantResolverMiddleware,
  tenantRegistry
};
