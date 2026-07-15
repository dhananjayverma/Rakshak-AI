const { logger } = require('../core/logger');

// Simulated high-fidelity credential leaks and database backup dumps
const adaptiveDecoys = {
  '/.env': 'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=production_db\nDB_USERNAME=root\nDB_PASSWORD=secret_db_pass_9988\nJWT_SECRET=super_secret_jwt_signature_4433',
  '/config.json': JSON.stringify({
    version: '2.4.1',
    environment: 'production',
    aws_key: 'AKIAIOSFODNN7EXAMPLE',
    aws_secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  }, null, 2),
  '/backup.sql': '-- WebShield Dynamic Decoy Dump\nCREATE TABLE `users` (\n  `id` int(11) NOT NULL,\n  `username` varchar(255) DEFAULT NULL,\n  `password_hash` varchar(255) DEFAULT NULL\n);\nINSERT INTO `users` VALUES (1, "admin", "$2a$12$K7MDENG/bPxRfiCYEXAMPLEKEY");'
};

/**
 * Serves dynamic decoy responses and delays scanner execution threads
 */
function dynamicHoneypotMiddleware(config) {
  return (req, res, next) => {
    const path = req.path || req.url || '';
    
    // Scan if current route matches any decoy template path
    const matchedDecoy = Object.keys(adaptiveDecoys).find(decoy => path.endsWith(decoy));
    
    if (matchedDecoy) {
      logger.warn(`[Honeypot 2.0] Decoy path hit: "${matchedDecoy}" from IP: ${req.ip || (req.connection && req.connection.remoteAddress) || '127.0.0.1'}`);
      
      req.webShieldState.honeypotHit = true;
      
      // Delay (tar-pit) response by 1.5 seconds to throttle scanner threads
      setTimeout(() => {
        res.setHeader('Content-Type', matchedDecoy.endsWith('.json') ? 'application/json' : 'text/plain');
        res.status(200).send(adaptiveDecoys[matchedDecoy]);
      }, 1500);
      return;
    }

    next();
  };
}

module.exports = {
  dynamicHoneypotMiddleware,
  adaptiveDecoys
};
