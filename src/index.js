const WebShield = require('./core/engine');
const ddosPlugin = require('./plugins/ddosPlugin');
const botDetectionPlugin = require('./plugins/botDetection');
const sqlInjectionPlugin = require('./plugins/sqlInjection');

/**
 * Main WebShield SDK entry point
 * 
 * Usage:
 * const { webShield } = require('webshield-sdk');
 * app.use(webShield({ apiKey: '...' }));
 */
function webShield(options = {}) {
  const shield = new WebShield(options);
  return shield.middleware();
}

module.exports = {
  webShield,
  WebShield,
  plugins: {
    ddosPlugin,
    botDetectionPlugin,
    sqlInjectionPlugin
  }
};
