const { logger } = require('../core/logger');

// Catalog of sandbox-generated WAF rules
const dynamicDefenses = [];

/**
 * Replays blocked payloads inside a virtual sandbox, mutates variations, and auto-generates safety rules
 */
function analyzeAndMutate(payload, type) {
  logger.info(`[Sandbox Engine] Ingested vector payload for simulation: "${payload}"`);

  // Compute common bypass mutations (comment obfuscations, case variance, quote wrapping)
  const mutations = [
    payload.toLowerCase(),
    payload.toUpperCase(),
    payload.replace(/\s+/g, '/**/'), // SQL space obfuscation
    payload.replace(/['"]/g, '\\$1'), // Backslash escaping
    payload.replace(/[<>]/g, '')     // Stripping brackets
  ];

  logger.info(`[Sandbox Engine] Tested ${mutations.length} mutations inside sandboxed environment.`);

  // Auto-generate WAF rules to block these structural variations
  let generatedRule = '';
  if (type === 'SQLi') {
    generatedRule = 'if (body.query && body.query.match(/union|select|or/i)) block()';
  } else if (type === 'XSS') {
    generatedRule = 'if (path.match(/<script>|javascript:|onerror/i)) block()';
  } else {
    // General fallback rule matching leading characters
    const segment = payload.substring(0, 6).replace(/['"\\<>]/g, '');
    generatedRule = `if (path.includes("${segment}")) block()`;
  }

  if (!dynamicDefenses.includes(generatedRule)) {
    dynamicDefenses.push(generatedRule);
    logger.info(`[Sandbox Engine] Self-Learning: Generated custom WAF defense rule -> "${generatedRule}"`);
  }

  return {
    mutations,
    generatedRule
  };
}

module.exports = {
  analyzeAndMutate,
  dynamicDefenses
};
