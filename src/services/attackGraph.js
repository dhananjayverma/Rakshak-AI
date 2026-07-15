const { logger } = require('../core/logger');

// Memory cache to store path sequences: { ip: [path1, path2, ...] }
const pathSequences = {};

// Hardcoded transitions mapping representing standard hacker directory scanning patterns
const markovTransitions = {
  '/': ['/login', '/api', '/admin'],
  '/login': ['/admin', '/config', '/api/debug'],
  '/admin': ['/.env', '/wp-config.php', '/config.json', '/setup.php'],
  '/api': ['/api/v1/users', '/api/v1/debug', '/actuator/env']
};

/**
 * Appends request nodes to the attacker's trajectory graph
 */
function recordAttackPath(ip, path) {
  if (!pathSequences[ip]) {
    pathSequences[ip] = [];
  }

  pathSequences[ip].push(path);

  // Keep sliding window size of 8 sequences
  if (pathSequences[ip].length > 8) {
    pathSequences[ip].shift();
  }

  logger.info(`[Attack Graph] Sequence mapped for IP ${ip}: ${pathSequences[ip].join(' -> ')}`);
}

/**
 * Predicts the next logical probe target and confidence rating
 */
function predictNextTarget(ip) {
  const sequence = pathSequences[ip] || [];
  if (sequence.length === 0) {
    return { prediction: null, confidence: 0 };
  }

  const lastProbedPath = sequence[sequence.length - 1];
  const potentials = markovTransitions[lastProbedPath] || [];

  if (potentials.length > 0) {
    const prediction = potentials[0]; // Predict highest probability transition
    const confidence = Math.round(100 / potentials.length);
    
    logger.warn(`[Predictive Engine] Alert for IP ${ip}: High probability of next probe targeting "${prediction}" (${confidence}% confidence)`);
    return { prediction, confidence };
  }

  return { prediction: null, confidence: 0 };
}

/**
 * Returns the recorded trajectory array
 */
function getAttackGraph(ip) {
  return pathSequences[ip] || [];
}

module.exports = {
  recordAttackPath,
  predictNextTarget,
  getAttackGraph
};
