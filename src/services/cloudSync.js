const { io } = require('socket.io-client');
const { logger } = require('../core/logger');

let socket = null;
let cloudSyncConfig = null;
const logQueue = [];

function initCloudSync(config) {
  cloudSyncConfig = config.cloudSync;

  if (!cloudSyncConfig || !cloudSyncConfig.enabled) {
    return;
  }

  try {
    socket = io(cloudSyncConfig.endpoint, {
      autoConnect: true,
      reconnection: true,
      auth: {
        token: config.apiKey
      }
    });

    socket.on('connect', () => {
      logger.info('Connected to WebShield SaaS Cloud Backend.');
      // Flush queued logs
      while (logQueue.length > 0) {
        const log = logQueue.shift();
        socket.emit('security-event', log);
      }
    });

    socket.on('connect_error', (err) => {
      logger.warn(`WebShield SaaS Cloud Backend connection failed: ${err.message}`);
    });
  } catch (err) {
    logger.error(`Error initializing Cloud Sync: ${err.message}`);
  }
}

function sendSyncLog(logData) {
  if (!cloudSyncConfig || !cloudSyncConfig.enabled) return;

  const eventPayload = {
    ...logData,
    timestamp: new Date().toISOString(),
    apiKey: cloudSyncConfig.apiKey
  };

  if (socket && socket.connected) {
    socket.emit('security-event', eventPayload);
  } else {
    // Queue offline logs
    logQueue.push(eventPayload);
    if (logQueue.length > 1000) {
      logQueue.shift(); // Evict oldest log if buffer is full
    }
  }
}

module.exports = {
  initCloudSync,
  sendSyncLog
};
