const { logger } = require('../core/logger');
const { staticBlacklist } = require('./ipBlocker');

// Map to track message history per socket connection
// Structure: socketId -> { timestamps: [], ip: string }
const wsRateStore = new Map();

function websocketGuard(options = {}) {
  const windowMs = options.windowMs || 1000; // 1 second window
  const maxMessages = options.maxMessages || 50; // Max messages per second

  return {
    attach: (io) => {
      logger.info('[WebSocket Guard] Successfully attached to server instance.');
      
      io.on('connection', (socket) => {
        // Resolve client IP safely
        const ip = socket.handshake.address || socket.conn.remoteAddress || '127.0.0.1';

        // Check if IP is already blocked in static blacklist
        if (staticBlacklist.includes(ip)) {
          logger.warn(`[WebSocket Guard] Disconnecting socket connection from blocked IP: ${ip}`);
          socket.disconnect(true);
          return;
        }

        wsRateStore.set(socket.id, {
          timestamps: [],
          ip
        });

        // Intercept incoming messages
        socket.use(([event, ...args], next) => {
          const now = Date.now();
          const rateData = wsRateStore.get(socket.id);

          if (rateData) {
            rateData.timestamps.push(now);
            // Filter timestamps to sliding window
            rateData.timestamps = rateData.timestamps.filter(t => now - t <= windowMs);

            // Check if client is flooding the socket
            if (rateData.timestamps.length > maxMessages) {
              logger.warn(`[WebSocket Guard] Flood detected! IP: ${ip} exceeded limit (${rateData.timestamps.length} msgs/sec). Disconnecting and blocking IP.`);
              
              // Add IP to firewall blocklist
              if (!staticBlacklist.includes(ip)) {
                staticBlacklist.push(ip);
              }
              
              socket.disconnect(true);
              return;
            }
          }
          next();
        });

        socket.on('disconnect', () => {
          wsRateStore.delete(socket.id);
        });
      });
    }
  };
}

module.exports = {
  websocketGuard,
  wsRateStore
};
