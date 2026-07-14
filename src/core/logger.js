const winston = require('winston');

let logger = console; // Fallback to basic console

function initializeLogger(config) {
  if (!config.logging || !config.logging.enabled) {
    logger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {}
    };
    return logger;
  }

  const transports = [];

  if (config.logging.console) {
    transports.push(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          winston.format.printf(({ timestamp, level, message }) => {
            return `[WebShield] ${timestamp} [${level}]: ${message}`;
          })
        )
      })
    );
  }

  if (config.logging.file && config.logging.filePath) {
    transports.push(
      new winston.transports.File({
        filename: config.logging.filePath,
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    );
  }

  const rawLogger = winston.createLogger({
    level: config.logging.level || 'info',
    transports
  });

  // Proxy logger calls to enforce log sampling on 'info' tier if configured
  logger = {
    info: (msg) => {
      if (config.logging.samplingEnabled) {
        if (Math.random() > (config.logging.samplingRate || 0.1)) return;
      }
      rawLogger.info(msg);
    },
    warn: (msg) => rawLogger.warn(msg),
    error: (msg) => rawLogger.error(msg),
    debug: (msg) => rawLogger.debug(msg)
  };

  return logger;
}

module.exports = {
  initializeLogger,
  get logger() {
    return logger;
  }
};
