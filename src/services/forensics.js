const fs = require('fs');
const path = require('path');
const { logger } = require('../core/logger');

let forensicsConfig = {};

/**
 * Initialize the Forensics configurations
 */
function initForensics(config) {
  forensicsConfig = config.forensics || {};
}

/**
 * Log full details of blocked requests into forensic files for analysis
 */
function logForensicEvent(req, score, reasons) {
  if (!forensicsConfig.enabled) return;

  const logFile = path.resolve(process.cwd(), forensicsConfig.logPath || 'webshield-forensics.json');
  
  const event = {
    id: req.id,
    timestamp: new Date().toISOString(),
    ip: req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || '127.0.0.1',
    method: req.method,
    url: req.originalUrl || req.url,
    headers: { ...req.headers },
    query: req.query || {},
    body: req.body || {},
    threatScore: score,
    reasons: reasons || [],
    fingerprint: req.webShieldState ? req.webShieldState.fingerprint : null
  };

  // Mask sensitive headers in forensic logs (prevent secret leak inside diagnostics database)
  if (event.headers.authorization) {
    event.headers.authorization = '[REDACTED AUTHORIZATION HEADER]';
  }
  if (event.headers.cookie) {
    event.headers.cookie = '[REDACTED COOKIES]';
  }

  fs.readFile(logFile, 'utf8', (err, data) => {
    let logs = [];
    if (!err && data) {
      try {
        logs = JSON.parse(data);
      } catch (parseErr) {
        logs = [];
      }
    }

    logs.unshift(event);

    // Limit maximum recorded items
    const maxLogs = forensicsConfig.maxLogs || 100;
    if (logs.length > maxLogs) {
      logs = logs.slice(0, maxLogs);
    }

    fs.writeFile(logFile, JSON.stringify(logs, null, 2), 'utf8', (writeErr) => {
      if (writeErr) {
        logger.error(`[Forensics Log Engine] Failed to record incident: ${writeErr.message}`);
      }
    });
  });
}

module.exports = {
  initForensics,
  logForensicEvent
};
