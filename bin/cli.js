#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const command = process.argv[2];

if (command === 'init') {
  console.log('🛡️  Initializing WebShield SDK Configuration File...');
  
  const configTemplate = `/**
 * WebShield SDK Configuration Settings
 */
module.exports = {
  apiKey: null, // Optional: Only required for remote cloud dashboard syncing
  mode: "strict", // 'strict' (block) or 'monitor' (flag and log)
  isolated: false, // Emergency lockdown mode

  allowlist: [
    '127.0.0.1'
  ],

  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true,
    secureCookies: false,
    headers: true,
    requestSizeLimit: '2mb'
  },

  rateLimit: {
    windowMs: 60000,
    max: 100,
    burstMax: 10
  },

  honeypot: {
    enabled: true,
    paths: ['/admin', '/.env', '/wp-admin']
  },

  cors: {
    mode: 'dynamic',
    allowedOrigins: ['*']
  },

  // WAF Custom DSL Rules (Zero-Trust Logic blocks)
  rules: [
    'if (path.includes("confidential")) block()',
    'if (headers["x-custom-block"] === "true") block()'
  ]
};
`;

  const targetFile = path.resolve(process.cwd(), 'webshield.config.js');
  try {
    fs.writeFileSync(targetFile, configTemplate, 'utf8');
    console.log(`✅ Success: Generated config file at ${targetFile}`);
  } catch (err) {
    console.error(`❌ Error writing configuration file: ${err.message}`);
  }
} else if (command === 'dashboard') {
  const express = require('express');
  const app = express();
  const PORT = process.env.PORT || 9999;

  console.log('🛡️  Launching Standalone WebShield Diagnostic Dashboard...');

  app.get('/', (req, res) => {
    const forensicsFile = path.resolve(process.cwd(), 'webshield-forensics.json');
    let logs = [];
    if (fs.existsSync(forensicsFile)) {
      try {
        logs = JSON.parse(fs.readFileSync(forensicsFile, 'utf8'));
      } catch (err) {
        logs = [];
      }
    }

    const logRows = logs.map(log => `
      <div style="background: #131a26; border: 1px solid #1e293b; padding: 1.25rem; border-radius: 8px; margin-bottom: 1rem; text-align: left; transition: border-color 0.2s;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <span style="color: #38bdf8; font-weight: 600; font-size: 1.05rem;">
            <span style="background: rgba(56, 189, 248, 0.1); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; margin-right: 0.5rem;">${log.method}</span>
            ${log.url}
          </span>
          <span style="color: #f87171; font-weight: bold; background: rgba(248, 113, 113, 0.1); padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.9rem;">
            Score: ${log.threatScore}
          </span>
        </div>
        <div style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.75rem; border-bottom: 1px dashed #1e293b; padding-bottom: 0.5rem;">
          <strong>IP:</strong> ${log.ip} &nbsp;|&nbsp; <strong>Time:</strong> ${new Date(log.timestamp).toLocaleString()} &nbsp;|&nbsp; <strong>Req ID:</strong> <code style="font-family: monospace; color: #e2e8f0;">${log.id}</code>
        </div>
        <div style="color: #34d399; font-size: 0.9rem; font-weight: 500;">
          ⚠️ <strong>Blocked Reasons:</strong> ${log.reasons.join('; ')}
        </div>
      </div>
    `).join('') || '<div style="color: #94a3b8; padding: 2rem;">No security threats or incident forensics logged yet.</div>';

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebShield Security Dashboard Monitor</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background-color: #0b0f17; color: #f8fafc; padding: 3rem 1.5rem; margin: 0; }
          .container { max-width: 800px; margin: 0 auto; }
          header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2.5rem; border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; }
          h1 { color: #38bdf8; font-size: 1.75rem; margin: 0; display: flex; align-items: center; gap: 0.75rem; }
          .pulse { display: inline-block; width: 12px; height: 12px; border-radius: 50%; background-color: #34d399; animation: pulse-anim 1.5s infinite; }
          @keyframes pulse-anim { 0% { opacity: 0.3; } 50% { opacity: 1; } 100% { opacity: 0.3; } }
          .banner { background-color: #1e293b; border-radius: 6px; padding: 1rem; font-size: 0.9rem; color: #94a3b8; margin-bottom: 2rem; display: flex; align-items: center; justify-content: space-between; }
          .btn { background-color: #38bdf8; color: #0b0f17; text-decoration: none; padding: 0.5rem 1rem; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 0.85rem; border: none; }
          .btn:hover { background-color: #7dd3fc; }
        </style>
      </head>
      <body>
        <div class="container">
          <header>
            <h1>🛡️ WebShield Live Monitor <span class="pulse"></span></h1>
            <button class="btn" onclick="window.location.reload()">Refresh Feed</button>
          </header>
          <div class="banner">
            <span>Diagnostics listener active on port <strong>${PORT}</strong>. Visualizing localized <code>webshield-forensics.json</code> telemetry logs.</span>
          </div>
          <div class="logs-list">
            ${logRows}
          </div>
        </div>
      </body>
      </html>
    `);
  });

  app.listen(PORT, () => {
    console.log(`🚀 Standalone Event Dashboard active: http://localhost:${PORT}`);
  });
} else {
  console.log('\n🛡️  WebShield SDK Command-Line Tool');
  console.log('====================================');
  console.log('Commands:');
  console.log('  npx webshield init      - Generate a custom webshield.config.js settings template');
  console.log('  npx webshield dashboard - Launch standalone diagnostics monitor visualizer');
  console.log('');
}
