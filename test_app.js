const express = require('express');
const { webShield, plugins } = require('./src/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable JSON parser for body parsing (needed by threat score checks)
app.use(express.json());

// Initialize WebShield middleware with all features active
app.use(webShield({
  apiKey: 'demo_test_key',
  mode: 'strict', // Set to monitor to just log instead of blocking
  
  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true
  },

  // Dynamic and Configurable CORS settings
  cors: {
    mode: 'dynamic',
    allowedOrigins: [
      'http://localhost:3000',
      /^https:\/\/.*\.vercel\.app$/, // Regex pattern allowed
      '*.my-startup.com'            // Wildcard pattern allowed
    ]
  },

  // Dynamic WAF Rules configuration
  waf: {
    enabled: true,
    rules: [
      { type: 'path', action: 'block', value: '/confidential' },
      { type: 'header', action: 'block', key: 'x-custom-hack', value: 'malicious' }
    ]
  },

  // Secret leak detection
  secretLeak: {
    enabled: true
  },

  // Risk-based access control rules
  riskBasedAccess: {
    enabled: true,
    captchaThreshold: 50,
    blockThreshold: 75
  },
  
  rateLimit: {
    windowMs: 10000, // Shortened to 10s for fast manual testing
    max: 5,         // Max 5 requests in 10s
    burstMax: 3     // Max 3 requests in 5s
  },
  
  honeypot: {
    enabled: true,
    paths: ['/admin', '/.env', '/wp-admin']
  },
  
  plugins: [
    plugins.ddosPlugin({ threshold: 5 }),
    plugins.botDetectionPlugin({ blockCrawlers: true }),
    plugins.sqlInjectionPlugin({ strict: true })
  ]
}));

// Setup normal test routes
app.get('/', (req, res) => {
  res.send('Welcome to the Secure WebShield Application! 🛡️');
});

app.post('/submit', (req, res) => {
  res.json({
    status: 'success',
    receivedData: req.body
  });
});

app.listen(PORT, () => {
  console.log(`[Test App] Running on http://localhost:${PORT}`);
  console.log(`[Test App] Verify WAF rule by visiting /confidential`);
  console.log(`[Test App] Verify Secret leak scanning by POSTing a Google API Key: "AIzaSy..." to /submit`);
});
