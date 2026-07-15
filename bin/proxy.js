const http = require('http');
const { URL } = require('url');
const { webShield } = require('../src/index');

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:3000';
const PROXY_PORT = process.env.PROXY_PORT || 8080;

// Initialize WebShield SDK in Gateway Mode
const shieldMiddleware = webShield({
  mode: 'strict',
  protection: {
    xss: true,
    csrf: false, // Disable CSRF verification inside simple reverse proxies
    sqlInjection: true,
    nosqlInjection: true,
    headers: true
  }
});

const proxyServer = http.createServer((req, res) => {
  // Run request through WebShield orchestrator
  shieldMiddleware(req, res, (err) => {
    if (err) {
      res.statusCode = 500;
      return res.end('Internal Proxy Gateway Error.');
    }

    // If WebShield blocked the request, exit early (middleware already responded)
    if (req.webShieldState && req.webShieldState.blocked) {
      return;
    }

    // Parse target destination coordinates
    const backend = new URL(BACKEND_URL);

    // Forward intercepted headers and payload stream
    const forwardRequest = http.request({
      host: backend.hostname,
      port: backend.port,
      path: req.url,
      method: req.method,
      headers: req.headers
    }, (forwardResponse) => {
      res.writeHead(forwardResponse.statusCode, forwardResponse.headers);
      forwardResponse.pipe(res);
    });

    forwardRequest.on('error', (proxyErr) => {
      res.statusCode = 502;
      res.end(`Bad Gateway: Connection error targeting backend ${BACKEND_URL}. Log: ${proxyErr.message}`);
    });

    req.pipe(forwardRequest);
  });
});

proxyServer.listen(PROXY_PORT, () => {
  console.log(`🛡️  WebShield Reverse Proxy Gateway running on port ${PROXY_PORT}`);
  console.log(`📡 Forwarding filtered traffic to: ${BACKEND_URL}`);
});
