const assert = require('assert');
const { calculateThreatScore } = require('./src/core/threatScore');
const { corsGuardMiddleware } = require('./src/middleware/corsGuard');

// Setup dummy configuration options
const testConfig = {
  protection: {
    xss: true,
    csrf: true,
    sqlInjection: true,
    nosqlInjection: true
  },
  secretLeak: {
    enabled: true,
    patterns: [/AIza[0-9A-Za-z-_]{35}/i]
  },
  riskBasedAccess: {
    captchaThreshold: 50,
    blockThreshold: 75
  },
  cors: {
    mode: 'dynamic',
    allowedOrigins: ['https://trusted.com', /^https:\/\/.*\.vercel\.app$/]
  }
};

/**
 * Run WebShield Threat Engine Unit Tests
 */
function runThreatScoreTests() {
  console.log('🧪 Running Threat Scoring Engine Tests...');

  // Test Case 1: Safe request should return 0 score
  const safeReq = {
    path: '/',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: {},
    body: {},
    webShieldState: {}
  };
  const safeResult = calculateThreatScore(safeReq, testConfig);
  assert.strictEqual(safeResult.score, 0);
  assert.strictEqual(safeResult.isMalicious, false);
  console.log('✅ Passed: Safe Request check');

  // Test Case 2: XSS script tag injection check
  const xssReq = {
    path: '/',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: { input: '<script>alert(1)</script>' },
    body: {},
    webShieldState: {}
  };
  const xssResult = calculateThreatScore(xssReq, testConfig);
  assert.ok(xssResult.score >= 40);
  console.log('✅ Passed: XSS payload detection check');

  // Test Case 3: SQL Injection union pattern check
  const sqliReq = {
    path: '/',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: { query: 'UNION SELECT username, password FROM users' },
    body: {},
    webShieldState: {}
  };
  const sqliResult = calculateThreatScore(sqliReq, testConfig);
  assert.ok(sqliResult.score >= 35);
  console.log('✅ Passed: SQL Injection detection check');

  // Test Case 4: Google API Key leak check
  const leakReq = {
    path: '/',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: { key: 'AIzaSyA12345678901234567890123456789012' },
    body: {},
    webShieldState: {}
  };
  const leakResult = calculateThreatScore(leakReq, testConfig);
  assert.ok(leakResult.score >= 45);
  console.log('✅ Passed: Secret leak scanning check');
}

/**
 * Run CORS Middleware Unit Tests
 */
function runCorsTests() {
  console.log('🧪 Running Dynamic CORS Engine Tests...');
  const runCors = corsGuardMiddleware(testConfig);

  // Test Case 1: Server-to-server request (no origin) should be allowed
  runCors({ headers: {} }, { setHeader: () => {}, end: () => {} }, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Server-to-server allowed');
  });

  // Test Case 2: Whitelisted origin string match should be allowed
  runCors({ headers: { origin: 'https://trusted.com' } }, { setHeader: () => {}, end: () => {} }, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Whitelisted Origin allowed');
  });

  // Test Case 3: RegExp matching origin match should be allowed
  runCors({ headers: { origin: 'https://my-subdomain.vercel.app' } }, { setHeader: () => {}, end: () => {} }, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Regex pattern matching allowed');
  });

  // Test Case 4: Unlisted origin should trigger CORS error block
  runCors({ headers: { origin: 'https://malicious.com' } }, { setHeader: () => {}, end: () => {} }, (err) => {
    assert.ok(err instanceof Error);
    console.log('✅ Passed: CORS Unauthorized Origin blocked');
  });
}

// Orchestrate runs
try {
  runThreatScoreTests();
  runCorsTests();
  console.log('\n🎉 ALL WEBSHIELD SDK TESTS PASSED SUCCESSFULLY!');
  process.exit(0);
} catch (testError) {
  console.error('\n❌ TEST FAILURE ENCOUNTERED:', testError.message);
  process.exit(1);
}
