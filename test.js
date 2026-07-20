const assert = require('assert');
process.env.NODE_ENV = 'production'; // Enforce strict production rules for testing
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
    headers: {
      'user-agent': 'Mozilla/5.0',
      'accept-language': 'en-US,en;q=0.9'
    },
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
    query: { key: 'AIzaSy' + 'A12345678901234567890123456789012' },
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

  // Mock response object satisfying `vary` library requirements (getHeader and setHeader functions)
  const mockRes = {
    getHeader: () => {},
    setHeader: () => {},
    end: () => {}
  };

  // Test Case 1: Server-to-server request (no origin) should be allowed
  runCors({ headers: {} }, mockRes, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Server-to-server allowed');
  });

  // Test Case 2: Whitelisted origin string match should be allowed
  runCors({ headers: { origin: 'https://trusted.com' } }, mockRes, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Whitelisted Origin allowed');
  });

  // Test Case 3: RegExp matching origin match should be allowed
  runCors({ headers: { origin: 'https://my-subdomain.vercel.app' } }, mockRes, (err) => {
    assert.strictEqual(err, undefined);
    console.log('✅ Passed: CORS Regex pattern matching allowed');
  });

  // Test Case 4: Unlisted origin should trigger CORS error block
  runCors({ headers: { origin: 'https://malicious.com' } }, mockRes, (err) => {
    assert.ok(err instanceof Error);
    console.log('✅ Passed: CORS Unauthorized Origin blocked');
  });
}

/**
 * Run GraphQL Depth Limit Guard Unit Tests
 */
function runGraphQLTests() {
  console.log('🧪 Running GraphQL depth checks...');
  const graphqlGuard = require('./src/middleware/graphqlGuard');
  const runGraphql = graphqlGuard({ maxDepth: 3, depthBanThreshold: 5 });

  const mockRes = {
    status: (code) => {
      assert.strictEqual(code, 400);
      return { json: (body) => { assert.strictEqual(body.success, false); } };
    }
  };

  // Safe shallow query
  const safeReq = {
    method: 'POST',
    body: { query: 'query { user { id name } }' },
    webShieldState: {}
  };
  runGraphql(safeReq, mockRes);
  assert.strictEqual(safeReq.webShieldState.blocked, undefined);
  console.log('✅ Passed: GraphQL shallow query permitted');

  // Nested query exceeding limit
  const nestedReq = {
    method: 'POST',
    body: { query: 'query { user { posts { comments { author { id } } } } }' },
    webShieldState: {}
  };
  runGraphql(nestedReq, mockRes);
  assert.strictEqual(nestedReq.webShieldState.blocked, true);
  console.log('✅ Passed: GraphQL query exceeding depth blocked');
}

/**
 * Run API Schema validation tests
 */
function runSchemaTests() {
  console.log('🧪 Running Schema validation checks...');
  const schemaGuard = require('./src/middleware/schemaGuard');
  const runSchema = schemaGuard({
    schemas: {
      '/register': {
        requiredFields: ['email', 'password'],
        allowedFields: ['email', 'password', 'name']
      }
    }
  });

  const mockRes = {
    status: (code) => {
      assert.strictEqual(code, 400);
      return { json: (body) => { assert.strictEqual(body.success, false); } };
    }
  };

  // Missing required parameter email
  const missingReq = {
    path: '/register',
    body: { password: '123' },
    webShieldState: {}
  };
  runSchema(missingReq, mockRes);
  assert.strictEqual(missingReq.webShieldState.blocked, true);
  console.log('✅ Passed: Schema missing key validation block');

  // Unexpected parameter admin
  const unexpectedReq = {
    path: '/register',
    body: { email: 'test@webshield.io', password: '123', admin: true },
    webShieldState: {}
  };
  runSchema(unexpectedReq, mockRes);
  assert.strictEqual(unexpectedReq.webShieldState.blocked, true);
  console.log('✅ Passed: Schema forbidden key parameter block');
}

/**
 * Run Challenge trigger tests
 */
function runChallengeTests() {
  console.log('🧪 Running Challenge trigger checks...');
  const challengeMiddleware = require('./src/middleware/challenge');
  const runChallenge = challengeMiddleware({ thresholdMin: 50, thresholdMax: 74 });

  const mockRes = {
    setHeader: () => {},
    status: (code) => {
      assert.strictEqual(code, 403);
      return { send: (body) => { assert.ok(body.includes('Challenge')); } };
    }
  };

  // Threat score triggering challenge
  const challengeReq = {
    webShieldState: {}
  };
  runChallenge(challengeReq, mockRes, 65);
  assert.strictEqual(challengeReq.webShieldState.blocked, true);
  console.log('✅ Passed: Threat score within Medium risk triggers challenge');
}

/**
 * Run WAF DSL Rule Engine tests
 */
function runDSLTests() {
  console.log('🧪 Running Custom WAF DSL Rule Engine checks...');
  const { evaluateDslRule } = require('./src/core/ruleEngine');

  const mockRes = {
    status: (code) => {
      assert.strictEqual(code, 403);
      return { send: (body) => { assert.ok(body.includes('blocked')); } };
    }
  };

  // 1. Matching rule triggers block()
  const blockReq = {
    path: '/admin/confidential',
    headers: {},
    webShieldState: {}
  };
  const blocked = evaluateDslRule('if (path.includes("confidential")) block()', blockReq, mockRes);
  assert.strictEqual(blocked, true);
  assert.strictEqual(blockReq.webShieldState.blocked, true);
  console.log('✅ Passed: Custom DSL block() action works');

  // 2. Non-matching rule passes through
  const passReq = {
    path: '/public',
    headers: {},
    webShieldState: {}
  };
  const triggered = evaluateDslRule('if (path.includes("confidential")) block()', passReq, mockRes);
  assert.strictEqual(triggered, false);
  assert.strictEqual(passReq.webShieldState.blocked, undefined);
  console.log('✅ Passed: Custom DSL non-matching rule bypass works');
}

/**
 * Run Device Fingerprinting tests
 */
function runFingerprintTests() {
  console.log('🧪 Running Device Fingerprinting (Canvas + WebGL) checks...');
  const { getFingerprintScript } = require('./src/core/fingerprintTag');
  const { calculateThreatScore } = require('./src/core/threatScore');

  // 1. Verify fingerprint script generator outputs code
  const scriptCode = getFingerprintScript();
  assert.ok(scriptCode.includes('canvas') && scriptCode.includes('webgl'));
  console.log('✅ Passed: Fingerprint script generation yields canvas/webgl routines');

  // 2. Verify score elevation on canvas-blocked fingerprint parameter
  const mockConfig = {
    protection: {},
    secretLeak: { enabled: false },
    riskBasedAccess: { captchaThreshold: 50, blockThreshold: 75 }
  };
  const blockedFpReq = {
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'x-webshield-device-id': 'canvas-blocked'
    },
    webShieldState: {}
  };
  const score = calculateThreatScore(blockedFpReq, mockConfig);
  assert.ok(score.score > 0);
  assert.strictEqual(blockedFpReq.webShieldState.deviceId, 'canvas-blocked');
  console.log('✅ Passed: Canvas fingerprint blocking/obfuscation correctly raises threat score');
}

/**
 * Run Secrets Vault and Multi-Tenant SaaS Config tests
 */
function runVaultAndTenantTests() {
  console.log('🧪 Running Secrets Vault & Multi-Tenant SaaS checks...');
  const { loadSecretsFromVault } = require('./src/services/vault');
  const { tenantResolverMiddleware } = require('./src/middleware/tenantResolver');

  // 1. Verify secrets vault loading fallback to environment variables
  process.env.WEBSHIELD_API_KEY = 'test_env_secret_key_112233';
  const mockConfig = {
    apiKey: 'original_key',
    vault: { enabled: false }
  };
  loadSecretsFromVault(mockConfig);
  assert.strictEqual(mockConfig.apiKey, 'test_env_secret_key_112233');
  console.log('✅ Passed: Secrets Vault environment variable auto-scan configuration');

  // 2. Verify dynamic multi-tenant configs resolution
  const globalConfig = {
    mode: 'strict',
    rateLimit: { max: 100 },
    waf: { enabled: true, rules: [] },
    protection: {}
  };
  const resolver = tenantResolverMiddleware(globalConfig);
  const mockReq = {
    headers: { 'x-tenant-id': 'client-saas-a' },
    hostname: 'localhost'
  };
  resolver(mockReq, {}, () => {});
  // Assert that rateLimit and WAF rules are swapped for tenant-a
  assert.strictEqual(mockReq.webShieldConfig.rateLimit.max, 3);
  assert.ok(mockReq.webShieldConfig.waf.rules.length > 0);
  console.log('✅ Passed: Multi-Tenant dynamic configuration context resolver');
}

/**
 * Run Next-Gen Security Suite checks
 */
function runNextGenSecurityTests() {
  console.log('🧪 Running Next-Gen Security Suite checks...');
  const { dynamicHoneypotMiddleware } = require('./src/middleware/dynamicHoneypot');
  const { stealthModeMiddleware } = require('./src/middleware/stealthMode');
  const { consciousnessMiddleware } = require('./src/middleware/consciousness');
  const { recordAttackPath, predictNextTarget } = require('./src/services/attackGraph');

  // 1. Verify dynamic honeypots response and score flagging
  const honeyReq = { path: '/.env', webShieldState: {} };
  const mockRes = {
    setHeader: () => {},
    status: (code) => {
      assert.strictEqual(code, 200);
      return { send: (body) => { assert.ok(body.includes('DB_CONNECTION')); } };
    }
  };
  const runHoneypot = dynamicHoneypotMiddleware({});
  runHoneypot(honeyReq, mockRes, () => {});
  assert.strictEqual(honeyReq.webShieldState.honeypotHit, true);
  console.log('✅ Passed: Adaptive Honeypot 2.0 dynamic dump and delay triggers');

  // 2. Verify stealth mode tar-pit delayed response masking
  const stealthReq = { path: '/submit', webShieldState: { blocked: true } };
  const stealthRes = {
    setHeader: () => {},
    status: (code) => {
      assert.strictEqual(code, 200);
      return { send: (body) => { assert.ok(body.includes('success')); } };
    }
  };
  const runStealth = stealthModeMiddleware({ stealthMode: true });
  // Overwrite setTimeout to run synchronously in test run
  const originalTimeout = global.setTimeout;
  global.setTimeout = (fn) => fn();
  runStealth(stealthReq, stealthRes, () => {});
  global.setTimeout = originalTimeout;
  console.log('✅ Passed: Stealth Mode WAF concealment and tar-pit delays');

  // 3. Verify consciousness bot trajectory validator
  const botReq = { method: 'POST', headers: {}, webShieldState: {} };
  const runConsciousness = consciousnessMiddleware({ consciousnessCheck: true });
  runConsciousness(botReq, {}, () => {});
  assert.strictEqual(botReq.webShieldState.botDetected, true);
  console.log('✅ Passed: Bot Consciousness Telemetry verification');

  // 4. Verify Attack Graph recording
  recordAttackPath('127.0.0.1', '/');
  recordAttackPath('127.0.0.1', '/login');
  const forecast = predictNextTarget('127.0.0.1');
  assert.strictEqual(forecast.prediction, '/admin');
  console.log('✅ Passed: Attacker Mindmap trajectory mapping & forecasting');
}

/**
 * Run Zero-Config WAF tests
 */
function runZeroConfigTests() {
  console.log('🧪 Running Zero-Config & Smart Auto Mode checks...');

  // 1. Verify dynamic mode initialization in production environment
  process.env.NODE_ENV = 'production';
  delete require.cache[require.resolve('./src/core/config')];
  delete require.cache[require.resolve('./src/core/engine')];
  const WebShieldProd = require('./src/core/engine');
  const engineProd = new WebShieldProd();
  assert.strictEqual(engineProd.config.mode, 'strict');

  // 2. Verify dynamic mode initialization in development environment
  process.env.NODE_ENV = 'development';
  delete require.cache[require.resolve('./src/core/config')];
  delete require.cache[require.resolve('./src/core/engine')];
  const WebShieldDev = require('./src/core/engine');
  const engineDev = new WebShieldDev();
  assert.strictEqual(engineDev.config.mode, 'monitor');
  console.log('✅ Passed: Smart Auto Mode dev/prod environment defaults');
}

/**
 * Run Advanced WebShield Security features checks
 */
function runAdvancedFeaturesTests() {
  console.log('🧪 Running Advanced WebShield Security features checks...');

  const WebShield = require('./src/core/engine');
  const engine = new WebShield({ mode: 'strict' });
  const { calculateThreatScore } = require('./src/core/threatScore');

  // 1. Deep Request Inspection - Nested JSON
  const nestedReq = {
    method: 'POST',
    path: '/api/test',
    headers: { 'user-agent': 'Mozilla/5.0' },
    body: { data: { nested: { payload: '<script>alert(1)</script>' } } },
    webShieldState: { blocked: false }
  };
  const nestedThreat = calculateThreatScore(nestedReq, engine.config);
  assert.ok(nestedThreat.score > 30, 'Should detect XSS in nested JSON body');
  console.log('✅ Passed: Deep request inspection (Nested JSON)');

  // 2. Deep Request Inspection - Base64 Payload
  const base64Req = {
    method: 'POST',
    path: '/api/test',
    headers: { 'user-agent': 'Mozilla/5.0' },
    body: { data: 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' }, // <script>alert(1)</script>
    webShieldState: { blocked: false }
  };
  const base64Threat = calculateThreatScore(base64Req, engine.config);
  assert.ok(base64Threat.score > 30, 'Should detect Base64 encoded XSS payload');
  console.log('✅ Passed: Deep request inspection (Base64 decoded)');

  // 3. Behavioral Tracking - Spike Detection
  const { behavioralTrackerMiddleware, trackingStore } = require('./src/middleware/behavioralTracker');
  const tracker = behavioralTrackerMiddleware({ spikeThreshold: 2 });
  const spikeReq = {
    ip: '192.168.1.99',
    path: '/test',
    headers: {},
    webShieldState: {}
  };
  // Simulate 3 requests in under 5 seconds
  tracker(spikeReq, {}, () => {});
  tracker(spikeReq, {}, () => {});
  tracker(spikeReq, {}, () => {});
  assert.strictEqual(spikeReq.webShieldState.requestSpikeDetected, true, 'Should detect request spike');
  console.log('✅ Passed: Behavioral tracking (Spike detection)');

  // 4. API Abuse - Token Sharing
  const sharedReq1 = { ip: '10.0.0.1', path: '/api', headers: { 'x-api-key': 'secret-token', 'x-client-ip': '10.0.0.1' }, webShieldState: {} };
  const sharedReq2 = { ip: '10.0.0.2', path: '/api', headers: { 'x-api-key': 'secret-token', 'x-client-ip': '10.0.0.2' }, webShieldState: {} };
  const sharedReq3 = { ip: '10.0.0.3', path: '/api', headers: { 'x-api-key': 'secret-token', 'x-client-ip': '10.0.0.3' }, webShieldState: {} };
  const sharedReq4 = { ip: '10.0.0.4', path: '/api', headers: { 'x-api-key': 'secret-token', 'x-client-ip': '10.0.0.4' }, webShieldState: {} };
  calculateThreatScore(sharedReq1, engine.config);
  calculateThreatScore(sharedReq2, engine.config);
  calculateThreatScore(sharedReq3, engine.config);
  const sharedThreat4 = calculateThreatScore(sharedReq4, engine.config);
  assert.ok(sharedThreat4.score >= 50, 'Should flag token sharing abuse');
  console.log('✅ Passed: API Abuse protection (Token sharing)');

  // 5. Self-Healing WAF Rules
  const healingReq = {
    method: 'POST',
    path: '/api/test',
    headers: { 'user-agent': 'Mozilla/5.0' },
    body: { data: 'select * from users; -- malicious-healing-payload-test' },
    webShieldState: { blocked: false }
  };
  const threatScoreRes = calculateThreatScore(healingReq, engine.config);
  
  const selfHealing = require('./src/services/selfHealing');
  const initialRulesCount = engine.activeRules.length;
  selfHealing.analyzeAndHeal(healingReq, 100, ['SQL Injection patterns detected'], engine);
  
  assert.ok(engine.activeRules.length > initialRulesCount, 'Should dynamically generate new WAF rule');
  assert.ok(engine.activeRules[engine.activeRules.length - 1].includes('malicious-healing-payload-test'), 'Should block custom offending payload');
  console.log('✅ Passed: Self-Healing security rule adaptation');

  // 6. DDoS Smart Mode Dynamic Latency Throttle
  const { ddosSmartModeMiddleware } = require('./src/middleware/ddosSmartMode');
  const ddosReq = {
    ip: '127.0.0.1',
    webShieldThreat: { score: 65 }, // Medium threat score
    webShieldState: {}
  };
  const start = Date.now();
  const runDdosSmart = ddosSmartModeMiddleware({ enabled: true });
  runDdosSmart(ddosReq, {}, () => {
    const elapsed = Date.now() - start;
    const expectedDelay = (65 - 50) * 80; // 1200ms
    assert.ok(elapsed >= expectedDelay - 100, 'DDoS Smart Mode should introduce dynamic delay');
    assert.strictEqual(ddosReq.webShieldState.throttledMs, expectedDelay, 'Should track throttle duration');
    console.log('✅ Passed: DDoS Smart Mode dynamic tar-pit throttling');
  });

  // 7. WebSocket Flood Guard
  const { websocketGuard, wsRateStore } = require('./src/middleware/websocketGuard');
  const { staticBlacklist } = require('./src/middleware/ipBlocker');
  
  const mockIo = {
    connectionCb: null,
    on(event, cb) {
      if (event === 'connection') this.connectionCb = cb;
    }
  };

  const wsGuardInstance = websocketGuard({ windowMs: 1000, maxMessages: 5 });
  wsGuardInstance.attach(mockIo);

  let disconnected = false;
  const mockSocket = {
    id: 'socket-test-123',
    handshake: { address: '198.51.100.99' },
    conn: { remoteAddress: '198.51.100.99' },
    middlewareHook: null,
    use(cb) {
      this.middlewareHook = cb;
    },
    disconnect(val) {
      if (val) disconnected = true;
    },
    on(event, cb) {}
  };

  // Trigger client connection
  mockIo.connectionCb(mockSocket);

  // Send 6 messages rapidly (limit is 5)
  for (let i = 0; i < 6; i++) {
    if (mockSocket.middlewareHook) {
      mockSocket.middlewareHook(['message', 'hello'], (err) => {});
    }
  }

  assert.strictEqual(disconnected, true, 'Should disconnect socket on message flood');
  assert.ok(staticBlacklist.includes('198.51.100.99'), 'Should add flooding IP to firewall blocklist');
  console.log('✅ Passed: WebSocket Guard connection flood blocker');
}

// Orchestrate runs
try {
  runThreatScoreTests();
  runCorsTests();
  runGraphQLTests();
  runSchemaTests();
  runChallengeTests();
  runDSLTests();
  runFingerprintTests();
  runVaultAndTenantTests();
  runNextGenSecurityTests();
  runZeroConfigTests();
  runAdvancedFeaturesTests();
  console.log('\n🎉 ALL WEBSHIELD SDK TESTS PASSED SUCCESSFULLY!');
  process.exit(0);
} catch (testError) {
  console.error('\n❌ TEST FAILURE ENCOUNTERED:', testError.stack || testError.message);
  process.exit(1);
}
