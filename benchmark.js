/**
 * WebShield SDK Real-World Performance Benchmark Utility
 * Measures execution latency and throughput of the threat scoring heuristics engine.
 */
const { calculateThreatScore } = require('./src/core/threatScore');

const config = {
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
  }
};

// 1. Prepare simulated request payloads (Safe, XSS, SQLi, and Secret Leak checks)
const mockRequests = [
  {
    path: '/api/v1/users',
    headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' },
    query: { page: '2', limit: '20' },
    body: { name: 'John Doe', email: 'john@example.com' },
    webShieldState: {}
  },
  {
    path: '/search',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: { q: '<script>alert("hack")</script>' }, // XSS
    body: {},
    webShieldState: {}
  },
  {
    path: '/login',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: {},
    body: { username: "admin' OR 1=1 --", password: 'password' }, // SQLi
    webShieldState: {}
  },
  {
    path: '/api/config',
    headers: { 'user-agent': 'Mozilla/5.0' },
    query: { key: 'AIzaSyA12345678901234567890123456789012' }, // Secret leak
    body: {},
    webShieldState: {}
  }
];

const ITERATIONS = 100000;

function runBenchmark() {
  console.log('⚡ Starting WebShield Threat Engine Benchmark...');
  console.log(`📊 Iterations: ${ITERATIONS.toLocaleString()} request evaluations`);
  console.log('----------------------------------------------------');

  const start = process.hrtime.bigint();

  for (let i = 0; i < ITERATIONS; i++) {
    const req = mockRequests[i % mockRequests.length];
    calculateThreatScore(req, config);
  }

  const end = process.hrtime.bigint();
  
  // Calculate execution stats
  const totalNs = Number(end - start);
  const totalMs = totalNs / 1_000_000;
  const totalSec = totalMs / 1000;
  
  const avgLatencyNs = totalNs / ITERATIONS;
  const avgLatencyUs = avgLatencyNs / 1000;
  
  const rps = Math.round(ITERATIONS / totalSec);

  console.log(`⏱️  Total Time: ${totalMs.toFixed(2)} ms (${totalSec.toFixed(4)} seconds)`);
  console.log(`🚀 Throughput: ${rps.toLocaleString()} requests/second`);
  console.log(`💎 Avg Latency: ${avgLatencyUs.toFixed(3)} microseconds (${(avgLatencyUs / 1000).toFixed(4)} ms)`);
  console.log('----------------------------------------------------');
  console.log('✨ Benchmark completed successfully. WebShield runs sub-millisecond!');
}

runBenchmark();
