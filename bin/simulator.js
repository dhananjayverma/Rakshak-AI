const axios = require('axios');

const TARGET_HOST = process.argv[2] || 'http://localhost:3000';

/**
 * Dispatches simulated attack payloads to verify WAF block responses
 */
async function runAttackSimulations() {
  console.log(`🛡️  WebShield Attack Simulator Running`);
  console.log(`🎯 Targeting Endpoint: ${TARGET_HOST}`);
  console.log('=======================================\n');

  const attackScenarios = [
    {
      name: 'Standard Legitimate Query',
      method: 'GET',
      url: `${TARGET_HOST}/`,
      data: null
    },
    {
      name: 'Cross-Site Scripting (XSS) exploit',
      method: 'GET',
      url: `${TARGET_HOST}/?q=<script>document.cookie</script>`,
      data: null
    },
    {
      name: 'SQL Injection payload',
      method: 'POST',
      url: `${TARGET_HOST}/submit`,
      data: { query: 'SELECT * FROM users WHERE username = "admin" OR "1"="1"' }
    },
    {
      name: 'Honeypot Decoy path traversal',
      method: 'GET',
      url: `${TARGET_HOST}/admin`,
      data: null
    }
  ];

  for (const scenario of attackScenarios) {
    console.log(`[Testing] ${scenario.name}...`);
    try {
      let response;
      if (scenario.method === 'GET') {
        response = await axios.get(scenario.url);
      } else {
        response = await axios.post(scenario.url, scenario.data);
      }
      console.log(`  🟢 Status: ALLOWED (HTTP ${response.status})\n`);
    } catch (err) {
      if (err.response) {
        console.log(`  🔴 Status: BLOCKED (HTTP ${err.response.status} - ${err.response.data || 'Forbidden'})\n`);
      } else {
        console.log(`  ❌ Connection Failure: ${err.message}\n`);
      }
    }
  }
}

runAttackSimulations();
