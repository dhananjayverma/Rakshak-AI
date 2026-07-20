const { logger } = require('../core/logger');
const axios = require('axios');

function challengeMiddleware(options = {}) {
  const thresholdMin = options.thresholdMin || 50;
  const thresholdMax = options.thresholdMax || 74;
  const siteKey = options.recaptchaSiteKey || null;

  return (req, res, threatScore) => {
    // If the request already has a valid challenge verification cookie, bypass
    if (req && req.headers && req.headers.cookie && req.headers.cookie.includes('webshield-verified=true')) {
      return;
    }

    if (threatScore >= thresholdMin && threatScore <= thresholdMax) {
      logger.warn(`[Req ID: ${req.id}] Serving Adaptive Challenge response for threat score: ${threatScore}`);
      req.webShieldState.blocked = true;

      res.setHeader('Content-Type', 'text/html');

      // Define challenge box HTML based on whether Google reCAPTCHA is configured
      let challengeFormHtml = '';
      if (siteKey) {
        challengeFormHtml = `
          <script src="https://www.google.com/recaptcha/api.js" async defer></script>
          <form method="POST" action="/webshield/challenge-verify">
            <div style="display: flex; justify-content: center; margin-bottom: 1.5rem;">
              <div class="g-recaptcha" data-sitekey="${siteKey}" data-theme="dark"></div>
            </div>
            <button type="submit">Verify & Proceed</button>
          </form>
        `;
      } else {
        challengeFormHtml = `
          <div class="math-challenge">What is 7 + 8?</div>
          <form method="POST" action="/webshield/challenge-verify">
            <input type="text" name="answer" placeholder="Enter your answer" required autocomplete="off">
            <button type="submit">Verify & Proceed</button>
          </form>
        `;
      }

      return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Security Verification Challenge | WebShield</title>
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
              background-color: #0b0f17;
              color: #f8fafc;
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100vh;
              margin: 0;
            }
            .challenge-box {
              background-color: #131a26;
              border: 1px solid #1e293b;
              padding: 2.5rem;
              border-radius: 12px;
              max-width: 440px;
              text-align: center;
              box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
            }
            h1 {
              font-size: 1.5rem;
              color: #38bdf8;
              margin-bottom: 1rem;
            }
            p {
              color: #94a3b8;
              font-size: 0.95rem;
              margin-bottom: 2rem;
            }
            .math-challenge {
              background-color: #0f141f;
              border: 1px solid #1e293b;
              padding: 1rem;
              border-radius: 6px;
              font-size: 1.25rem;
              font-weight: bold;
              margin-bottom: 1.5rem;
              color: #34d399;
            }
            input[type="text"] {
              width: 100%;
              padding: 0.75rem;
              background-color: #0b0f17;
              border: 1px solid #1e293b;
              border-radius: 6px;
              color: #fff;
              font-size: 1rem;
              text-align: center;
              outline: none;
              transition: border-color 0.2s;
            }
            input[type="text"]:focus {
              border-color: #38bdf8;
            }
            button {
              width: 100%;
              margin-top: 1rem;
              padding: 0.75rem;
              background-color: #38bdf8;
              border: none;
              border-radius: 6px;
              color: #0b0f17;
              font-size: 1rem;
              font-weight: 600;
              cursor: pointer;
              transition: background-color 0.2s;
            }
            button:hover {
              background-color: #7dd3fc;
            }
          </style>
        </head>
        <body>
          <div class="challenge-box">
            <h1>Security Check Required 🛡️</h1>
            <p>Your request pattern triggered temporary verification rules. Solve the puzzle below to continue to your destination:</p>
            ${challengeFormHtml}
          </div>
        </body>
        </html>
      `);
    }
  };
}

async function verifyChallenge(req, res, options = {}) {
  // Ensure we can parse URL-encoded body
  let body = req.body || {};
  if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
    // If not already parsed by middleware
    if (typeof body === 'string') {
      const querystring = require('querystring');
      body = querystring.parse(body);
    }
  }

  let isPassed = false;

  if (options.recaptchaSecretKey) {
    const responseToken = body['g-recaptcha-response'];
    if (responseToken) {
      try {
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${options.recaptchaSecretKey}&response=${responseToken}`;
        const verifyRes = await axios.post(verifyUrl);
        if (verifyRes.data && verifyRes.data.success) {
          isPassed = true;
        }
      } catch (err) {
        logger.error(`[Challenge Verification] reCAPTCHA verify request failed: ${err.message}`);
      }
    }
  } else {
    // Math challenge fallback
    const answer = body.answer ? body.answer.trim() : '';
    if (answer === '15') {
      isPassed = true;
    }
  }

  if (isPassed) {
    logger.info(`[Challenge Verification] IP: ${req.ip || req.connection.remoteAddress} successfully passed the security challenge.`);
    // Set a session cookie valid for 1 hour to bypass subsequent WAF challenges
    res.setHeader('Set-Cookie', 'webshield-verified=true; Path=/; HttpOnly; Max-Age=3600');
    
    // Redirect user back to home or the referrer page if available
    const redirectUrl = req.headers.referer || '/';
    return res.status(200).send(`
      <html>
        <head><meta http-equiv="refresh" content="1;url=${redirectUrl}"></head>
        <body style="background: #0b0f17; color: #34d399; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
          <div>
            <h2>Verification successful! Redirecting you now...</h2>
          </div>
        </body>
      </html>
    `);
  } else {
    logger.warn(`[Challenge Verification] Verification failed for IP: ${req.ip || req.connection.remoteAddress}`);
    return res.status(403).send('Verification Failed: Answer was incorrect or invalid.');
  }
}

module.exports = challengeMiddleware;
module.exports.challengeMiddleware = challengeMiddleware;
module.exports.verifyChallenge = verifyChallenge;
