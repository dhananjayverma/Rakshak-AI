const { logger } = require('../core/logger');

/**
 * Adaptive CAPTCHA/Challenge serving middleware
 */
function challengeMiddleware(options = {}) {
  const thresholdMin = options.thresholdMin || 50;
  const thresholdMax = options.thresholdMax || 74;

  return (req, res, threatScore) => {
    // Only serve challenge if threat score is within the MEDIUM warning band (50 - 74)
    if (threatScore >= thresholdMin && threatScore <= thresholdMax) {
      logger.warn(`[Req ID: ${req.id}] Serving Adaptive Challenge response for threat score: ${threatScore}`);
      req.webShieldState.blocked = true;

      res.setHeader('Content-Type', 'text/html');
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
            
            <div class="math-challenge">What is 7 + 8?</div>

            <form method="POST" action="/webshield/challenge-verify">
              <input type="text" name="answer" placeholder="Enter your answer" required autocomplete="off">
              <button type="submit">Verify & Proceed</button>
            </form>
          </div>
        </body>
        </html>
      `);
    }
  };
}

module.exports = challengeMiddleware;
