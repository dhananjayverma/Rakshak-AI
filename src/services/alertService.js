const nodemailer = require('nodemailer');
const { logger } = require('../core/logger');

let mailTransporter = null;
let alertsConfig = null;

function initAlerts(config) {
  alertsConfig = config.alerts;

  // Init Nodemailer if configured
  if (alertsConfig.email && alertsConfig.email.enabled) {
    try {
      if (alertsConfig.email.transport) {
        mailTransporter = nodemailer.createTransport(alertsConfig.email.transport);
      } else {
        logger.warn('Nodemailer alert enabled, but transport config is missing.');
      }
    } catch (err) {
      logger.error(`Failed to init Nodemailer: ${err.message}`);
    }
  }
}

async function sendAlert(subject, data) {
  if (!alertsConfig) return;

  const messageText = `WebShield Threat Event:\n\n${JSON.stringify(data, null, 2)}`;

  // Send Email Alert
  if (alertsConfig.email && alertsConfig.email.enabled && mailTransporter) {
    try {
      await mailTransporter.sendMail({
        from: alertsConfig.email.from,
        to: alertsConfig.email.to,
        subject: `[WebShield ALERT] ${subject}`,
        text: messageText
      });
      logger.info('WebShield email alert sent successfully.');
    } catch (err) {
      logger.error(`Failed to send email alert: ${err.message}`);
    }
  }

  // Send Webhook Alert (supporting rich Slack and Discord integrations)
  if (alertsConfig.webhook && alertsConfig.webhook.enabled && alertsConfig.webhook.url) {
    try {
      const axios = require('axios');
      const url = alertsConfig.webhook.url;
      let payload = {
        event: 'security_alert',
        subject,
        timestamp: new Date().toISOString(),
        data
      };

      // Slack Rich Formatting
      if (url.includes('hooks.slack.com')) {
        payload = {
          text: `🚨 *WebShield Alert: ${subject}*\n\`\`\`${JSON.stringify(data, null, 2)}\`\`\``
        };
      }
      // Discord Rich Formatting
      else if (url.includes('discord.com/api/webhooks')) {
        payload = {
          content: `⚠️ **WebShield Security Threat Triggered**`,
          embeds: [{
            title: subject,
            color: 15158332, // Red color
            description: `\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``,
            timestamp: new Date().toISOString()
          }]
        };
      }

      await axios.post(url, payload);
      logger.info('WebShield Webhook alert sent successfully.');
    } catch (err) {
      logger.error(`Failed to send Webhook alert: ${err.message}`);
    }
  }
}

module.exports = {
  initAlerts,
  sendAlert
};
