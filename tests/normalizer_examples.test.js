const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

function loadEngines() {
  const context = { window: {}, console, URL };
  vm.createContext(context);
  const files = [
    'extension/feature_engine.js',
    'extension/risk_engine.js',
    'extension/body_normalizer.js'
  ];
  for (const file of files) {
    vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
  }
  return context.window;
}

function runCase(email) {
  const w = loadEngines();
  const features = w.FeatureEngine.buildSanitizedFeatures(email);
  const risk = w.RiskEngine.scoreRisk(features);
  return w.EmailNormalizer.buildAiContext(email, features, risk);
}

(function testHerokuOnboarding() {
  const payload = runCase({
    sender: 'notifications@heroku.com',
    subject: 'Confirm your Heroku account',
    body: 'Hi Alex, welcome to Heroku. Please confirm your email within 30 days to activate your account.',
    links: [{ href: 'https://dashboard.heroku.com/verify?token=abc123xyz987', text: 'Confirm account' }]
  });

  assert(payload.normalized_body.includes('[TIME_WINDOW: 30 days]'));
  assert(!payload.normalized_body.includes('Alex'));
  assert.strictEqual(payload.sender_domain, 'heroku.com');
})();

(function testLegitPasswordReset() {
  const payload = runCase({
    sender: 'security@github.com',
    subject: 'Reset your password',
    body: 'Hello Sam, we received a password reset request. If this was you, reset your password within 24 hours.',
    links: [{ href: 'https://github.com/password_reset?token=abc123456789tokenvalue', text: 'https://github.com/password_reset' }]
  });

  assert(payload.normalized_body.includes('[TIME_WINDOW: 24 hours]'));
  assert(payload.links[0].actual_domain === 'github.com');
})();

(function testPhishingBrandImpersonationMismatch() {
  const payload = runCase({
    sender: 'alert@microsoft-support-mail.com',
    subject: 'Microsoft account suspended',
    body: 'Immediate action required. Verify your Microsoft account immediately to avoid suspension.',
    links: [{ href: 'https://login-check-secure.net/verify?session=8899', text: 'https://microsoft.com/security' }]
  });

  assert(payload.normalized_body.includes('[TIME_WINDOW: immediate]'));
  assert(payload.links[0].visible_domain === 'microsoft.com');
  assert(payload.links[0].actual_domain === 'login-check-secure.net');
})();

(function testPhishingIpLink() {
  const payload = runCase({
    sender: 'admin@company-mail.com',
    subject: 'Security check',
    body: 'Your account will be disabled. Login now.',
    links: [{ href: 'http://185.10.10.3/login?user=bob@example.com', text: 'Login now' }]
  });

  assert(payload.links[0].actual_domain === '185.10.10.3');
  assert(payload.normalized_body.includes('[LINK_TO_DOMAIN: 185.10.10.3]'));
})();

console.log('normalizer example tests passed');
