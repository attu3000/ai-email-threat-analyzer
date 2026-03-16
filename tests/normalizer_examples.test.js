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

function analyzeEmail(email) {
  const w = loadEngines();
  const features = w.FeatureEngine.buildSanitizedFeatures(email);
  const risk = w.RiskEngine.scoreRisk(features);
  const payload = w.EmailNormalizer.buildAiContext(email, features, risk);
  return { features, risk, payload };
}

(function testLegitimateHerokuAccountConfirmation() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'notifications@heroku.com',
    subject: 'Confirm your Heroku account',
    body: 'Hi Alex, welcome to Heroku. Please confirm your email within 30 days to activate your account.',
    links: [{ href: 'https://dashboard.heroku.com/verify?token=abc123xyz987', text: 'Confirm account' }]
  });

  assert.strictEqual(payload.sender_domain, 'heroku.com');
  assert(payload.normalized_body.includes('[TIME_WINDOW: 30 days]'));
  assert(!payload.normalized_body.includes('Alex'));
  assert.strictEqual(features.sender_link_match, 'match');
  assert.strictEqual(risk.classification, 'safe');
  assert(risk.risk_score <= 15);
})();

(function testLegitimatePasswordReset() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'security@github.com',
    subject: 'Reset your password',
    body: 'Hello Sam, we received a password reset request. If this was you, reset your password within 24 hours.',
    links: [{ href: 'https://github.com/password_reset?token=abc123456789tokenvalue', text: 'https://github.com/password_reset' }]
  });

  assert(payload.normalized_body.includes('[TIME_WINDOW: 24 hours]'));
  assert.strictEqual(payload.links[0].actual_domain, 'github.com');
  assert.strictEqual(features.sender_link_match, 'match');
  assert.strictEqual(risk.classification, 'safe');
})();

(function testStorageDeletionScam() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'storage-alert@googlemail-secure-notify.com',
    subject: 'Your storage will be deleted',
    body: 'FINAL NOTICE: your cloud storage data will be permanently deleted by 09/20/2026. Verify account now to keep files.',
    links: [{ href: 'https://drive-storage-recovery.top/recover?session=abc', text: 'Restore storage immediately' }]
  });

  assert(payload.normalized_body.includes('FINAL NOTICE'));
  assert(payload.normalized_body.includes('[DATE]'));
  assert.strictEqual(features.suspicious_tld_present, true);
  assert(risk.risk_score >= 30);
})();

(function testBrandImpersonationMismatchedLinkDomain() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'alert@microsoft.com',
    subject: 'Microsoft account security check',
    body: 'Immediate action required. Verify your Microsoft account immediately to avoid suspension.',
    links: [{ href: 'https://login-check-secure.net/verify?session=8899', text: 'https://microsoft.com/security' }]
  });

  assert.strictEqual(payload.links[0].visible_domain, 'microsoft.com');
  assert.strictEqual(payload.links[0].actual_domain, 'login-check-secure.net');
  assert.strictEqual(features.visible_actual_mismatch, true);
  assert.strictEqual(features.sender_link_match, 'mismatch');
  assert.strictEqual(risk.classification, 'phishing');
})();

(function testHostedContentPhishingPage() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'security@bank-example.com',
    subject: 'Security alert',
    body: 'Review this document to secure your account today.',
    links: [{ href: 'https://secure-review-docs.github.io/account-check', text: 'Review account document' }]
  });

  assert.strictEqual(payload.links[0].is_hosted_content_platform, true);
  assert.strictEqual(features.hosted_content_domain_present, true);
  assert.strictEqual(features.sender_link_match, 'mismatch');
  assert(risk.risk_score >= 20);
})();

(function testIpLinkPhishing() {
  const { features, risk, payload } = analyzeEmail({
    sender: 'admin@company-mail.com',
    subject: 'Security check',
    body: 'Your account will be disabled. Login now.',
    links: [{ href: 'http://185.10.10.3/login?user=bob@example.com', text: 'Login now' }]
  });

  assert.strictEqual(payload.links[0].actual_domain, '185.10.10.3');
  assert(payload.normalized_body.includes('[LINK_TO_DOMAIN: 185.10.10.3]'));
  assert.strictEqual(features.ip_link_present, true);
  assert.strictEqual(risk.classification, 'phishing');
})();

console.log('normalizer and structural-risk tests passed');
