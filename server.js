'use strict';
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const { encrypt, decrypt, safeEqual } = require('./src/crypto');
const { putOtp, getOtp } = require('./src/store');

const {
  PORT = 3000,
  DEVICE_API_KEY,
  EXTENSION_API_KEY,
  ENCRYPTION_KEY, // 64 hex chars (32 bytes)
  ALLOWED_ORIGIN = '', // comma-separated, e.g. chrome-extension://<id>
  OTP_TTL_SECONDS = '1800', // 30 minutes
} = process.env;

// ---- fail fast if misconfigured (never run insecurely) ----
function requireEnv(name, val) {
  if (!val) {
    console.error(`FATAL: required env var ${name} is not set`);
    process.exit(1);
  }
}
requireEnv('DEVICE_API_KEY', DEVICE_API_KEY);
requireEnv('EXTENSION_API_KEY', EXTENSION_API_KEY);
requireEnv('ENCRYPTION_KEY', ENCRYPTION_KEY);
if (!/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY)) {
  console.error('FATAL: ENCRYPTION_KEY must be 64 hex chars (32 bytes). Run: npm run genkeys');
  process.exit(1);
}
if (DEVICE_API_KEY === EXTENSION_API_KEY) {
  console.error('FATAL: DEVICE_API_KEY and EXTENSION_API_KEY must differ');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // behind Render/Firebase proxy -> correct client IPs

// ---- security middleware ----
app.use(helmet());
app.use(express.json({ limit: '4kb' })); // tiny payloads only; blocks body-flooding
app.use(
  cors({
    origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(',').map((s) => s.trim()) : false,
    methods: ['GET'],
    allowedHeaders: ['x-api-key'],
  })
);

const postLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
const getLimiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });

function auth(expectedKey) {
  return (req, res, next) => {
    if (!safeEqual(req.get('x-api-key') || '', expectedKey)) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    next();
  };
}

// ---- routes ----
app.get('/healthz', (req, res) => res.json({ ok: true }));

// Android app posts a captured OTP.
app.post('/api/otp', postLimiter, auth(DEVICE_API_KEY), (req, res) => {
  const body = req.body || {};
  const otp = body.otp;
  if (typeof otp !== 'string' || !/^\d{4,8}$/.test(otp)) {
    return res.status(400).json({ error: 'invalid otp' });
  }
  // Keep only a short sender hint; ignore the full message body on purpose.
  const sender = (typeof body.sender === 'string' ? body.sender : '').slice(0, 32);

  const ttlMs = Math.max(30, parseInt(OTP_TTL_SECONDS, 10) || 120) * 1000;
  const record = encrypt(JSON.stringify({ otp, sender, at: Date.now() }), ENCRYPTION_KEY);
  putOtp(record, ttlMs);

  // NEVER log the OTP or message body.
  console.log(`stored OTP (ttl=${ttlMs}ms)`);
  res.status(201).json({ status: 'stored' });
});

// Web extension reads the latest OTP. Stays valid for the whole TTL window
// (not deleted on read); replaced by a newer OTP or erased at expiry.
app.get('/api/otp/latest', getLimiter, auth(EXTENSION_API_KEY), (req, res) => {
  const item = getOtp();
  if (!item) return res.status(404).json({ error: 'no otp available' });
  try {
    const data = JSON.parse(decrypt(item.record, ENCRYPTION_KEY));
    const expiresInSeconds = Math.max(0, Math.round((item.expiresAt - Date.now()) / 1000));
    res.json({ otp: data.otp, sender: data.sender, at: data.at, expiresInSeconds });
  } catch (e) {
    res.status(500).json({ error: 'decrypt failed' });
  }
});

// Default: nothing else is exposed.
app.use((req, res) => res.status(404).json({ error: 'not found' }));

app.listen(PORT, () => console.log(`OTP relay listening on :${PORT}`));
