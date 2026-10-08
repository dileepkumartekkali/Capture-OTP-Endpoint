'use strict';
const crypto = require('crypto');

// AES-256-GCM: authenticated encryption. GCM gives confidentiality AND
// integrity (the auth tag detects tampering), so a modified ciphertext is
// rejected on decrypt rather than silently returning garbage.
const ALGO = 'aes-256-gcm';

/**
 * @param {string} plaintext
 * @param {string} keyHex 64 hex chars (32 bytes)
 * @returns {{iv:string, tag:string, ct:string}} base64 parts
 */
function encrypt(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12); // 96-bit nonce, fresh per message
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ct.toString('base64'),
  };
}

/**
 * @param {{iv:string, tag:string, ct:string}} record
 * @param {string} keyHex
 * @returns {string} plaintext (throws if tampered / wrong key)
 */
function decrypt(record, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(record.iv, 'base64');
  const tag = Buffer.from(record.tag, 'base64');
  const ct = Buffer.from(record.ct, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Constant-time string compare — avoids auth-token timing attacks. */
function safeEqual(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { encrypt, decrypt, safeEqual };
