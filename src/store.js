'use strict';

// Holds only the LATEST OTP, encrypted, in memory.
//
// Lifecycle (as specified):
//  - A new OTP REPLACES the previous one immediately (only the latest lives).
//  - It stays available until it is replaced OR its TTL (30 min) expires.
//  - Reading does NOT delete it — it remains valid for the whole window.
//  - In memory only: nothing is written to disk; cleared on restart.
//
// Trade-off vs. single-use: because the same OTP can be fetched more than once
// within the window, this relies on MCA invalidating the OTP once it's used.
let current = null; // { record, expiresAt }

function putOtp(record, ttlMs) {
  current = { record, expiresAt: Date.now() + ttlMs };
}

/** Peek the current OTP without consuming it. Returns {record, expiresAt} or null. */
function getOtp() {
  if (!current) return null;
  if (Date.now() > current.expiresAt) {
    current = null; // expired -> erase
    return null;
  }
  return current;
}

function clearOtp() {
  current = null;
}

// Best-effort sweep so an unread OTP is erased promptly at expiry.
setInterval(() => {
  if (current && Date.now() > current.expiresAt) current = null;
}, 30_000).unref();

module.exports = { putOtp, getOtp, clearOtp };
