'use strict';
// Generates the three secrets you need. Copy the output into your env vars.
const crypto = require('crypto');

console.log('ENCRYPTION_KEY=' + crypto.randomBytes(32).toString('hex'));
console.log('DEVICE_API_KEY=' + crypto.randomBytes(32).toString('base64url'));
console.log('EXTENSION_API_KEY=' + crypto.randomBytes(32).toString('base64url'));
