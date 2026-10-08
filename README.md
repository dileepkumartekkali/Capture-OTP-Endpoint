# OTP Relay Backend

A small, hardened relay that carries a captured MCA OTP from the Android app to
the web extension. It is **not** a public capture site — it requires secrets on
both ends.

> Honest note: no server is unhackable. This follows current best practices to
> make it hard to abuse. It is not a guarantee.

## Flow

```
Android app  --POST /api/otp (x-api-key: DEVICE_API_KEY)-->  relay
                                                             | encrypt (AES-256-GCM)
                                                             | store in memory, single-use, TTL
web extension --GET /api/otp/latest (x-api-key: EXTENSION_API_KEY)--> relay
                                                             | decrypt, return latest (valid 30 min)
```

## Security properties

- **TLS** — provided by Render/Firebase (HTTPS only). The Android app also
  refuses plaintext HTTP.
- **Two separate secrets** — the device and the extension use different API
  keys, checked in **constant time** (no timing side-channel).
- **Encrypted at rest** — the OTP is stored with AES-256-GCM (authenticated
  encryption; tampering is detected).
- **Latest-only, 30-min window** — a new OTP immediately replaces the old one;
  it stays valid until replaced or until its 30-minute TTL expires, then it's
  erased. It is readable more than once within the window (MCA invalidates the
  code once it's actually used).
- **Auto-expiry** — the OTP is dropped after `OTP_TTL_SECONDS` (default 1800).
- **In memory only** — nothing is written to disk.
- **No sensitive logging** — the OTP and message body are never logged.
- **Rate limited**, small body limit, `helmet` headers, CORS locked to the
  extension origin, minimal surface (only 3 routes).

## Setup

1. Install Node 18+.
2. `npm install`
3. Generate secrets: `npm run genkeys` — copy the three lines.
4. Copy `.env.example` to `.env` and paste the secrets; set `ALLOWED_ORIGIN`
   to your extension's origin.
5. `npm start`, then test:
   ```
   curl -X POST http://localhost:3000/api/otp \
     -H "x-api-key: <DEVICE_API_KEY>" -H "content-type: application/json" \
     -d '{"otp":"1234","sender":"AD-GOVMCA-S"}'

   curl http://localhost:3000/api/otp/latest -H "x-api-key: <EXTENSION_API_KEY>"
   ```

## Deploy to Render

1. Push this folder to a Git repo.
2. Render ▸ New ▸ Blueprint, point it at the repo (`render.yaml` is picked up).
3. In the service's **Environment**, set `ENCRYPTION_KEY`, `DEVICE_API_KEY`,
   `EXTENSION_API_KEY`, `ALLOWED_ORIGIN` (the `genkeys` values). Never commit them.
4. Deploy. Your base URL is `https://<service>.onrender.com`.

## Wire up the Android app

In the app's `Config.kt`, set:
```
API_URL = "https://<service>.onrender.com/api/otp"
```
and add the `x-api-key: <DEVICE_API_KEY>` header in `OtpSender` (ask and this
can be added). The app must send over HTTPS (it already enforces that).

## Firebase alternative

Deployable as a Cloud Function instead: wrap the Express `app` with
`functions.https.onRequest(app)` and store secrets via
`firebase functions:secrets`. Use Firestore with a TTL field (or Realtime DB)
in place of `src/store.js` if you want cross-instance storage.

## Known limitations (honest)

- **In-memory store** resets on redeploy and is per-instance. On Render's free
  plan (single instance) that's fine; if you scale to multiple instances,
  move to **Redis** with a TTL, or the OTP posted to one instance won't be
  visible to another.
- Free hosting tiers **sleep** when idle; the first request after idle is slow.
- The strongest possible design is **end-to-end encryption** (the phone
  encrypts the OTP with the extension's public key; the relay only passes
  ciphertext and never sees the OTP). That's a larger change — see below.

## Optional: end-to-end encryption (strongest)

If you want the relay to be *zero-knowledge* (it never sees the OTP in
plaintext), the extension generates a keypair, the Android app encrypts the OTP
with the extension's public key, and the relay stores/forwards only ciphertext.
This resists even a fully compromised server. Ask and I can design this variant.
