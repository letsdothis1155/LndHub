/**
 * Verifies YubiKey OTPs (the 44-char one-time password a YubiKey types out on button press)
 * against Yubico's cloud validation service (YubiCloud), protocol 2.0.
 * https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
 */
const crypto = require('crypto');
const fetch = require('node-fetch');
const config = require('../config');

const VERIFY_URL = 'https://api.yubico.com/wsapi/2.0/verify';
const OTP_RE = /^[cbdefghijklnrtuv]{32,48}$/;

function getPublicId(otp) {
  return otp.slice(0, otp.length - 32);
}

function sign(params, secretKeyB64) {
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('&');
  return crypto.createHmac('sha1', Buffer.from(secretKeyB64, 'base64')).update(sorted).digest('base64');
}

function parseResponse(body) {
  const out = {};
  for (const line of body.split('\n')) {
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

/**
 * @param {string} otp raw OTP string as typed by the YubiKey
 * @returns {Promise<{valid: boolean, publicId: (string|null)}>}
 */
async function verifyOtp(otp) {
  if (typeof otp !== 'string' || !OTP_RE.test(otp)) return { valid: false, publicId: null };
  if (!config.yubico || !config.yubico.clientId) return { valid: false, publicId: null };

  const publicId = getPublicId(otp);
  const nonce = crypto.randomBytes(16).toString('hex');
  const params = { id: config.yubico.clientId, otp, nonce, timestamp: '1' };

  if (config.yubico.secretKey) {
    params.h = sign(params, config.yubico.secretKey);
  }

  const qs = Object.keys(params)
    .sort()
    .map((k) => `${k}=${encodeURIComponent(params[k])}`)
    .join('&');

  let response;
  try {
    response = await fetch(`${VERIFY_URL}?${qs}`, { timeout: 10000 });
  } catch (e) {
    return { valid: false, publicId: null };
  }
  if (!response.ok) return { valid: false, publicId: null };

  const body = parseResponse(await response.text());

  if (body.otp !== otp || body.nonce !== nonce) return { valid: false, publicId: null };

  // If a secret key is configured, a signature is REQUIRED - not merely checked
  // when one happens to be present. Treating a missing `h` as "nothing to
  // verify" means anyone who can tamper with this response just omits it and
  // the second factor is decided by whatever they send back.
  if (config.yubico.secretKey) {
    if (!body.h) return { valid: false, publicId: null };
    const { h, ...rest } = body;
    const expected = Buffer.from(sign(rest, config.yubico.secretKey));
    const received = Buffer.from(h);
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      return { valid: false, publicId: null };
    }
  }

  if (body.status !== 'OK') return { valid: false, publicId: null };

  return { valid: true, publicId };
}

module.exports = { verifyOtp, getPublicId };
