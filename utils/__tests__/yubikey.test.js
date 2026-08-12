const crypto = require('crypto');

const SECRET_KEY_B64 = Buffer.from('test-secret-key-bytes').toString('base64');

jest.mock('../../config', () => ({
  yubico: { clientId: 'test-client-id', secretKey: Buffer.from('test-secret-key-bytes').toString('base64') },
}));
jest.mock('node-fetch');

const fetch = require('node-fetch');
const { verifyOtp, getPublicId } = require('../yubikey');

// mirrors the request-signing logic in utils/yubikey.js, needed here to build responses
// that pass its HMAC verification
function signParams(params, secretKeyB64) {
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('&');
  return crypto.createHmac('sha1', Buffer.from(secretKeyB64, 'base64')).update(sorted).digest('base64');
}

function mockYubicoResponse(build) {
  fetch.mockImplementation(async (url) => {
    const qs = url.split('?')[1];
    const reqParams = Object.fromEntries(new URLSearchParams(qs));
    const respParams = build(reqParams);
    const body = Object.entries(respParams)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    return { ok: true, text: async () => body };
  });
}

const VALID_OTP = 'c'.repeat(44);

describe('getPublicId', () => {
  it('strips the trailing 32-char OTP, keeping the public id prefix', () => {
    expect(getPublicId(VALID_OTP)).toBe('c'.repeat(12));
  });
});

describe('verifyOtp', () => {
  afterEach(() => jest.resetAllMocks());

  it('rejects malformed input without making a network call', async () => {
    expect(await verifyOtp('not-a-valid-otp!!')).toEqual({ valid: false, publicId: null });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects empty/missing input', async () => {
    expect(await verifyOtp('')).toEqual({ valid: false, publicId: null });
    expect(await verifyOtp(undefined)).toEqual({ valid: false, publicId: null });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('accepts a well-formed OTP that YubiCloud confirms OK, with a matching signature', async () => {
    mockYubicoResponse((req) => {
      const base = { nonce: req.nonce, otp: req.otp, status: 'OK' };
      return { ...base, h: signParams(base, SECRET_KEY_B64) };
    });

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: true, publicId: 'c'.repeat(12) });
  });

  it('rejects when YubiCloud reports a non-OK status', async () => {
    mockYubicoResponse((req) => {
      const base = { nonce: req.nonce, otp: req.otp, status: 'REPLAYED_OTP' };
      return { ...base, h: signParams(base, SECRET_KEY_B64) };
    });

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });

  it('rejects when the response signature does not match', async () => {
    mockYubicoResponse((req) => ({ nonce: req.nonce, otp: req.otp, status: 'OK', h: 'not-a-real-signature' }));

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });

  it('rejects a response with NO signature at all when a secret key is configured', async () => {
    // The dangerous case is not a bad signature but an absent one: if the check
    // is skipped whenever `h` is missing, anyone who can tamper with this
    // response simply omits it and decides the second factor themselves.
    mockYubicoResponse((req) => ({ nonce: req.nonce, otp: req.otp, status: 'OK' }));

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });

  it('rejects when the echoed otp/nonce do not match the request (anti-replay/tamper check)', async () => {
    mockYubicoResponse(() => {
      const base = { nonce: 'wrong-nonce', otp: VALID_OTP, status: 'OK' };
      return { ...base, h: signParams(base, SECRET_KEY_B64) };
    });

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });

  it('fails closed if the request to YubiCloud throws', async () => {
    fetch.mockImplementation(async () => {
      throw new Error('network down');
    });

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });

  it('fails closed on a non-ok HTTP response', async () => {
    fetch.mockImplementation(async () => ({ ok: false, text: async () => '' }));

    expect(await verifyOtp(VALID_OTP)).toEqual({ valid: false, publicId: null });
  });
});
