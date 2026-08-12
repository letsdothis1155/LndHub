/**
 * Route-level tests for /create, /auth, and /yubikey/* - the actual HTTP
 * wiring, not just the underlying utils/User methods (covered separately).
 * Runs against real local Redis (throwaway users, cleaned up after each
 * test); lightning/bitcoin are mocked since these routes never touch LND
 * or bitcoind and those modules do real file/network I/O at require time.
 */
// controllers/api.js makes live smoke-test calls (bitcoind getblockchaininfo,
// LND getInfo, an invoice subscription stream) unconditionally at require
// time - these stubs just need to satisfy that startup code without hanging
// or throwing; none of it is exercised by the routes under test here.
jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true, identity_pubkey: 'mock-pubkey' })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
}));
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    const result = { result: { chain: 'main', blocks: 999999999 } };
    if (typeof cb === 'function') cb(null, result);
    return Promise.resolve(result);
  }),
}));
jest.mock('../../utils/yubikey', () => ({
  verifyOtp: jest.fn(),
}));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
const Redis = require('ioredis');
const config = require('../../config');
const yubikey = require('../../utils/yubikey');

function buildApp() {
  const app = express();
  app.use(bodyParser.json());
  app.use(require('../api'));
  return app;
}

const app = buildApp();
const redis = new Redis(config.redis);

afterAll(() => {
  redis.disconnect();
});

afterEach(() => {
  yubikey.verifyOtp.mockReset();
});

async function createUser() {
  const res = await request(app).post('/create').send({});
  return res.body; // { login, password }
}

async function cleanupUser(login, password) {
  const userid = await redis.get('user_' + login + '_' + require('crypto').createHash('sha256').update(password).digest('hex'));
  if (userid) await redis.del('yubikey_ids_for_' + userid);
}

describe('POST /create', () => {
  it('creates an account with a login and password', async () => {
    const res = await request(app).post('/create').send({});
    expect(res.body.login).toEqual(expect.any(String));
    expect(res.body.password).toEqual(expect.any(String));
    await cleanupUser(res.body.login, res.body.password);
  });
});

describe('POST /auth (password only, no YubiKey enrolled)', () => {
  let login, password;

  beforeEach(async () => {
    ({ login, password } = await createUser());
  });

  afterEach(async () => {
    await cleanupUser(login, password);
  });

  it('succeeds with the correct password and never touches YubiCloud', async () => {
    const res = await request(app).post('/auth').send({ login, password });
    expect(res.body.access_token).toEqual(expect.any(String));
    expect(res.body.refresh_token).toEqual(expect.any(String));
    expect(yubikey.verifyOtp).not.toHaveBeenCalled();
  });

  it('rejects a wrong password without calling YubiCloud', async () => {
    const res = await request(app).post('/auth').send({ login, password: 'wrong-password' });
    expect(res.body.error).toBe(true);
    expect(res.body.access_token).toBeUndefined();
    expect(yubikey.verifyOtp).not.toHaveBeenCalled();
  });

  it('refreshes via refresh_token without needing an OTP', async () => {
    const first = await request(app).post('/auth').send({ login, password });
    const res = await request(app).post('/auth').send({ refresh_token: first.body.refresh_token });
    expect(res.body.access_token).toEqual(expect.any(String));
  });
});

describe('YubiKey enrollment and OTP-gated login', () => {
  let login, password, accessToken;

  beforeEach(async () => {
    ({ login, password } = await createUser());
    const auth = await request(app).post('/auth').send({ login, password });
    accessToken = auth.body.access_token;
  });

  afterEach(async () => {
    await cleanupUser(login, password);
  });

  it('rejects enrollment with an invalid OTP', async () => {
    yubikey.verifyOtp.mockResolvedValue({ valid: false, publicId: null });
    const res = await request(app).post('/yubikey/enroll').set('Authorization', `Bearer ${accessToken}`).send({ yubikey_otp: 'garbage' });
    expect(res.body.error).toBe(true);
  });

  it('rejects enrollment without an access token', async () => {
    yubikey.verifyOtp.mockResolvedValue({ valid: true, publicId: 'ccccccexample' });
    const res = await request(app).post('/yubikey/enroll').send({ yubikey_otp: 'anything' });
    expect(res.body.error).toBe(true);
  });

  it('enrolls a key, then requires it on future logins', async () => {
    yubikey.verifyOtp.mockResolvedValue({ valid: true, publicId: 'ccccccexample' });

    const enroll = await request(app)
      .post('/yubikey/enroll')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ yubikey_otp: 'ccccccexampledeadbeefdeadbeefdeadbeefaa' });
    expect(enroll.body.publicId).toBe('ccccccexample');

    // password alone is no longer enough
    const passwordOnly = await request(app).post('/auth').send({ login, password });
    expect(passwordOnly.body.error).toBe(true);
    expect(passwordOnly.body.access_token).toBeUndefined();

    // wrong/absent OTP is rejected too, even though a key is enrolled
    yubikey.verifyOtp.mockResolvedValue({ valid: false, publicId: null });
    const badOtp = await request(app).post('/auth').send({ login, password, yubikey_otp: 'wrong' });
    expect(badOtp.body.error).toBe(true);

    // an OTP from a *different, unenrolled* key is rejected
    yubikey.verifyOtp.mockResolvedValue({ valid: true, publicId: 'ccccccnotenrolled' });
    const wrongKey = await request(app).post('/auth').send({ login, password, yubikey_otp: 'someone-elses-otp' });
    expect(wrongKey.body.error).toBe(true);

    // the enrolled key's OTP succeeds
    yubikey.verifyOtp.mockResolvedValue({ valid: true, publicId: 'ccccccexample' });
    const goodOtp = await request(app).post('/auth').send({ login, password, yubikey_otp: 'ccccccexampledeadbeefdeadbeefdeadbeefaa' });
    expect(goodOtp.body.access_token).toEqual(expect.any(String));
  });

  it('lists and removes enrolled keys, restoring password-only login', async () => {
    yubikey.verifyOtp.mockResolvedValue({ valid: true, publicId: 'ccccccexample' });
    await request(app).post('/yubikey/enroll').set('Authorization', `Bearer ${accessToken}`).send({ yubikey_otp: 'x' });

    const list = await request(app).get('/yubikey').set('Authorization', `Bearer ${accessToken}`);
    expect(list.body.publicIds).toEqual(['ccccccexample']);

    await request(app).post('/yubikey/remove').set('Authorization', `Bearer ${accessToken}`).send({ publicId: 'ccccccexample' });

    const listAfter = await request(app).get('/yubikey').set('Authorization', `Bearer ${accessToken}`);
    expect(listAfter.body.publicIds).toEqual([]);

    // back to password-only
    const res = await request(app).post('/auth').send({ login, password });
    expect(res.body.access_token).toEqual(expect.any(String));
  });
});
