/**
 * Token expiry: asserts that access and refresh tokens stored in Redis
 * have finite TTLs and match the expected ranges (1-hour access,
 * 30-day refresh). Stolen bearer tokens should not be valid forever.
 *
 * Runs against real local Redis; LND/bitcoind are mocked (not exercised
 * by /create or /auth).
 */
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
jest.mock('../../utils/yubikey', () => ({ verifyOtp: jest.fn() }));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
const Redis = require('ioredis');
const crypto = require('crypto');
const config = require('../../config');

function buildApp() {
  const app = express();
  app.use(bodyParser.json());
  app.use(require('../api'));
  return app;
}

const app = buildApp();
const redis = new Redis(config.redis);

afterAll(() => redis.disconnect());

async function createAndLogin() {
  const createRes = await request(app).post('/create').send({});
  const { login, password } = createRes.body;
  const authRes = await request(app).post('/auth').send({ login, password });
  return { login, password, ...authRes.body };
}

async function cleanupUser(login, password) {
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  await redis.del('user_' + login + '_' + hash);
}

describe('token TTLs', () => {
  let login, password, access_token, refresh_token;

  beforeAll(async () => {
    ({ login, password, access_token, refresh_token } = await createAndLogin());
  });

  afterAll(async () => {
    await cleanupUser(login, password);
  });

  it('access token has a TTL set (not -1 / no-expiry)', async () => {
    const ttl = await redis.ttl('userid_for_' + access_token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('access token TTL is approximately 1 hour (3600s ± 5s)', async () => {
    const ttl = await redis.ttl('userid_for_' + access_token);
    expect(ttl).toBeGreaterThanOrEqual(3595);
    expect(ttl).toBeLessThanOrEqual(3600);
  });

  it('refresh token has a TTL set (not -1 / no-expiry)', async () => {
    const ttl = await redis.ttl('userid_for_' + refresh_token);
    expect(ttl).toBeGreaterThan(0);
  });

  it('refresh token TTL is approximately 30 days (2592000s ± 5s)', async () => {
    const ttl = await redis.ttl('userid_for_' + refresh_token);
    expect(ttl).toBeGreaterThanOrEqual(2591995);
    expect(ttl).toBeLessThanOrEqual(2592000);
  });

  it('access_token_for_<userid> lookup key also has a TTL', async () => {
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const userid = await redis.get('user_' + login + '_' + hash);
    const ttl = await redis.ttl('access_token_for_' + userid);
    expect(ttl).toBeGreaterThan(0);
  });

  it('refresh_token_for_<userid> lookup key also has a TTL', async () => {
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const userid = await redis.get('user_' + login + '_' + hash);
    const ttl = await redis.ttl('refresh_token_for_' + userid);
    expect(ttl).toBeGreaterThan(0);
  });

  it('token rotation on refresh also sets TTLs on the new tokens', async () => {
    const refreshRes = await request(app).post('/auth').send({ refresh_token });
    const newAccessToken = refreshRes.body.access_token;
    const newRefreshToken = refreshRes.body.refresh_token;

    expect(newAccessToken).toBeTruthy();
    expect(newRefreshToken).toBeTruthy();
    expect(newAccessToken).not.toBe(access_token);

    const accessTtl = await redis.ttl('userid_for_' + newAccessToken);
    const refreshTtl = await redis.ttl('userid_for_' + newRefreshToken);

    expect(accessTtl).toBeGreaterThan(0);
    expect(refreshTtl).toBeGreaterThan(0);
  });
});
