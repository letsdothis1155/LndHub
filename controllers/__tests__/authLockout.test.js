/**
 * Account lockout: after AUTH_LOCKOUT_THRESHOLD consecutive bad passwords,
 * further attempts are rejected without hitting the database — and the
 * counter resets on a successful login.
 *
 * Also asserts that error responses carry proper HTTP status codes
 * (not everything-is-200).
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

async function createUser() {
  const res = await request(app).post('/create').send({});
  return res.body;
}

async function cleanupUser(login, password) {
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  const userid = await redis.get('user_' + login + '_' + hash);
  if (userid) await redis.del('yubikey_ids_for_' + userid);
  await redis.del('auth_fail_' + login);
}

describe('account lockout after repeated failures', () => {
  let login, password;

  beforeAll(async () => {
    ({ login, password } = await createUser());
  });

  afterAll(async () => {
    await cleanupUser(login, password);
  });

  afterEach(async () => {
    await redis.del('auth_fail_' + login);
  });

  it('allows login with correct credentials', async () => {
    const res = await request(app).post('/auth').send({ login, password });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
  });

  it('returns 401 on bad credentials', async () => {
    const res = await request(app).post('/auth').send({ login, password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ error: true, code: 1 });
  });

  it('locks after 5 consecutive failures', async () => {
    for (let i = 0; i < 5; i++) {
      await request(app).post('/auth').send({ login, password: 'wrong' });
    }
    // 6th attempt — lock should be active
    const res = await request(app).post('/auth').send({ login, password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ error: true });
    // Confirm the counter is at 5
    const count = await redis.get('auth_fail_' + login);
    expect(parseInt(count, 10)).toBe(5);
  });

  it('lockout blocks even a correct password', async () => {
    for (let i = 0; i < 5; i++) {
      await request(app).post('/auth').send({ login, password: 'wrong' });
    }
    const res = await request(app).post('/auth').send({ login, password });
    expect(res.status).toBe(401);
  });

  it('successful login clears the failure counter', async () => {
    // 4 failures — not yet locked
    for (let i = 0; i < 4; i++) {
      await request(app).post('/auth').send({ login, password: 'wrong' });
    }
    const beforeCount = parseInt((await redis.get('auth_fail_' + login)) || '0', 10);
    expect(beforeCount).toBe(4);

    // correct login clears it
    const res = await request(app).post('/auth').send({ login, password });
    expect(res.status).toBe(200);

    const afterCount = parseInt((await redis.get('auth_fail_' + login)) || '0', 10);
    expect(afterCount).toBe(0);
  });
});

describe('HTTP status codes on error responses', () => {
  let login, password;

  beforeAll(async () => {
    ({ login, password } = await createUser());
  });

  afterAll(async () => {
    await cleanupUser(login, password);
  });

  it('POST /auth bad credentials → 401', async () => {
    const res = await request(app).post('/auth').send({ login, password: 'wrong' });
    expect(res.status).toBe(401);
  });

  it('POST /auth missing body → 400', async () => {
    const res = await request(app).post('/auth').send({});
    expect(res.status).toBe(400);
  });

  it('GET /balance no token → 401', async () => {
    const res = await request(app).get('/balance');
    expect(res.status).toBe(401);
  });

  it('GET /gettxs no token → 401', async () => {
    const res = await request(app).get('/gettxs');
    expect(res.status).toBe(401);
  });

  it('POST /addinvoice no token → 401', async () => {
    const res = await request(app).post('/addinvoice').send({ amt: 100 });
    expect(res.status).toBe(401);
  });
});
