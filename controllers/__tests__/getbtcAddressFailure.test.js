/**
 * /getbtc is a money-in path: it hands the wallet the address a user deposits
 * to. Two failure shapes are pinned here.
 *
 * generateAddress() rejects when LND cannot produce an address, and Express 4
 * does not catch a rejection from an async handler - so the request was simply
 * never answered. It also held a five-minute lock that it never released on
 * failure, and a retry inside that window found the lock taken, returned early,
 * and produced `200 [{"address": null}]` - a success response carrying a blank
 * deposit address, with nothing to tell the client anything had gone wrong.
 */
const mockNewAddress = jest.fn();

jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true, identity_pubkey: 'our-own-node' })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
  newAddress: (opts, cb) => mockNewAddress(opts, cb),
}));
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    const r = { result: { chain: 'main', blocks: 999999999 } };
    if (typeof cb === 'function') cb(null, r);
    return Promise.resolve(r);
  }),
}));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
const Redis = require('ioredis');
const crypto = require('crypto');
const config = require('../../config');

const app = express();
app.use(bodyParser.json());
app.use(require('../api'));
const redis = new Redis(config.redis);

afterAll(() => redis.disconnect());

async function newAuthedUser() {
  const { login, password } = (await request(app).post('/create').send({})).body;
  const { access_token } = (await request(app).post('/auth').send({ login, password })).body;
  const userid = await redis.get('userid_for_' + access_token);
  return { login, password, access_token, userid };
}

async function cleanup({ login, password, userid }) {
  await redis.del('user_' + login + '_' + crypto.createHash('sha256').update(password).digest('hex'));
  await redis.del('generating_address_' + userid);
  await redis.del('bitcoin_address_for_' + userid);
}

const getbtc = (token) =>
  request(app)
    .get('/getbtc')
    .set('Authorization', 'Bearer ' + token);

describe('GET /getbtc when LND cannot generate an address', () => {
  let user;

  beforeAll(async () => {
    mockNewAddress.mockImplementation((opts, cb) => cb(new Error('lnd cannot make an address right now')));
    user = await newAuthedUser();
  }, 20000);

  afterAll(() => cleanup(user));

  it('answers with an error instead of hanging until the client times out', async () => {
    const res = await getbtc(user.access_token);

    expect(res.status).toBe(503);
    expect(res.body).toEqual(expect.objectContaining({ error: true, code: 7 }));
  });

  it('releases the address-generation lock, so a retry is not blocked for five minutes', async () => {
    expect(await redis.get('generating_address_' + user.userid)).toBeNull();
  });

  it('never answers 200 with a null address', async () => {
    const res = await getbtc(user.access_token);

    expect(res.status).toBe(503);
    expect(res.body).not.toEqual([{ address: null }]);
    expect(res.body.address).toBeUndefined();
  });
});

describe('GET /getbtc when LND is healthy', () => {
  let user;

  beforeAll(async () => {
    mockNewAddress.mockImplementation((opts, cb) => cb(null, { address: 'bc1qtestaddressfortesting' }));
    user = await newAuthedUser();
  }, 20000);

  afterAll(() => cleanup(user));

  it('still returns the generated address', async () => {
    const res = await getbtc(user.access_token);

    expect(res.status).toBe(200);
    expect(res.body).toEqual([{ address: 'bc1qtestaddressfortesting' }]);
  });
});
