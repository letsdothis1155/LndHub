/**
 * What /payinvoice does when the sendPayment gRPC stream fails.
 *
 * The handler only ever registered a 'data' listener. An 'error' event with no
 * listener throws rather than being handled, so the HTTP request never answered
 * at all: the caller could not tell whether their payment had gone out, and the
 * per-user lock stayed held for its full five minutes so they could not retry.
 *
 * The contract pinned here is deliberately asymmetric - release the lock, but
 * leave the funds locked. A stream error means the payment's outcome is
 * unknown; it may still be in flight, and scripts/process-locked-payments.js is
 * what reconciles it. Unlocking funds on an unknown outcome is how you spend
 * them twice.
 */
const { EventEmitter } = require('events');

const mockCall = new EventEmitter();
mockCall.write = jest.fn(() => {
  setImmediate(() => mockCall.emit('error', new Error('lnd went away mid-payment')));
});

jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true, identity_pubkey: 'our-own-node' })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
  decodePayReq: jest.fn((opts, cb) =>
    cb(null, {
      num_satoshis: '1000',
      // anything other than our own identity_pubkey takes the external path
      destination: 'some-other-node',
      payment_hash: 'a'.repeat(64),
      description: 'test payment',
    }),
  ),
  sendPayment: jest.fn(() => mockCall),
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
const { User } = require('../../class/');

const app = express();
app.use(bodyParser.json());
app.use(require('../api'));
const redis = new Redis(config.redis);

afterAll(() => redis.disconnect());

describe('POST /payinvoice when the sendPayment stream errors', () => {
  let login, password, accessToken, userid, response;

  beforeAll(async () => {
    // real balance accounting needs decodable BOLT11 in redis; the balance
    // itself is not what is under test here
    jest.spyOn(User.prototype, 'getCalculatedBalance').mockResolvedValue(500000);

    ({ login, password } = (await request(app).post('/create').send({})).body);
    accessToken = (await request(app).post('/auth').send({ login, password })).body.access_token;
    userid = await redis.get('userid_for_' + accessToken);

    response = await request(app)
      .post('/payinvoice')
      .set('Authorization', 'Bearer ' + accessToken)
      .send({ invoice: 'lnbc-test-invoice' });
  }, 20000);

  afterAll(async () => {
    await redis.del('user_' + login + '_' + crypto.createHash('sha256').update(password).digest('hex'));
    await redis.del('locked_payments_for_' + userid);
    await redis.del('invoice_paying_for_' + userid);
  });

  it('answers the request instead of hanging until the client times out', () => {
    expect(response.status).toBe(503);
    expect(response.body).toEqual(expect.objectContaining({ error: true, code: 7 }));
  });

  it('releases the per-user payment lock, so the caller can retry', async () => {
    expect(await redis.get('invoice_paying_for_' + userid)).toBeNull();
  });

  it('leaves the funds locked for the reconciler, since the outcome is unknown', async () => {
    const u = new User(redis, null, null);
    u._userid = userid;
    const locked = await u.getLockedPayments();

    expect(locked).toHaveLength(1);
    expect(locked[0]).toEqual(expect.objectContaining({ pay_req: 'lnbc-test-invoice', amount: 1000 }));
  });
});
