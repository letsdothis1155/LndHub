/**
 * Route-level tests for POST /addinvoice - the core money-in path (creating
 * a receivable invoice). Mocks LND's addInvoice with a real bolt11-encoded
 * response (matching the preimage/hash the route actually generates) so the
 * full pipeline - preimage generation, invoice decoding, Redis storage - is
 * exercised, not just the HTTP shell.
 */
jest.mock('../../lightning', () => {
  const bolt11 = require('bolt11');
  const crypto = require('crypto');
  return {
    getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true })),
    subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
    addInvoice: jest.fn((opts, cb) => {
      const preimageHex = Buffer.from(opts.r_preimage, 'base64').toString('hex');
      const paymentHash = crypto.createHash('sha256').update(Buffer.from(preimageHex, 'hex')).digest('hex');
      const encoded = bolt11.encode({
        satoshis: opts.value,
        timestamp: Math.floor(Date.now() / 1000),
        tags: [
          { tagName: 'payment_hash', data: paymentHash },
          { tagName: 'description', data: opts.memo || '' },
        ],
      });
      const signed = bolt11.sign(encoded, crypto.randomBytes(32));
      cb(null, { payment_request: signed.paymentRequest, r_hash: Buffer.from(paymentHash, 'hex'), add_index: '1' });
    }),
  };
});
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    if (typeof cb === 'function') cb(null, { result: { chain: 'main', blocks: 999999999 } });
    return Promise.resolve({ result: { chain: 'main', blocks: 999999999 } });
  }),
}));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
const crypto = require('crypto');
const Redis = require('ioredis');
const config = require('../../config');
const lightning = require('../../lightning');

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
  lightning.addInvoice.mockClear();
});

async function createAuthedUser() {
  const created = await request(app).post('/create').send({});
  const { login, password } = created.body;
  const auth = await request(app).post('/auth').send({ login, password });
  return { login, password, accessToken: auth.body.access_token };
}

async function cleanupUser(login, password, userid) {
  await redis.del('userinvoices_for_' + userid);
  await redis.del('yubikey_ids_for_' + userid);
}

describe('POST /addinvoice', () => {
  let login, password, accessToken, userid;

  beforeEach(async () => {
    ({ login, password, accessToken } = await createAuthedUser());
    userid = await redis.get('userid_for_' + accessToken);
  });

  afterEach(async () => {
    await cleanupUser(login, password, userid);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await request(app).post('/addinvoice').send({ amt: 1000 });
    expect(res.body.error).toBe(true);
    expect(lightning.addInvoice).not.toHaveBeenCalled();
  });

  it.each([[undefined], [0], [-100], ['not-a-number']])('rejects an invalid amount: %p', async (amt) => {
    const res = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt });
    expect(res.body.error).toBe(true);
    expect(lightning.addInvoice).not.toHaveBeenCalled();
  });

  it('creates an invoice for the correct amount/memo and returns pay_req for client compatibility', async () => {
    const res = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 1500, memo: 'coffee' });

    expect(lightning.addInvoice).toHaveBeenCalledTimes(1);
    const [calledOpts] = lightning.addInvoice.mock.calls[0];
    expect(calledOpts.value).toBe(1500);
    expect(calledOpts.memo).toBe('coffee');
    expect(calledOpts.expiry).toBe(3600 * 24);

    expect(res.body.payment_request).toEqual(expect.any(String));
    expect(res.body.pay_req).toBe(res.body.payment_request);
  });

  it('generates a fresh, random preimage per invoice', async () => {
    const res1 = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 100 });
    const res2 = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 100 });

    expect(res1.body.payment_request).not.toBe(res2.body.payment_request);
  });

  it('persists the invoice so it shows up in the user history', async () => {
    await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 777, memo: 'persisted' });

    const stored = await redis.lrange('userinvoices_for_' + userid, 0, -1);
    expect(stored.length).toBe(1);

    // the raw stored doc is whatever LND returned (payment_request/r_hash/add_index) -
    // memo isn't a field on it directly, it's embedded in the bolt11 payment_request
    const bolt11 = require('bolt11');
    const decoded = bolt11.decode(JSON.parse(stored[0]).payment_request);
    expect(decoded.tags.find((t) => t.tagName === 'description').data).toBe('persisted');
  });

  it('saves the preimage, retrievable by payment hash', async () => {
    const res = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 100 });

    // r_hash comes back as a JSON-serialized Buffer (`{type:'Buffer',data:[...]}`),
    // same as it would from a real LND response - decode the invoice itself instead
    const bolt11 = require('bolt11');
    const decoded = bolt11.decode(res.body.payment_request);
    const paymentHash = decoded.tags.find((t) => t.tagName === 'payment_hash').data;

    const savedPreimageHex = await redis.get('preimage_for_' + paymentHash);
    expect(savedPreimageHex).toEqual(expect.any(String));

    const rehashed = crypto.createHash('sha256').update(Buffer.from(savedPreimageHex, 'hex')).digest('hex');
    expect(rehashed).toBe(paymentHash);

    await redis.del('preimage_for_' + paymentHash);
    await redis.del('payment_hash_' + paymentHash);
  });

  it('surfaces an LND failure as errorLnd instead of a raw crash', async () => {
    lightning.addInvoice.mockImplementationOnce((opts, cb) => cb(new Error('lnd unreachable')));

    const res = await request(app).post('/addinvoice').set('Authorization', `Bearer ${accessToken}`).send({ amt: 100 });
    expect(res.body.error).toBe(true);
  });
});
