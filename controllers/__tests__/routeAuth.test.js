/**
 * Guards against unauthenticated access to LND node information.
 *
 * /queryroutes and /getchaninfo originally shipped with no auth check at
 * all (unlike every sibling route), exposing live routing and channel-graph
 * queries against the operator's node to anyone who could reach the port.
 * These assert every node-info route rejects an anonymous caller.
 */
jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
  queryRoutes: jest.fn((req, cb) => cb(null, { routes: [{ total_amt: 1000 }] })),
  decodePayReq: jest.fn((opts, cb) => cb(null, { num_satoshis: '1000', destination: 'somepubkey' })),
}));
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    if (typeof cb === 'function') cb(null, { result: { chain: 'main', blocks: 999999999 } });
    return Promise.resolve({ result: { chain: 'main', blocks: 999999999 } });
  }),
}));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
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
  lightning.queryRoutes.mockClear();
});

async function authedToken() {
  const created = await request(app).post('/create').send({});
  const auth = await request(app).post('/auth').send({ login: created.body.login, password: created.body.password });
  return auth.body.access_token;
}

const NODE_INFO_ROUTES = [
  ['/queryroutes/sourcepubkey/destpubkey/1000'],
  ['/getchaninfo/12345'],
  ['/getinfo'],
  ['/checkrouteinvoice?invoice=lnbc1example'],
];

describe('node-info routes require authentication', () => {
  it.each(NODE_INFO_ROUTES)('rejects an anonymous request to %s', async (route) => {
    const res = await request(app).get(route);
    expect(res.body.error).toBe(true);
    expect(res.body.code).toBe(1); // errorBadAuth
  });

  it.each(NODE_INFO_ROUTES)('rejects a bogus bearer token on %s', async (route) => {
    const res = await request(app).get(route).set('Authorization', 'Bearer not-a-real-token');
    expect(res.body.error).toBe(true);
    expect(res.body.code).toBe(1);
  });

  it('does not reach LND at all when /queryroutes is unauthenticated', async () => {
    await request(app).get('/queryroutes/sourcepubkey/destpubkey/1000');
    expect(lightning.queryRoutes).not.toHaveBeenCalled();
  });

  it('still serves /queryroutes to an authenticated caller', async () => {
    const token = await authedToken();
    const res = await request(app).get('/queryroutes/sourcepubkey/destpubkey/1000').set('Authorization', `Bearer ${token}`);

    expect(res.body.error).toBeUndefined();
    expect(lightning.queryRoutes).toHaveBeenCalledTimes(1);
  });

  it('still serves /getchaninfo to an authenticated caller', async () => {
    const token = await authedToken();
    const res = await request(app).get('/getchaninfo/12345').set('Authorization', `Bearer ${token}`);

    // empty body is the documented "no such channel in the cached graph" response;
    // what matters is that it is not an auth rejection
    expect(res.body.error).toBeUndefined();
  });
});
