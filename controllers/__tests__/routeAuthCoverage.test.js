/**
 * Exhaustive auth coverage: enumerates every route the router actually
 * registers and asserts each one rejects unauthenticated callers.
 *
 * This exists because /queryroutes and /getchaninfo shipped with no auth
 * check at all and went unnoticed - a hand-written list of routes to test
 * would have had the same blind spot as the code it was testing. Deriving
 * the list from the router means a newly added route is covered the moment
 * it exists, and a route added without auth fails this test.
 *
 * Routes that are public by design must be named in PUBLIC_ROUTES below,
 * so making something public is always a deliberate, reviewable edit.
 */
jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true, identity_pubkey: 'mock' })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
  // if auth ever regresses, these let the request proceed far enough to
  // return a success payload, which is what makes the assertion meaningful
  queryRoutes: jest.fn((req, cb) => cb(null, { routes: ['leaked-route-data'] })),
  decodePayReq: jest.fn((opts, cb) => cb(null, { num_satoshis: '1' })),
  addInvoice: jest.fn((opts, cb) => cb(null, { payment_request: 'lnbc-mock' })),
  sendPayment: jest.fn(() => ({ on: jest.fn(), write: jest.fn() })),
}));
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    const result = { result: { chain: 'main', blocks: 999999999 } };
    if (typeof cb === 'function') cb(null, result);
    return Promise.resolve(result);
  }),
}));

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');

const router = require('../api');

// Public by design: account creation and the login endpoint itself.
const PUBLIC_ROUTES = [
  { method: 'post', path: '/create' },
  { method: 'post', path: '/auth' },
];

function buildApp() {
  const app = express();
  app.use(bodyParser.json());
  app.use(router);
  return app;
}

const app = buildApp();

/** every route express actually has registered, derived from the router */
function registeredRoutes() {
  return router.stack
    .filter((layer) => layer.route)
    .flatMap((layer) =>
      Object.keys(layer.route.methods)
        .filter((m) => m !== '_all')
        .map((method) => ({ method, path: layer.route.path })),
    );
}

function isPublic(route) {
  return PUBLIC_ROUTES.some((p) => p.method === route.method && p.path === route.path);
}

/** '/checkpayment/:payment_hash' -> '/checkpayment/abc123' */
function concretePath(path) {
  return path.replace(/:[^/]+/g, 'test-param-value');
}

const protectedRoutes = registeredRoutes().filter((r) => !isPublic(r));

describe('every non-public route requires authentication', () => {
  it('found routes to check (guards against the enumeration silently returning nothing)', () => {
    expect(protectedRoutes.length).toBeGreaterThan(5);
  });

  // Asserting specifically on the *auth* error, not merely on `error: true`.
  // A bare truthy-error check passes for any failure at all, so a route that
  // lost its auth check but happened to reject the empty test body with
  // errorBadArguments would still look covered - which is exactly the blind
  // spot this file exists to close.
  const expectBadAuth = (res) => {
    expect(res.status).toBe(401);
    expect(res.body).toEqual(expect.objectContaining({ error: true, code: 1 }));
  };

  describe.each(protectedRoutes)('$method $path', (route) => {
    it('rejects a request with no Authorization header', async () => {
      const res = await request(app)[route.method](concretePath(route.path)).send({});
      expectBadAuth(res);
    });

    it('rejects a request with a bogus bearer token', async () => {
      const res = await request(app)
        [route.method](concretePath(route.path))
        .set('Authorization', 'Bearer not-a-real-token-at-all')
        .send({});
      expectBadAuth(res);
    });
  });
});

describe('public routes are an explicit, reviewed allowlist', () => {
  it.each(PUBLIC_ROUTES)('$method $path is registered and intentionally public', (route) => {
    expect(registeredRoutes()).toContainEqual({ method: route.method, path: route.path });
  });
});
