/**
 * The dashboard router. Two things are pinned here:
 *
 * 1. Which origin ends up inside the /qr pairing code. That QR tells a wallet
 *    which server to send its requests to, so letting the caller's Host header
 *    decide it is a way to hand someone a QR pointing at a server that is not
 *    this one.
 * 2. Which routes this router exposes at all. Everything here is public by
 *    design, and controllers/__tests__/routeAuthCoverage.test.js only walks the
 *    API router - so without this, a route added to the dashboard is covered by
 *    nothing. The allowlist below makes adding one a deliberate edit.
 */
jest.mock('../../lightning', () => ({
  // website.js calls process.exit(4) if these error, so they must succeed
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true, block_height: 1 })),
  listChannels: jest.fn((opts, cb) => cb(null, { channels: [] })),
}));

const captured = [];
jest.mock('qr-image', () => ({
  image: (url) => {
    captured.push(url);
    const { Readable } = require('stream');
    return Readable.from(['png-bytes']);
  },
}));

const express = require('express');
const request = require('supertest');

const router = require('../website');

const app = express();
app.use(router);

/** the origin encoded into the bluewallet: deep link, decoded back out */
async function qrOrigin(hostHeader) {
  captured.length = 0;
  const req = request(app).get('/qr');
  if (hostHeader) req.set('Host', hostHeader);
  await req;
  const payload = captured[captured.length - 1];
  return decodeURIComponent(payload.replace('bluewallet:setlndhuburl?url=', ''));
}

describe('/qr pairing code origin', () => {
  const saved = { PUBLIC_URL: process.env.PUBLIC_URL, TOR_URL: process.env.TOR_URL };

  afterEach(() => {
    process.env.PUBLIC_URL = saved.PUBLIC_URL;
    process.env.TOR_URL = saved.TOR_URL;
    if (saved.PUBLIC_URL === undefined) delete process.env.PUBLIC_URL;
    if (saved.TOR_URL === undefined) delete process.env.TOR_URL;
  });

  it('uses PUBLIC_URL and ignores the Host header entirely', async () => {
    process.env.PUBLIC_URL = 'https://hub.example.com';
    delete process.env.TOR_URL;

    expect(await qrOrigin('evil.example.com')).toBe('https://hub.example.com');
  });

  it('strips a trailing slash from PUBLIC_URL rather than doubling it', async () => {
    process.env.PUBLIC_URL = 'https://hub.example.com/';
    delete process.env.TOR_URL;

    expect(await qrOrigin()).toBe('https://hub.example.com');
  });

  it('prefers PUBLIC_URL over TOR_URL when both are set', async () => {
    process.env.PUBLIC_URL = 'https://hub.example.com';
    process.env.TOR_URL = 'someonion.onion';

    expect(await qrOrigin('evil.example.com')).toBe('https://hub.example.com');
  });

  it('falls back to TOR_URL when PUBLIC_URL is unset', async () => {
    delete process.env.PUBLIC_URL;
    process.env.TOR_URL = 'someonion.onion';

    expect(await qrOrigin('evil.example.com')).toBe('http://someonion.onion');
  });

  it('falls back to the Host header only when neither is configured', async () => {
    // documents the remaining exposure rather than asserting it is safe:
    // an unconfigured deployment still derives the origin from the request
    delete process.env.PUBLIC_URL;
    delete process.env.TOR_URL;

    expect(await qrOrigin('whatever.example.com')).toBe('http://whatever.example.com');
  });
});

describe('the dashboard router exposes only its known public routes', () => {
  // Public by design: the status page and the pairing QR. Anything added here
  // is a new unauthenticated surface and should be a considered change.
  const EXPECTED_PUBLIC = [
    { method: 'get', path: '/' },
    { method: 'get', path: '/qr' },
  ];

  function registeredRoutes() {
    return router.stack
      .filter((layer) => layer.route)
      .flatMap((layer) =>
        Object.keys(layer.route.methods)
          .filter((m) => m !== '_all')
          .map((method) => ({ method, path: layer.route.path })),
      );
  }

  it('matches the allowlist exactly - a new route here fails this test', () => {
    expect(registeredRoutes().sort((a, b) => a.path.localeCompare(b.path))).toEqual(EXPECTED_PUBLIC);
  });

  it('serves the status page without credentials, as intended', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
  });

  it('404s unknown paths instead of falling through', async () => {
    const res = await request(app).get('/definitely-not-a-route');
    expect(res.status).toBe(404);
  });
});
