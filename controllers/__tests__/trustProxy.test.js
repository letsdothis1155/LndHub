/**
 * `trust proxy` decides whether req.ip is the socket peer or a value the client
 * sends in X-Forwarded-For. Trusting every hop lets a caller pick their own
 * req.ip, which silently voids every express-rate-limit bucket and makes the IP
 * in the auth log forgeable - so the default has to be "trust nothing", and the
 * behaviour is pinned here rather than left to a one-line call in index.js.
 */
const express = require('express');
const request = require('supertest');
const rateLimit = require('express-rate-limit');
const { parseTrustProxy } = require('../../utils/trustProxy');

describe('parseTrustProxy', () => {
  it('defaults to false when unconfigured', () => {
    expect(parseTrustProxy(undefined)).toBe(false);
    expect(parseTrustProxy(null)).toBe(false);
    expect(parseTrustProxy('')).toBe(false);
    expect(parseTrustProxy('   ')).toBe(false);
  });

  it('treats explicit falsey strings as off', () => {
    expect(parseTrustProxy('false')).toBe(false);
    expect(parseTrustProxy('FALSE')).toBe(false);
    expect(parseTrustProxy('0')).toBe(false);
  });

  it('reads a bare integer as a hop count', () => {
    expect(parseTrustProxy('1')).toBe(1);
    expect(parseTrustProxy(' 2 ')).toBe(2);
  });

  it("passes Express's own trust-list syntax through untouched", () => {
    expect(parseTrustProxy('loopback')).toBe('loopback');
    expect(parseTrustProxy('10.0.0.0/8, 127.0.0.1')).toBe('10.0.0.0/8, 127.0.0.1');
  });

  it('still allows opting all the way in', () => {
    expect(parseTrustProxy('true')).toBe(true);
  });
});

function buildApp(trustProxyEnv) {
  const app = express();
  app.set('trust proxy', parseTrustProxy(trustProxyEnv));
  app.use(rateLimit({ windowMs: 60 * 1000, max: 2 }));
  app.get('/x', (req, res) => res.send({ ip: req.ip }));
  return app;
}

async function statusesWithRotatingForwardedFor(app) {
  const statuses = [];
  for (let i = 0; i < 4; i++) {
    statuses.push((await request(app).get('/x').set('X-Forwarded-For', `10.0.0.${i}`)).status);
  }
  return statuses;
}

describe('rate limiting cannot be sidestepped with X-Forwarded-For by default', () => {
  it('ignores the header, so a rotating spoofed IP still hits the limit', async () => {
    const app = buildApp(undefined);

    const res = await request(app).get('/x').set('X-Forwarded-For', '1.2.3.4');
    expect(res.body.ip).not.toBe('1.2.3.4');

    // requests 3 and 4 are refused even though every one claims a different IP
    expect(await statusesWithRotatingForwardedFor(buildApp(undefined))).toEqual([200, 200, 429, 429]);
  });

  it('honours the header once a deployment opts in', async () => {
    const app = buildApp('1');

    const res = await request(app).get('/x').set('X-Forwarded-For', '1.2.3.4');
    expect(res.body.ip).toBe('1.2.3.4');

    // documents the cost of opting in: behind a real proxy these are genuinely
    // different clients, but if nothing strips the header they are free buckets
    expect(await statusesWithRotatingForwardedFor(buildApp('1'))).toEqual([200, 200, 200, 200]);
  });
});
