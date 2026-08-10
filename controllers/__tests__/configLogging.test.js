/**
 * Regression test for the startup config log: controllers/api.js prints
 * `config` to stdout on every non-'prod' boot for debugging convenience,
 * but the raw config carries the bitcoind RPC password, Redis password,
 * LND wallet password, and Yubico secret key. This asserts those never
 * appear in the logged output, using synthetic secrets (never the real
 * ones).
 */
const SYNTHETIC_BITCOIND_PASSWORD = 'super-secret-bitcoind-password';
const SYNTHETIC_REDIS_PASSWORD = 'super-secret-redis-password';
const SYNTHETIC_LND_PASSWORD = 'super-secret-lnd-wallet-password';
const SYNTHETIC_YUBICO_SECRET = 'super-secret-yubico-key';

jest.mock('../../config', () => ({
  bitcoind: { rpc: `http://rpcuser:${'super-secret-bitcoind-password'}@127.0.0.1:8332` },
  redis: { port: 6379, host: '127.0.0.1', family: 4, db: 0, password: 'super-secret-redis-password' },
  lnd: { url: 'localhost:10009', password: 'super-secret-lnd-wallet-password' },
  yubico: {
    clientId: 'some-client-id',
    secretKey: 'super-secret-yubico-key',
    requiredForLogins: [],
    allowedPublicIds: [],
  },
}));
jest.mock('../../lightning', () => ({
  getInfo: jest.fn((opts, cb) => cb(null, { synced_to_chain: true })),
  subscribeInvoices: jest.fn(() => ({ on: jest.fn() })),
}));
jest.mock('../../bitcoin', () => ({
  request: jest.fn((method, params, cb) => {
    if (typeof cb === 'function') cb(null, { result: { chain: 'main', blocks: 999999999 } });
    return Promise.resolve({ result: { chain: 'main', blocks: 999999999 } });
  }),
}));

it('never logs raw secrets from config at startup, in any non-prod environment', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  delete process.env.NODE_ENV; // most permissive case: no NODE_ENV set at all

  const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  let loggedText;
  try {
    require('../api');
    // read calls before mockRestore(), which clears .mock.calls as part of its reset
    loggedText = logSpy.mock.calls.map((args) => args.join(' ')).join('\n');
  } finally {
    logSpy.mockRestore();
    process.env.NODE_ENV = originalNodeEnv;
  }

  expect(loggedText).toContain('using config');
  expect(loggedText).not.toContain(SYNTHETIC_BITCOIND_PASSWORD);
  expect(loggedText).not.toContain(SYNTHETIC_REDIS_PASSWORD);
  expect(loggedText).not.toContain(SYNTHETIC_LND_PASSWORD);
  expect(loggedText).not.toContain(SYNTHETIC_YUBICO_SECRET);
  // and confirms it's actually redacting, not just omitting the config log entirely
  expect(loggedText).toContain('***');
});
