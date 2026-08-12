/**
 * Exercises User's YubiKey enrollment storage against a real local Redis
 * (same instance the app uses), scoped to a throwaway userid so it never
 * touches real account data. Skipped automatically if Redis isn't reachable.
 */
const crypto = require('crypto');
const Redis = require('ioredis');
const config = require('../../config');
const { User } = require('../User');

// Unique per process. These tests write to the real shared Redis, so a fixed
// userid means two runs - two overlapping `npm test` invocations, or two jest
// workers - collide on one key: the afterEach cleanup of one empties the set
// the other is about to assert on, and the failure looks like a real bug in
// enrollment rather than a test-isolation problem.
const TEST_USERID = `__jest_yubikey_test_${process.pid}_${crypto.randomBytes(4).toString('hex')}__`;

let redis;
let redisAvailable = true;

beforeAll(async () => {
  redis = new Redis(config.redis);
  try {
    await redis.ping();
  } catch (e) {
    redisAvailable = false;
  }
});

afterEach(async () => {
  if (redisAvailable) await redis.del('yubikey_ids_for_' + TEST_USERID);
});

afterAll(() => {
  redis.disconnect();
});

function makeUser() {
  const u = new User(redis, null, null);
  u._userid = TEST_USERID;
  return u;
}

describe('User yubikey enrollment', () => {
  it('starts with no enrolled keys', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    expect(await u.getYubikeyIds()).toEqual([]);
  });

  it('enrolls a public id and lists it back', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    await u.addYubikeyId('ccccccexample');
    expect(await u.getYubikeyIds()).toEqual(['ccccccexample']);
  });

  it('is idempotent - enrolling the same id twice does not duplicate it', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    await u.addYubikeyId('ccccccexample');
    await u.addYubikeyId('ccccccexample');
    expect(await u.getYubikeyIds()).toEqual(['ccccccexample']);
  });

  it('supports enrolling more than one key', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    await u.addYubikeyId('ccccccfirst');
    await u.addYubikeyId('ccccccsecond');
    expect((await u.getYubikeyIds()).sort()).toEqual(['ccccccfirst', 'ccccccsecond']);
  });

  it('removes an enrolled key, restoring password-only login', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    await u.addYubikeyId('ccccccexample');
    await u.removeYubikeyId('ccccccexample');
    expect(await u.getYubikeyIds()).toEqual([]);
  });

  it('removing a key that was never enrolled is a harmless no-op', async () => {
    if (!redisAvailable) return;
    const u = makeUser();
    await u.removeYubikeyId('never-enrolled');
    expect(await u.getYubikeyIds()).toEqual([]);
  });

  it('scopes enrolled keys per-user (does not leak across userids)', async () => {
    if (!redisAvailable) return;
    const u1 = makeUser();
    const u2 = new User(redis, null, null);
    u2._userid = TEST_USERID + '_other';

    try {
      await u1.addYubikeyId('ccccccexample');
      expect(await u2.getYubikeyIds()).toEqual([]);
    } finally {
      await redis.del('yubikey_ids_for_' + u2._userid);
    }
  });
});

if (!redisAvailable) {
  // eslint-disable-next-line no-console
  console.warn('Skipping User yubikey tests: Redis not reachable at configured host/port.');
}
