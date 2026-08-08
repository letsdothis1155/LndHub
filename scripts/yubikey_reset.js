/**
 * Operator recovery tool: clears all enrolled YubiKeys from an account,
 * restoring password-only login for someone locked out after losing their
 * only registered key. Doesn't touch bitcoind/LND, just Redis.
 *
 * Usage:
 *   node scripts/yubikey_reset.js <userid>
 *
 * <userid> is the account's internal id (not its `login`), same identifier
 * used by scripts/show_user.js. There's no login->userid lookup by design
 * (finding a userid normally requires the login+password together), so the
 * operator needs it from a backup, redis dump, or the account owner.
 */
import { User } from '../class/';
const config = require('../config');

var Redis = require('ioredis');
var redis = new Redis(config.redis);

redis.info(function (err, info) {
  if (err || !info) {
    console.error('redis failure');
    process.exit(5);
  }
});

(async () => {
  const userid = process.argv[2];
  if (!userid) {
    console.error('usage: node scripts/yubikey_reset.js <userid>');
    process.exit(1);
  }

  const u = new User(redis, null, null);
  u._userid = userid;

  const before = await u.getYubikeyIds();
  if (before.length === 0) {
    console.log('Account has no enrolled YubiKeys, nothing to do.');
    process.exit(0);
  }

  console.log('Currently enrolled public IDs:', before);
  for (const publicId of before) {
    await u.removeYubikeyId(publicId);
  }
  console.log('Cleared. Account can now log in with password only (re-enroll via `npm run login:enroll`).');

  process.exit(0);
})();
