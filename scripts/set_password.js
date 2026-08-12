/**
 * Operator tool: sets a new password for an existing account.
 *
 * LndHub has no password reset - a password exists only as the Redis key
 * `user_<login>_<sha256(password)>` pointing at the userid, so a forgotten
 * password is otherwise unrecoverable even with full database access.
 *
 * Usage:
 *   node scripts/set_password.js <login>
 *
 * Prompts twice for the new password (never echoed, never taken as an
 * argument, so it stays out of shell history and the process table). The
 * new credential is written and read back before any old one is removed,
 * so an interrupted run can only ever leave you with more working
 * passwords, never zero.
 */
const crypto = require('crypto');
const config = require('../config');

var Redis = require('ioredis');
var redis = new Redis(config.redis);

const KEYCODE_ENTER_CR = 13;
const KEYCODE_ENTER_LF = 10;
const KEYCODE_CTRL_C = 3;
const KEYCODE_DEL = 127;
const KEYCODE_BACKSPACE = 8;

function hash(string) {
  return crypto.createHash('sha256').update(string).digest().toString('hex');
}

function readHidden(promptText) {
  // non-TTY (piped stdin) is supported so this can be exercised by tests
  if (!process.stdin.isTTY) {
    return new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (chunk) => (data += chunk));
      process.stdin.on('end', () => resolve(data.split('\n')[0]));
    });
  }

  return new Promise((resolve) => {
    process.stdout.write(promptText);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (chunk) => {
      const str = chunk.toString();
      // scan every byte: a paste (or a hardware key) can deliver the whole
      // value plus its terminator in a single chunk
      for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code === KEYCODE_ENTER_CR || code === KEYCODE_ENTER_LF) {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(value);
          return;
        }
        if (code === KEYCODE_CTRL_C) {
          stdin.setRawMode(false);
          process.stdout.write('\n');
          process.exit(1);
        }
        if (code === KEYCODE_DEL || code === KEYCODE_BACKSPACE) {
          value = value.slice(0, -1);
          continue;
        }
        value += str[i];
      }
    };
    stdin.on('data', onData);
  });
}

(async () => {
  const login = process.argv[2];
  if (!login) {
    console.error('usage: node scripts/set_password.js <login>');
    process.exit(1);
  }

  // resolve the account from its existing credential key(s)
  const existingKeys = [];
  let cursor = '0';
  do {
    const [next, keys] = await redis.scan(cursor, 'MATCH', 'user_' + login + '_*', 'COUNT', 1000);
    cursor = next;
    existingKeys.push(...keys);
  } while (cursor !== '0');

  if (existingKeys.length === 0) {
    console.error(`No account found for login "${login}". Refusing to create one - check the login, and that this is the right redis db.`);
    process.exit(1);
  }

  const userids = [...new Set(await Promise.all(existingKeys.map((k) => redis.get(k))))];
  if (userids.length > 1) {
    console.error('Login maps to multiple userids, refusing to guess:', userids);
    process.exit(1);
  }
  const userid = userids[0];

  console.log(`Account: ${login}`);
  console.log(`Userid:  ${userid}`);
  console.log(`Existing password entries: ${existingKeys.length}`);
  console.log(`Using redis db ${config.redis.db} on ${config.redis.host}:${config.redis.port}\n`);

  const password = await readHidden('New password: ');
  if (!password) {
    console.error('Empty password, aborting.');
    process.exit(1);
  }

  if (process.stdin.isTTY) {
    const confirm = await readHidden('Confirm password: ');
    if (confirm !== password) {
      console.error('Passwords do not match, aborting. Nothing was changed.');
      process.exit(1);
    }
  }

  const newKey = 'user_' + login + '_' + hash(password);

  if (existingKeys.includes(newKey)) {
    console.log('That is already the current password for this account. Nothing to do.');
    process.exit(0);
  }

  // write and verify BEFORE removing anything
  await redis.set(newKey, userid);
  const readback = await redis.get(newKey);
  if (readback !== userid) {
    console.error('Failed to verify the new password entry, aborting. Old password(s) left untouched.');
    process.exit(1);
  }
  console.log('New password set and verified.');

  const stale = existingKeys.filter((k) => k !== newKey);
  for (const k of stale) {
    await redis.del(k);
  }
  console.log(`Removed ${stale.length} old password entr${stale.length === 1 ? 'y' : 'ies'}.`);
  console.log('\nDone. Note any enrolled YubiKey is still required on login (see scripts/yubikey_reset.js).');

  // Changing the password does not touch tokens: they live in their own
  // `userid_for_<token>` keys with no index back to the account, so there is
  // nothing here to revoke without scanning the keyspace. That is fine for a
  // routine change and wrong for a compromise, and the operator is the only one
  // who knows which this is - so say it plainly rather than implying the account
  // is now sealed.
  // point the suggested command at the same redis this script just wrote to,
  // so it cannot silently operate on db 0 of the wrong server
  const cli = `redis-cli -h ${config.redis.host} -p ${config.redis.port} -n ${config.redis.db || 0}`;
  console.log('\nExisting sessions are NOT signed out. Any access token stays valid for up to');
  console.log('1 hour and any refresh token for up to 30 days from when it was issued.');
  console.log('If you are resetting because the account may be compromised, that window is');
  console.log("the exposure - watch the balance over it, or flush this account's tokens:");
  console.log(`  ${cli} --scan --pattern 'userid_for_*' | while read -r k; do`);
  console.log(`    [ "$(${cli} get "$k")" = "${userid}" ] && ${cli} del "$k"`);
  console.log('  done');

  process.exit(0);
})();
