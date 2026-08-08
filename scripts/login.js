/**
 * CLI helper for logging into a YubiKey-gated LndHub account.
 *
 * Usage:
 *   node scripts/login.js login <login>     interactive login (password + OTP prompts), saves session
 *   node scripts/login.js refresh           refreshes tokens from saved session (no password/OTP needed)
 *   node scripts/login.js whoami            prints the currently saved session
 *   node scripts/login.js enroll            registers a YubiKey against the logged-in account (2FA going forward)
 *
 * Session (access_token/refresh_token) is cached in .lndhub-session.json (gitignored).
 */
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const config = require('../config');

const LNDHUB_URL = process.env.LNDHUB_URL || 'http://localhost:3000';
const SESSION_FILE = path.join(__dirname, '..', '.lndhub-session.json');

const KEYCODE_ENTER_CR = 13;
const KEYCODE_ENTER_LF = 10;
const KEYCODE_CTRL_C = 3;
const KEYCODE_DEL = 127;
const KEYCODE_BACKSPACE = 8;

function readHidden(promptText) {
  return new Promise((resolve) => {
    process.stdout.write(promptText);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    // Scan every character in the chunk individually - a YubiKey burst-types
    // its OTP faster than a human, so the terminal may deliver the OTP text
    // and its trailing Enter as a single chunk. Checking only chunk[0] misses
    // a mid-chunk terminator and silently corrupts the captured value.
    const onData = (chunk) => {
      const str = chunk.toString();
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

function saveSession(login, tokens) {
  fs.writeFileSync(SESSION_FILE, JSON.stringify({ login, ...tokens }, null, 2), { mode: 0o600 });
}

function loadSession() {
  if (!fs.existsSync(SESSION_FILE)) return null;
  return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
}

async function attemptAuth(body) {
  const res = await fetch(`${LNDHUB_URL}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, json: await res.json() };
}

async function doLogin(login) {
  if (!login) {
    console.error('usage: node scripts/login.js login <login>');
    process.exit(1);
  }

  const password = await readHidden('Password: ');
  // known up front only if this login is in the static override list;
  // self-enrolled accounts aren't knowable until the server rejects us
  let yubikey_otp = config.yubico.requiredForLogins.includes(login) ? await readHidden('Touch your YubiKey: ') : undefined;

  let { ok, json } = await attemptAuth({ login, password, yubikey_otp });

  if ((!ok || json.error) && !yubikey_otp) {
    // account may require a self-enrolled YubiKey we didn't know about; retry once
    yubikey_otp = await readHidden('Touch your YubiKey: ');
    ({ ok, json } = await attemptAuth({ login, password, yubikey_otp }));
  }

  if (!ok || json.error) {
    console.error('Login failed:', json.message || 'unknown error');
    process.exit(1);
  }

  saveSession(login, json);
  console.log('Logged in. access_token:', json.access_token);
}

async function doRefresh() {
  const session = loadSession();
  if (!session || !session.refresh_token) {
    console.error('No saved session. Run: node scripts/login.js login <login>');
    process.exit(1);
  }

  const res = await fetch(`${LNDHUB_URL}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: session.refresh_token }),
  });
  const json = await res.json();

  if (!res.ok || json.error) {
    console.error('Refresh failed:', json.message || res.statusText);
    process.exit(1);
  }

  saveSession(session.login, json);
  console.log('Refreshed. access_token:', json.access_token);
}

function doWhoami() {
  const session = loadSession();
  if (!session) {
    console.log('No saved session.');
    return;
  }
  console.log(JSON.stringify(session, null, 2));
}

async function doEnroll() {
  const session = loadSession();
  if (!session || !session.access_token) {
    console.error('No saved session. Run: node scripts/login.js login <login>');
    process.exit(1);
  }

  const yubikey_otp = await readHidden('Touch your YubiKey to enroll it: ');

  const res = await fetch(`${LNDHUB_URL}/yubikey/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
    body: JSON.stringify({ yubikey_otp }),
  });
  const json = await res.json();

  if (!res.ok || json.error) {
    console.error('Enrollment failed:', json.message || res.statusText);
    process.exit(1);
  }

  console.log('Enrolled YubiKey with public ID:', json.publicId, '- OTP will now be required on login.');
}

(async () => {
  const [, , cmd, arg] = process.argv;
  if (cmd === 'login') await doLogin(arg);
  else if (cmd === 'refresh') await doRefresh();
  else if (cmd === 'whoami') doWhoami();
  else if (cmd === 'enroll') await doEnroll();
  else {
    console.error('usage: node scripts/login.js <login|refresh|whoami|enroll> [login]');
    process.exit(1);
  }
})();
