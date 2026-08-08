/**
 * CLI helper for logging into a YubiKey-gated LndHub account.
 *
 * Usage:
 *   node scripts/login.js login <login>     interactive login (password + OTP prompts), saves session
 *   node scripts/login.js refresh           refreshes tokens from saved session (no password/OTP needed)
 *   node scripts/login.js whoami            prints the currently saved session
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
    const onData = (chunk) => {
      const str = chunk.toString();
      const code = str.charCodeAt(0);
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
        return;
      }
      value += str;
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

async function doLogin(login) {
  if (!login) {
    console.error('usage: node scripts/login.js login <login>');
    process.exit(1);
  }

  const password = await readHidden('Password: ');
  const needsOtp = config.yubico.requiredForLogins.includes(login);
  const yubikey_otp = needsOtp ? await readHidden('Touch your YubiKey: ') : undefined;

  const body = { login, password };
  if (yubikey_otp) body.yubikey_otp = yubikey_otp;

  const res = await fetch(`${LNDHUB_URL}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();

  if (!res.ok || json.error) {
    console.error('Login failed:', json.message || res.statusText);
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

(async () => {
  const [, , cmd, arg] = process.argv;
  if (cmd === 'login') await doLogin(arg);
  else if (cmd === 'refresh') await doRefresh();
  else if (cmd === 'whoami') doWhoami();
  else {
    console.error('usage: node scripts/login.js <login|refresh|whoami> [login]');
    process.exit(1);
  }
})();
