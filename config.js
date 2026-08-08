require('dotenv').config();

let config = {
  bitcoind: {
    rpc: process.env.BITCOIND_RPC || 'http://login:password@127.0.0.1:8332',
  },
  redis: {
    port: Number(process.env.REDIS_PORT) || 6379,
    host: process.env.REDIS_HOST || '127.0.0.1',
    family: Number(process.env.REDIS_FAMILY) || 4,
    db: Number(process.env.REDIS_DB) || 0,
  },
  lnd: {
    url: process.env.LND_URL || 'localhost:10009',
    password: process.env.LND_WALLET_PASSWORD || '',
  },
  yubico: {
    clientId: process.env.YUBICO_CLIENT_ID || '',
    secretKey: process.env.YUBICO_SECRET_KEY || '',
    // logins (as returned by /create) that must present a valid YubiKey OTP in addition to their password
    requiredForLogins: (process.env.YUBICO_REQUIRED_LOGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    // public IDs (first 12 chars of an OTP) of YubiKeys allowed to satisfy the above requirement
    allowedPublicIds: (process.env.YUBICO_ALLOWED_PUBLIC_IDS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  },
};

if (process.env.CONFIG) {
  console.log('using config from env');
  config = JSON.parse(process.env.CONFIG);
}
module.exports = config;
