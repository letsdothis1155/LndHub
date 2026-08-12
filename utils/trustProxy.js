/**
 * Resolves Express's `trust proxy` setting from the environment.
 *
 * This matters more than it looks: `trust proxy` decides whether `req.ip` comes
 * from the socket or from a client-supplied `X-Forwarded-For` header. Trusting
 * every hop (`app.enable('trust proxy')`) lets any direct caller pick their own
 * `req.ip`, which silently defeats every express-rate-limit bucket - rotate the
 * header per request and the limits never apply - and makes the IP recorded in
 * the auth log attacker-controlled.
 *
 * So the default is to trust nothing. Deployments that really do sit behind a
 * reverse proxy opt in by setting TRUST_PROXY to the number of proxies in front
 * of them (usually 1), or to an explicit list Express understands.
 *
 * Accepted values:
 *   unset | '' | 'false' | '0'  -> false        (default: req.ip is the socket peer)
 *   '1', '2', ...               -> hop count    (trust N proxies closest to the app)
 *   'loopback', '10.0.0.0/8'... -> passed through to Express as a trust list
 *   'true'                      -> true         (trust every hop - unsafe, see above)
 */
function parseTrustProxy(value) {
  if (value === undefined || value === null) return false;

  const normalized = String(value).trim();
  if (normalized === '' || normalized.toLowerCase() === 'false' || normalized === '0') return false;
  if (normalized.toLowerCase() === 'true') return true;

  // a bare integer is a hop count, which is the setting most reverse-proxy
  // deployments actually want
  if (/^\d+$/.test(normalized)) return parseInt(normalized, 10);

  // anything else (named presets like 'loopback', IPs, CIDR lists) is Express's
  // own trust-list syntax - hand it over untouched
  return normalized;
}

module.exports = { parseTrustProxy };
