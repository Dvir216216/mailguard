const cache = require('../utils/cache');
const { isPrivateIP } = require('../utils/ssrfGuard');

const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const TTL_SECONDS = 3600;
const POINTS = 20;
const ABUSE_THRESHOLD = 50;
const REQUEST_TIMEOUT_MS = 5000;

async function checkIp(ip) {
  if (!ip || typeof ip !== 'string') {
    return { hit: false, score: 0, points: 0, skipped: true, reason: 'no_ip' };
  }
  if (isPrivateIP(ip)) {
    return { hit: false, score: 0, points: 0, skipped: true, reason: 'private_ip' };
  }

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { hit: false, score: 0, points: 0, skipped: true, reason: 'no_api_key' };
  }

  const cacheKey = `abuseipdb:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  try {
    const url = new URL(ABUSEIPDB_URL);
    url.searchParams.set('ipAddress', ip);
    url.searchParams.set('maxAgeInDays', '90');

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);

    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        Key: apiKey,
        Accept: 'application/json'
      },
      signal: ctrl.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      console.warn(`[ipRep] abuseipdb returned ${res.status} for ${ip}`);
      const fallback = { hit: false, score: 0, points: 0, error: true };
      cache.set(cacheKey, fallback, 60);
      return fallback;
    }

    const data = await res.json();
    const abuseScore = data?.data?.abuseConfidenceScore ?? 0;

    const result = abuseScore > ABUSE_THRESHOLD
      ? { hit: true, score: abuseScore, points: POINTS }
      : { hit: false, score: abuseScore, points: 0 };

    cache.set(cacheKey, result, TTL_SECONDS);
    return result;
  } catch (err) {
    console.warn('[ipRep] lookup failed:', err.message);
    return { hit: false, score: 0, points: 0, error: true };
  }
}

module.exports = { checkIp };
