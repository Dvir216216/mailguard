const ipRangeCheck = require('ip-range-check');

const BLOCKED_RANGES = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '0.0.0.0/8',
  '::1/128',
  'fc00::/7',
  'fe80::/10'
];

const BLOCKED_LITERALS = new Set([
  '169.254.169.254',
  '::1',
  '0.0.0.0'
]);

function isPrivateIP(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const trimmed = ip.trim();
  if (trimmed.length === 0) return true;
  if (BLOCKED_LITERALS.has(trimmed)) return true;
  try {
    return Boolean(ipRangeCheck(trimmed, BLOCKED_RANGES));
  } catch {
    return true;
  }
}

module.exports = { isPrivateIP, BLOCKED_RANGES };
