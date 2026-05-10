const punycode = require('punycode');
const { distance } = require('fastest-levenshtein');
const whois = require('whois');
const cache = require('../utils/cache');

const PROTECTED_BRANDS = [
  'paypal.com', 'google.com', 'microsoft.com',
  'amazon.com', 'apple.com', 'facebook.com',
  'netflix.com', 'instagram.com', 'twitter.com',
  'linkedin.com', 'dropbox.com', 'github.com'
];

const URGENCY_PHRASES = [
  'act now', 'urgent', 'verify immediately',
  'account suspended', 'click here', 'limited time',
  'confirm your', 'unusual activity', 'security alert',
  'update your payment', 'your account will be'
];

const SUSPICIOUS_EXTS = ['.exe', '.js', '.vbs', '.zip', '.bat', '.cmd', '.scr', '.msi'];

function getDomain(email) {
  if (!email || typeof email !== 'string') return '';
  const at = email.lastIndexOf('@');
  if (at < 0) return '';
  return email.slice(at + 1).trim().toLowerCase().replace(/^www\./, '');
}

function getDomainFromUrl(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    const m = url.match(/^(?:https?:\/\/)?([^\/\s?#]+)/i);
    return m ? m[1].toLowerCase().replace(/^www\./, '') : '';
  }
}

function replyToMismatch(senderEmail, replyTo) {
  const senderDomain = getDomain(senderEmail);
  const replyDomain = getDomain(replyTo);
  if (!senderDomain || !replyDomain) return 0;
  return senderDomain !== replyDomain ? 30 : 0;
}

function urlSpoofing(urls) {
  if (!Array.isArray(urls) || urls.length === 0) return 0;
  for (const url of urls) {
    if (typeof url !== 'string') continue;
    if (/@/.test(url) && /^https?:\/\/[^\/]*@/i.test(url)) return 25;
    if (/^https?:\/\/\d+\.\d+\.\d+\.\d+/i.test(url)) return 25;
    if (/xn--/i.test(url)) return 25;
    const host = getDomainFromUrl(url);
    for (const brand of PROTECTED_BRANDS) {
      if (host && host.includes(brand.split('.')[0]) && !host.endsWith(brand)) {
        return 25;
      }
    }
  }
  return 0;
}

function homoglyphDetection(domains) {
  if (!Array.isArray(domains) || domains.length === 0) return 0;
  for (const raw of domains) {
    if (!raw) continue;
    let normalized;
    try {
      normalized = punycode.toUnicode(raw.toLowerCase().replace(/^www\./, ''));
    } catch {
      normalized = raw.toLowerCase().replace(/^www\./, '');
    }
    let asciiForm;
    try {
      asciiForm = punycode.toASCII(normalized);
    } catch {
      asciiForm = normalized;
    }
    for (const brand of PROTECTED_BRANDS) {
      if (asciiForm === brand) continue;
      const d = distance(asciiForm, brand);
      if (d > 0 && d <= 2) return 25;
      const dUni = distance(normalized, brand);
      if (dUni > 0 && dUni <= 2) return 25;
    }
  }
  return 0;
}

function urgencyLanguage(subject, body) {
  const haystack = `${subject || ''} ${body || ''}`.toLowerCase();
  for (const phrase of URGENCY_PHRASES) {
    if (haystack.includes(phrase)) return 20;
  }
  return 0;
}

function spfDkimFail(headers) {
  if (!headers) return 0;
  const spf = (headers.spf_result || '').toLowerCase();
  const dkim = (headers.dkim_result || '').toLowerCase();
  if (spf === 'fail' || dkim === 'none') return 10;
  return 0;
}

function suspiciousAttachment(attachments) {
  if (!Array.isArray(attachments) || attachments.length === 0) return 0;
  for (const att of attachments) {
    const name = (att?.name || '').toLowerCase();
    const dot = name.lastIndexOf('.');
    if (dot < 0) continue;
    const ext = name.slice(dot);
    if (SUSPICIOUS_EXTS.includes(ext)) return 15;
  }
  return 0;
}

function whoisLookup(domain) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(null);
      }
    }, 5000);
    try {
      whois.lookup(domain, (err, data) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) return resolve(null);
        resolve(data);
      });
    } catch {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(null);
      }
    }
  });
}

function parseCreationDate(whoisText) {
  if (!whoisText || typeof whoisText !== 'string') return null;
  const patterns = [
    /Creation Date:\s*([^\r\n]+)/i,
    /Created On:\s*([^\r\n]+)/i,
    /Created:\s*([^\r\n]+)/i,
    /Domain Registration Date:\s*([^\r\n]+)/i,
    /Registered on:\s*([^\r\n]+)/i,
    /created:\s*([^\r\n]+)/i
  ];
  for (const re of patterns) {
    const m = whoisText.match(re);
    if (m) {
      const date = new Date(m[1].trim());
      if (!isNaN(date.getTime())) return date;
    }
  }
  return null;
}

async function newlyRegisteredDomain(senderDomain) {
  if (!senderDomain) return 0;
  const cacheKey = `whois:${senderDomain}`;
  const cached = cache.get(cacheKey);
  if (cached !== null) {
    return cached.points;
  }
  try {
    const data = await whoisLookup(senderDomain);
    if (!data) {
      cache.set(cacheKey, { points: 0 }, 24 * 3600);
      return 0;
    }
    const created = parseCreationDate(data);
    if (!created) {
      cache.set(cacheKey, { points: 0 }, 24 * 3600);
      return 0;
    }
    const ageDays = (Date.now() - created.getTime()) / 86400000;
    const points = ageDays < 30 ? 15 : 0;
    cache.set(cacheKey, { points }, 24 * 3600);
    return points;
  } catch (err) {
    console.warn('[heuristics] whois failed:', err.message);
    return 0;
  }
}

async function analyzeHeuristics(payload) {
  const signals = [];
  let totalPoints = 0;

  const checks = [
    { name: 'Reply-to mismatch', fn: () => replyToMismatch(payload.sender_email, payload.reply_to) },
    { name: 'URL spoofing pattern', fn: () => urlSpoofing(payload.urls) },
    { name: 'Homoglyph / typosquat domain', fn: () => homoglyphDetection([getDomain(payload.sender_email), ...(payload.urls || []).map(getDomainFromUrl)]) },
    { name: 'Urgency language', fn: () => urgencyLanguage(payload.subject, payload.body_text) },
    { name: 'SPF/DKIM failure', fn: () => spfDkimFail(payload.headers) },
    { name: 'Suspicious attachment extension', fn: () => suspiciousAttachment(payload.attachments) }
  ];

  for (const check of checks) {
    try {
      const points = check.fn();
      if (points > 0) {
        signals.push({ name: check.name, points });
        totalPoints += points;
      }
    } catch (err) {
      console.warn(`[heuristics] ${check.name} failed:`, err.message);
    }
  }

  try {
    const senderDomain = getDomain(payload.sender_email);
    const newDomainPoints = await newlyRegisteredDomain(senderDomain);
    if (newDomainPoints > 0) {
      signals.push({ name: 'Newly registered domain (<30 days)', points: newDomainPoints });
      totalPoints += newDomainPoints;
    }
  } catch (err) {
    console.warn('[heuristics] newly-registered-domain check failed:', err.message);
  }

  return { totalPoints, signals };
}

module.exports = {
  analyzeHeuristics,
  getDomain,
  getDomainFromUrl,
  replyToMismatch,
  urlSpoofing,
  homoglyphDetection,
  urgencyLanguage,
  spfDkimFail,
  suspiciousAttachment
};
