const LIMITS = {
  sender_email: 254,
  subject: 998,
  body_text: 50000,
  sender_name: 100,
  reply_to: 254,
  url: 2000,
  urlsMax: 50,
  attachmentsMax: 20,
  attachmentNameMax: 255,
  mimeTypeMax: 255,
  ipMax: 45,
  authResultMax: 64
};

class HttpError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function stripNullAndTrim(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/\0/g, '').trim();
}

function clampString(str, maxLen) {
  const cleaned = stripNullAndTrim(str);
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

function sanitizePayload(rawPayload) {
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    throw new HttpError(400, 'Invalid payload: expected JSON object');
  }

  const required = ['sender_email', 'subject', 'body_text'];
  for (const field of required) {
    if (!rawPayload[field] || typeof rawPayload[field] !== 'string') {
      throw new HttpError(400, `Missing required field: ${field}`);
    }
  }

  const clean = {};

  clean.sender_email = clampString(rawPayload.sender_email, LIMITS.sender_email);
  clean.subject = clampString(rawPayload.subject, LIMITS.subject);
  clean.body_text = clampString(rawPayload.body_text, LIMITS.body_text);
  clean.sender_name = clampString(rawPayload.sender_name || '', LIMITS.sender_name);
  clean.reply_to = clampString(rawPayload.reply_to || '', LIMITS.reply_to);

  if (Array.isArray(rawPayload.urls)) {
    clean.urls = rawPayload.urls
      .slice(0, LIMITS.urlsMax)
      .map((u) => clampString(u, LIMITS.url))
      .filter((u) => u.length > 0);
  } else {
    clean.urls = [];
  }

  if (Array.isArray(rawPayload.attachments)) {
    clean.attachments = rawPayload.attachments
      .slice(0, LIMITS.attachmentsMax)
      .map((att) => {
        if (!att || typeof att !== 'object') return null;
        return {
          name: clampString(att.name || '', LIMITS.attachmentNameMax),
          mimeType: clampString(att.mimeType || '', LIMITS.mimeTypeMax),
          size: Number.isFinite(att.size) ? att.size : 0
        };
      })
      .filter(Boolean);
  } else {
    clean.attachments = [];
  }

  const headers = rawPayload.headers && typeof rawPayload.headers === 'object' ? rawPayload.headers : {};
  clean.headers = {
    sender_ip: clampString(headers.sender_ip || '', LIMITS.ipMax),
    spf_result: clampString(headers.spf_result || '', LIMITS.authResultMax).toLowerCase(),
    dkim_result: clampString(headers.dkim_result || '', LIMITS.authResultMax).toLowerCase(),
    dmarc_result: clampString(headers.dmarc_result || '', LIMITS.authResultMax).toLowerCase()
  };

  return clean;
}

module.exports = { sanitizePayload, HttpError, LIMITS };
