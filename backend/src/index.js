require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const analyzeRoute = require('./routes/analyze');
const bloomFilter = require('./layers/bloomFilter');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const API_KEY = process.env.API_KEY || '';

app.set('trust proxy', 1);
app.use(helmet());

const allowedOrigins = [
  /\.google\.com$/,
  /\.googleusercontent\.com$/,
  /\.googleapis\.com$/,
  /^https:\/\/script\.google\.com$/
];

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      const ok = allowedOrigins.some((rule) =>
        rule instanceof RegExp ? rule.test(origin) : rule === origin
      );
      return ok ? cb(null, true) : cb(new Error('CORS: origin not allowed'));
    }
  })
);

app.use(express.json({ limit: '50kb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});
app.use(limiter);

function requireApiKey(req, res, next) {
  if (!API_KEY) {
    return res.status(500).json({ error: 'Server not configured: API_KEY missing' });
  }
  const provided = req.get('X-API-Key') || '';
  const a = Buffer.from(provided);
  const b = Buffer.from(API_KEY);
  if (a.length !== b.length) {
    // Still call timingSafeEqual to keep comparison time uniform
    const dummy = Buffer.alloc(b.length);
    crypto.timingSafeEqual(dummy, b);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  let ok = false;
  try {
    ok = crypto.timingSafeEqual(a, b);
  } catch {
    ok = false;
  }
  if (!ok) return res.status(401).json({ error: 'Unauthorized' });
  return next();
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.use('/analyze', requireApiKey, analyzeRoute);

app.use((err, _req, res, _next) => {
  console.warn('[error]', err.message);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err.message && err.message.startsWith('CORS:')) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  return res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => {
  console.log(`[mailguard] backend listening on :${PORT}`);
  bloomFilter.fetchPhishTank().catch((err) => {
    console.warn('[mailguard] PhishTank seed failed:', err.message);
  });
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));

module.exports = app;
