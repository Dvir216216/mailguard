# MailGuard

A Gmail Add-on that analyzes incoming emails for maliciousness using a multi-layer detection system: Bloom filter (PhishTank), IP reputation (AbuseIPDB), heuristic checks, and an LLM verdict (Claude) for borderline cases.

## Layout

```
mailguard/
├── addon/                # Google Apps Script add-on
│   ├── Code.gs
│   ├── Sidebar.html
│   └── appsscript.json
├── backend/              # Node.js + Express analysis API
│   ├── src/
│   │   ├── index.js
│   │   ├── routes/analyze.js
│   │   ├── layers/
│   │   │   ├── bloomFilter.js
│   │   │   ├── ipReputation.js
│   │   │   ├── heuristics.js
│   │   │   └── llmVerdict.js
│   │   ├── utils/
│   │   │   ├── sanitize.js
│   │   │   ├── cache.js
│   │   │   └── ssrfGuard.js
│   │   └── data/
│   ├── package.json
│   ├── .env.example
│   └── .gitignore
└── README.md
```

## Detection layers

1. **Bloom filter** (`+40`) — sender / URL domains checked against PhishTank feed.
2. **IP reputation** (`+20`) — AbuseIPDB lookup on sender IP, score > 50 fires.
3. **Heuristics** — reply-to mismatch (30), URL spoofing (25), homoglyph/typosquat (25), urgency language (20), SPF/DKIM fail (10), suspicious attachment ext (15), newly-registered domain (15).
4. **LLM verdict** — only invoked when total score is in the **40–69** band; provides reasoning + threat type.

Final score is capped at 100. Verdict labels:

| Range  | Verdict     |
|--------|-------------|
| 0–39   | SAFE        |
| 40–69  | SUSPICIOUS  |
| 70–100 | MALICIOUS   |

## Backend setup

```bash
cd backend
npm install
cp .env.example .env
# fill in API_KEY, ABUSEIPDB_API_KEY, ANTHROPIC_API_KEY
npm start
```

The server listens on `PORT` (default 3000), seeds the Bloom filter from PhishTank on startup, and persists it to `src/data/bloom_filter.bin`.

### Required environment variables

| Var | Purpose |
|-----|---------|
| `PORT` | Server port (default 3000) |
| `API_KEY` | Shared secret the add-on must send in `X-API-Key` |
| `ABUSEIPDB_API_KEY` | AbuseIPDB v2 key for IP reputation lookups |
| `ANTHROPIC_API_KEY` | Claude API key for the LLM verdict layer |

### Endpoint

`POST /analyze` (requires `X-API-Key`)

Request body — see `backend/src/utils/sanitize.js` for full schema. Required: `sender_email`, `subject`, `body_text`. Optional: `sender_name`, `reply_to`, `urls[]`, `attachments[]`, `headers{sender_ip, spf_result, dkim_result, dmarc_result}`.

Response:

```json
{
  "score": 75,
  "verdict": "MALICIOUS",
  "signals": [
    { "name": "Bloom filter hit (paypa1.com)", "points": 40 },
    { "name": "Reply-to mismatch", "points": 30 }
  ],
  "reasoning": null,
  "layers_called": ["bloom", "ip", "heuristics"]
}
```

## Add-on setup

1. Open [script.google.com](https://script.google.com) and create a new Apps Script project.
2. Replace `appsscript.json` (visible after enabling **Show "appsscript.json" manifest file** in project settings) with [addon/appsscript.json](addon/appsscript.json).
3. Replace the default `Code.gs` with [addon/Code.gs](addon/Code.gs).
4. Add a new HTML file `Sidebar` and paste in [addon/Sidebar.html](addon/Sidebar.html).
5. Open **Project Settings → Script Properties** and add:
   - `BACKEND_URL` — your backend's public URL (e.g. `https://mailguard.example.com`)
   - `API_KEY` — same value as `API_KEY` in `backend/.env`
6. **Deploy → Test deployments → Install** to side-load into your Gmail.

## Security highlights

- API key compared with `crypto.timingSafeEqual` (constant time).
- Payload **sanitized** (length-clamped, null-byte stripped) before any analysis layer touches it.
- SSRF guard (`utils/ssrfGuard.js`) blocks RFC1918, loopback, link-local, IPv6 ULA, and the cloud metadata endpoint (`169.254.169.254`) before any outbound HTTP.
- Express body limit `50kb`; rate limit 100 req / 15 min / IP.
- LLM prompt isolates **system instructions** from **untrusted email content** with explicit delimiters and an instruction to ignore content inside the delimited block.
- One failing layer never crashes a request — every layer is wrapped in try/catch.
- `helmet` for default security headers; CORS restricted to Google origins.

## Development

```bash
cd backend
npm run dev   # node --watch
```

`POST /health` returns `{ ok: true }` (no auth required).

## Notes / things you must fill in

- `backend/.env` — copy from `.env.example` and add real keys.
- Apps Script script properties (`BACKEND_URL`, `API_KEY`) — see step 5 above.
- AbuseIPDB free tier is 1000 lookups/day; cache.js caches results 1h.
- The `Sidebar.html` is wired up via `saveUserThreshold(value)`. To open it from Gmail, add a universal action / homepage trigger that returns it via `HtmlService.createHtmlOutputFromFile('Sidebar')` if you want it visible in-product.

## Known Limitation: 
Gmail restricts add-on access to 
spam/suspicious folder emails by platform policy. 
MailGuard operates on inbox emails only. 
Ironically, this means the most suspicious emails 
are the ones the add-on cannot directly analyze.
