const express = require('express');
const { sanitizePayload, HttpError } = require('../utils/sanitize');
const bloomFilter = require('../layers/bloomFilter');
const ipReputation = require('../layers/ipReputation');
const { analyzeHeuristics, getDomain, getDomainFromUrl } = require('../layers/heuristics');
const { getLlmVerdict } = require('../layers/llmVerdict');

const router = express.Router();

const BLOOM_POINTS = 40;
const LLM_MIN_SCORE = 40;
const LLM_MAX_SCORE = 69;
const SUSPICIOUS_THRESHOLD = 40;
const MALICIOUS_THRESHOLD = 70;

function verdictFromScore(score) {
  if (score >= MALICIOUS_THRESHOLD) return 'MALICIOUS';
  if (score >= SUSPICIOUS_THRESHOLD) return 'SUSPICIOUS';
  return 'SAFE';
}

router.post('/', async (req, res, next) => {
  try {
    const clean = sanitizePayload(req.body);

    const signals = [];
    const layersCalled = [];
    let score = 0;
    let reasoning = null;

    // Layer 1: Bloom filter
    layersCalled.push('bloom');
    try {
      const senderDomain = getDomain(clean.sender_email);
      const urlDomains = (clean.urls || []).map(getDomainFromUrl).filter(Boolean);
      const allDomains = [senderDomain, ...urlDomains].filter(Boolean);
      const bloomResult = bloomFilter.checkDomains(allDomains);
      if (bloomResult.hit) {
        signals.push({ name: `Bloom filter hit (${bloomResult.matched})`, points: BLOOM_POINTS });
        score += BLOOM_POINTS;
      }
    } catch (err) {
      console.warn('[analyze] bloom layer failed:', err.message);
    }

    // Layer 2: IP reputation
    layersCalled.push('ip');
    try {
      const senderIp = clean.headers?.sender_ip;
      if (senderIp) {
        const ipResult = await ipReputation.checkIp(senderIp);
        if (ipResult.hit) {
          signals.push({
            name: `IP reputation (abuse score ${ipResult.score})`,
            points: ipResult.points
          });
          score += ipResult.points;
        }
      }
    } catch (err) {
      console.warn('[analyze] ip layer failed:', err.message);
    }

    // Layer 3: Heuristics
    layersCalled.push('heuristics');
    try {
      const heur = await analyzeHeuristics(clean);
      for (const sig of heur.signals) signals.push(sig);
      score += heur.totalPoints;
    } catch (err) {
      console.warn('[analyze] heuristics layer failed:', err.message);
    }

    // Layer 4: LLM verdict — only if 40 <= score <= 69
    if (score >= LLM_MIN_SCORE && score <= LLM_MAX_SCORE) {
      layersCalled.push('llm');
      try {
        const llm = await getLlmVerdict({
          signals,
          score,
          sender: clean.sender_email,
          subject: clean.subject,
          body: clean.body_text
        });
        reasoning = llm.reasoning;
      } catch (err) {
        console.warn('[analyze] llm layer failed:', err.message);
        reasoning = 'LLM analysis unavailable';
      }
    }

    score = Math.min(score, 100);

    return res.json({
      score,
      verdict: verdictFromScore(score),
      signals,
      reasoning,
      layers_called: layersCalled
    });
  } catch (err) {
    if (err instanceof HttpError) {
      return res.status(err.code).json({ error: err.message });
    }
    return next(err);
  }
});

module.exports = router;
