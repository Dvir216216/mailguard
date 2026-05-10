const fs = require('fs');
const path = require('path');
const { BloomFilter } = require('bloom-filters');

const DATA_DIR = path.join(__dirname, '..', 'data');
const BIN_PATH = path.join(DATA_DIR, 'bloom_filter.bin');
const PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.json';
const CAPACITY = 100000;
const ERROR_RATE = 0.001;

let filter = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function normalizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let d = raw.trim().toLowerCase();
  if (d.startsWith('www.')) d = d.slice(4);
  return d;
}

function extractDomainFromUrl(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    const parsed = new URL(url);
    return normalizeDomain(parsed.hostname);
  } catch {
    const match = url.match(/^(?:https?:\/\/)?([^\/\s?#]+)/i);
    return match ? normalizeDomain(match[1]) : '';
  }
}

function saveToDisk() {
  if (!filter) return;
  try {
    ensureDataDir();
    const json = JSON.stringify(filter.saveAsJSON());
    fs.writeFileSync(BIN_PATH, json, 'utf8');
  } catch (err) {
    console.warn('[bloom] failed to save filter:', err.message);
  }
}

function loadFromDisk() {
  try {
    if (fs.existsSync(BIN_PATH)) {
      const json = fs.readFileSync(BIN_PATH, 'utf8');
      filter = BloomFilter.fromJSON(JSON.parse(json));
      console.log('[bloom] loaded filter from disk');
      return true;
    }
  } catch (err) {
    console.warn('[bloom] failed to load filter from disk:', err.message);
  }
  return false;
}

function initEmpty() {
  filter = BloomFilter.create(CAPACITY, ERROR_RATE);
}

function init() {
  ensureDataDir();
  if (!loadFromDisk()) {
    initEmpty();
  }
}

init();

async function fetchPhishTank() {
  if (!filter) initEmpty();
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 30000);
    const res = await fetch(PHISHTANK_URL, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) {
      console.warn(`[bloom] PhishTank fetch returned ${res.status}, continuing with existing filter`);
      return { added: 0, ok: false };
    }
    const data = await res.json();
    if (!Array.isArray(data)) {
      console.warn('[bloom] PhishTank response was not an array');
      return { added: 0, ok: false };
    }
    const seen = new Set();
    for (const entry of data) {
      const url = entry && (entry.url || entry.phish_detail_url);
      const domain = extractDomainFromUrl(url);
      if (domain && !seen.has(domain)) {
        seen.add(domain);
        filter.add(domain);
      }
    }
    saveToDisk();
    console.log(`[bloom] added ${seen.size} unique PhishTank domains`);
    return { added: seen.size, ok: true };
  } catch (err) {
    console.warn('[bloom] PhishTank fetch failed:', err.message);
    return { added: 0, ok: false };
  }
}

function checkDomains(domains) {
  if (!filter) initEmpty();
  if (!Array.isArray(domains)) return { hit: false, matched: null };
  for (const raw of domains) {
    const domain = normalizeDomain(raw);
    if (domain && filter.has(domain)) {
      return { hit: true, matched: domain };
    }
  }
  return { hit: false, matched: null };
}

function addDomain(domain) {
  if (!filter) initEmpty();
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;
  filter.add(normalized);
  saveToDisk();
  return true;
}

module.exports = {
  checkDomains,
  addDomain,
  fetchPhishTank,
  extractDomainFromUrl,
  normalizeDomain
};
