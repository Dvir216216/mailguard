const store = new Map();

function isExpired(entry) {
  return entry.expiresAt !== 0 && Date.now() > entry.expiresAt;
}

function get(key) {
  const entry = store.get(key);
  if (!entry) return null;
  if (isExpired(entry)) {
    store.delete(key);
    return null;
  }
  return entry.value;
}

function set(key, value, ttlSeconds) {
  const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : 0;
  store.set(key, { value, expiresAt });
}

function has(key) {
  const entry = store.get(key);
  if (!entry) return false;
  if (isExpired(entry)) {
    store.delete(key);
    return false;
  }
  return true;
}

function _clear() {
  store.clear();
}

module.exports = { get, set, has, _clear };
