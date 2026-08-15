// ---------- Durable state store (KV-backed with in-memory fallback) ----------
// Cloudflare isolates do NOT share memory, so all cross-request state (sessions,
// OAST/command logs, brute-force counters, coupon/race maps) must live in a
// durable store. When the `STATE` KV binding is present, this module reads and
// writes that namespace; when it is absent (local `node test.mjs`, dev server),
// it falls back to an in-process Map so the whole suite stays green locally.

let kv = null;          // KV namespace binding, set once per isolate via init(env)
const mem = new Map();  // fallback store used when kv is null

export function init(env) {
  kv = (env && env.STATE) || null;
  return kv;
}

export async function read(key, def) {
  if (kv) {
    try {
      const raw = await kv.get(key, 'json');
      return raw === null ? def : raw;
    } catch (e) {
      return def;
    }
  }
  return mem.has(key) ? mem.get(key) : def;
}

export async function write(key, val) {
  if (kv) {
    try {
      await kv.put(key, JSON.stringify(val));
    } catch (e) {
      /* best effort */
    }
  } else {
    mem.set(key, val);
  }
}

// Write with an automatic expiry (seconds). KV removes the key server-side;
// the in-memory fallback relies on the caller checking an embedded exp field.
export async function writeTtl(key, val, ttlSeconds) {
  if (kv) {
    try {
      await kv.put(key, JSON.stringify(val), { expirationTtl: ttlSeconds });
    } catch (e) {
      /* best effort */
    }
  } else {
    mem.set(key, val);
  }
}

export async function del(key) {
  if (kv) {
    try {
      await kv.delete(key);
    } catch (e) {
      /* best effort */
    }
  } else {
    mem.delete(key);
  }
}