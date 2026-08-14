// ============================================================
//  Web Attack Academy — front-end config
//  Change API_BASE to your deployed Cloudflare Worker URL.
//  For local dev: http://localhost:8787  (default below)
// ============================================================
window.CONFIG = {
  API_BASE: 'https://web-attack-academy.web-attack-academy-worker.workers.dev',
  // Local dev override: API_BASE: 'http://localhost:8787',
  LAB_ORIGIN_RE: /^(?:https?:\/\/)?(?:[a-z0-9-]+\.)?(workers\.dev|localhost(?::\d+)?|127\.0\.0\.1(?::\d+)?)/i
};