# Web Attack Academy

A deliberately vulnerable practice platform for learning web attacks — 94 labs inspired by the PortSwigger Web Security Academy (SQLi, XSS, CSRF, clickjacking, path traversal, auth, access control, SSRF, XXE, SSTI, command injection, NoSQL injection, request smuggling, insecure deserialization, file upload, business logic, race conditions, weak crypto, CORS, host header attacks, web cache poisoning, prototype pollution, GraphQL, WebSockets, open redirect, and information disclosure). Front-end runs on GitHub Pages; the vulnerable lab backend runs on a Cloudflare Worker.

## Architecture

```
site/            static front-end (GitHub Pages)
  index.html     dashboard / lab list
  lab.html       embedded lab runner (iframe + postMessage solve signals)
  js/app.js      dashboard logic
  js/lab.js      lab embedding + solve tracking
  js/config.js   API_BASE -> points at the deployed worker
  data/labs.json lab metadata (id, title, objective, hint, type)
worker/          Cloudflare Worker backend (the vulnerable apps)
  index.js       all lab handlers, session + solve tracking
  test.mjs       integration test: hits every lab, asserts solve signal
  wrangler.toml  Worker deployment config
```

## Labs (94)

| Category | Labs |
|----------|------|
| SQL injection | `sqli-1..6` (error/hidden, login bypass, union, blind boolean, blind time) |
| XSS | `xss-1..7` (reflected, stored, DOM, attribute, image, filtered, JS context) |
| CSRF | `csrf-1..5` (token, fake token, GET, referer, JSON) |
| Clickjacking | `cj-1..3` (no XFO, frame-busting, prefill) |
| Path traversal | `pt-1..6` (simple, absolute, strip, double-encode, start-of-path, null byte) |
| Authentication | `auth-1..6` (enumeration, IP brute-force, lockout, cookie, stay-logged-in, 2FA) |
| Access control | `ac-1..6` (unprotected admin, hidden, IDOR uid, API, method-based, referer-based) |
| SSRF | `ssrf-1..4` (basic, blacklist bypass, allowlist bypass, blind OAST) |
| XXE | `xxe-1..4` (/etc/passwd, SVG, blind external DTD, SSRF) |
| SSTI | `ssti-1..4` (basic, arithmetic/env, Java RCE, Python RCE) |
| Command injection | `cmdi-1..3` (basic, blind log, filter bypass) |
| NoSQL injection | `nosql-1..3` (login bypass, $regex query, $regex reset) |
| Request smuggling | `smug-1..3` (CL.TE, TE.CL, obfuscated TE) |
| Insecure deserialization | `deser-1..2` (object tampering, gadget chain) |
| File upload | `upload-1..3` (no restrictions, content-type, ext blacklist) |
| Business logic | `bl-1..3` (price tampering, negative quantity, coupon reuse) |
| Race conditions | `race-1..2` (coupon overrun, multi-endpoint) |
| Weak crypto | `crypto-1..2` (predictable reset token, forged JWT) |
| CORS | `cors-1..4` (any origin, null origin, suffix bypass, substring bypass) |
| Host header attacks | `host-1..3` (reset poisoning, X-Forwarded-Host, validation bypass) |
| Web cache poisoning | `cache-1..3` (unkeyed XFH, unkeyed XFS, unkeyed utm) |
| Prototype pollution | `proto-1..3` (__proto__, constructor.prototype, RCE gadget) |
| GraphQL | `graphql-1..3` (introspection, BOLA, batching) |
| WebSockets | `ws-1..2` (CSWSH, stored XSS) |
| Open redirect | `redirect-1..2` (no validation, validation bypass) |
| Information disclosure | `info-1..2` (debug errors, leftover files) |

## Local development

```bash
# 1. Run the worker backend (in-process fetch, no real port needed)
cd worker
node test.mjs          # runs every lab, prints solved=true / false

# 2. Serve the front-end
#    Open site/index.html via any static server (e.g. `npx serve site`),
#    then open a lab. site/js/config.js must point at the worker.

# 3. Optional: real local worker via wrangler dev
cd worker
npm i
npm run dev            # runs dev-server.mjs (in-process) or wrangler dev
```

## Deploy

1. **Backend** — deploy the Worker:
   ```bash
   cd worker
   npx wrangler login
   npm run deploy       # name: web-attack-academy  (config in wrangler.toml)
   ```
   Your Worker URL will be `https://web-attack-academy.<SUBDOMAIN>.workers.dev`.

2. **Front-end** — publish `site/` to GitHub Pages, then set `API_BASE` in
   `site/js/config.js` to the Worker URL above and redeploy.

> **Security note:** This repo contains intentionally vulnerable code. Do **not**
> deploy it to a production or internet-facing environment for real users. It is
> for authorized, isolated practice only.

## Solve mechanics

- Server-side labs return an `x-lab-solved: true` response header when exploited.
- Client-side labs (DOM XSS, clickjacking) `postMessage('academy-solved:<id>')`
  to the parent; `site/js/lab.js` catches it and calls `/api/mark/<id>`.
- Progress persists per browser via a session cookie; `/api/status/<id>` reports
  solve state.