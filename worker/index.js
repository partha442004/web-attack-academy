// ============================================================
//  Web Attack Academy — deliberately vulnerable lab backend
//  Cloudflare Worker (also runs with `node worker/dev-server.mjs`)
//
//  WARNING: contains intentional vulnerabilities for security
//  training ONLY. Hosted on Cloudflare Workers so every request
//  runs in a sandboxed isolate — safe to expose publicly.
// ============================================================

import { extraRoutes } from './extras.js';

const APP = {
  name: 'Academy Shop',
  storeName: 'Web Attack Academy'
};

// ---------------- fake data ----------------
const PRODUCTS = [
  { id: 1, category: 'Gifts',    name: 'Teddy Bear',      released: true },
  { id: 2, category: 'Gifts',    name: 'Coffee Mug',      released: true },
  { id: 3, category: 'Toys',     name: 'RC Car',          released: true },
  { id: 4, category: 'Toys',     name: 'Puzzle Box',      released: true },
  { id: 5, category: 'Electronics', name: 'Headphones',   released: true },
  { id: 6, category: 'Electronics', name: 'Keyboard',     released: true },
  { id: 7, category: 'Books',    name: 'Hacking 101',     released: true },
  { id: 8, category: 'Books',    name: 'Networking',      released: true },
  { id: 9, category: 'Gifts',    name: 'VIP Mystery Box', released: false }, // hidden product
  { id: 10, category: 'Toys',    name: 'Collector Set',   released: false }
];

// usernames -> password (this is the "database" an attacker reads)
const USERS = {
  wiener:       { password: 'peter',     role: 'user',  name: 'wiener Wiener' },
  carlos:       { password: 'montoya',   role: 'user',  name: 'carlos Carlos' },
  administrator:{ password: '123456',    role: 'admin', name: 'administrator' }
};

const WORDLIST = [
  '123456','password','qwerty','admin','letmein','monkey','dragon','sunshine',
  'princess','football','iloveyou','welcome','abc123','shadow','master','111111',
  '123123','trustno1','admin123','carolina','montoya'
];

const FAKE_PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash';

const SECRETS = {
  sqli3: 'administrator',
  sqli4: 'administrator / aL4bZ0x'
};

// ---------------- session store (in-memory) ----------------
// Map sessionId -> { solved: Set }
const sessions = new Map();
const bruteFail = { byIp: new Map(), byUser: new Map() };

function sessionIdFrom(req) {
  const c = (req.headers.get('cookie') || '').split(';').map(s => s.trim());
  const hit = c.find(k => k.startsWith('academy_session='));
  return hit ? hit.slice('academy_session='.length) : null;
}
function getSession(id) {
  if (!id) return null;
  let s = sessions.get(id);
  if (!s) { s = { solved: new Set() }; sessions.set(id, s); }
  return s;
}
function isSolved(req, labId) {
  const s = getSession(sessionIdFrom(req));
  return s ? s.solved.has(labId) : false;
}
function markSolved(req, labId) {
  let sid = sessionIdFrom(req);
  if (!sid) { sid = Math.random().toString(36).slice(2) + Date.now().toString(36); }
  const s = getSession(sid);
  s.solved.add(labId);
  return sid;
}

// ---------------- helpers ----------------
function cookieSet(sid) {
  return `academy_session=${sid}; Path=/; HttpOnly; SameSite=None; Secure`;
}
function html(body, opts = {}) {
  const title = opts.title || 'Academy';
  const style = `
  <style>
    *{box-sizing:border-box;font-family:'Segoe UI',Arial,sans-serif}
    body{margin:0;background:#f4f5f7;color:#222}
    header{background:#24292e;color:#fff;padding:10px 20px;display:flex;justify-content:space-between;align-items:center}
    header a{color:#79b8ff;text-decoration:none}
    .wrap{max-width:900px;margin:20px auto;padding:0 16px}
    .card{background:#fff;border:1px solid #e1e4e8;border-radius:6px;padding:16px;margin-bottom:16px}
    .banner{background:#fff3cd;border:1px solid #ffeeba;color:#664d03;padding:10px 14px;border-radius:4px;margin-bottom:12px;font-size:13px}
    .ok{background:#d4edda;color:#155724;border:1px solid #c3e6cb;padding:10px 14px;border-radius:4px;margin-bottom:12px}
    .err{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb;padding:10px 14px;border-radius:4px;margin-bottom:12px}
    table{border-collapse:collapse;width:100%;background:#fff}
    th,td{border:1px solid #e1e4e8;padding:8px 10px;text-align:left}
    th{background:#f6f8fa}
    input[type=text],input[type=password],input[type=email],textarea{width:100%;padding:8px;border:1px solid #c9ccd1;border-radius:4px;margin-bottom:10px}
    button{background:#2ea44f;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px}
    .btn2{background:#0366d6}
    .muted{color:#6a737d;font-size:13px}
    .row{display:flex;gap:8px;align-items:center}
    .link{color:#0366d6;text-decoration:none;margin-right:12px}
    ul{line-height:1.7}
  </style>`;
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>${style}</head>
  <body><header><strong>${APP.name}</strong><a href="/">Back to store</a></header>
  <div class="wrap">${body}</div></body></html>`;
}

// strip dangerous chars for "filtered" labs
function htmlenc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function bodyParams(req) {
  return new Promise(res => {
    req.text().then(t => {
      const p = new URLSearchParams(t);
      const o = {};
      p.forEach((v, k) => o[k] = v);
      res(o);
    }).catch(() => res({}));
  });
}

function cspHeaders() {
  return {
    'Content-Security-Policy': "frame-ancestors 'self' http://localhost:* http://127.0.0.1:* https://*.github.io",
    'X-Frame-Options': 'ALLOW-FROM *'
  };
}

// ============================================================
//  LAB HANDLERS
//  each: async (req, url, ctx) => { body, solved?, cookie?, contentType? }
// ============================================================

// ---------- SQL Injection ----------
const sqli = {
  // shop page shared by sqli-1/3/4
  shopPage(extra) {
    return `<h2>${APP.storeName}</h2>
    <div class="banner">Vulnerability: SQL query built by string concatenation.</div>
    <div class="row" style="margin-bottom:12px">
      <span class="muted">Categories:</span>
      <a class="link" href="/lab/${extra.id}">All</a>
      <a class="link" href="/lab/${extra.id}?category=Gifts">Gifts</a>
      <a class="link" href="/lab/${extra.id}?category=Toys">Toys</a>
      <a class="link" href="/lab/${extra.id}?category=Electronics">Electronics</a>
      <a class="link" href="/lab/${extra.id}?category=Books">Books</a>
    </div>
    <form method="GET" class="card" style="padding:10px">
      <label class="muted">Try a raw category value (test for SQLi):</label>
      <div class="row">
        <input type="text" name="category" placeholder="Gifts" value="">
        <button type="submit">Filter</button>
      </div>
    </form>
    ${extra.stock || ''}
    ${extra.msg || ''}`;
  },

  async sql1(req, url) {
    const cat = url.searchParams.get('category');
    let stock = '', msg = '', solved = false;
    if (cat === null) {
      stock = table(PRODUCTS.filter(p => p.released));
    } else if (/['"]/.test(cat) === false) {
      // "safe-looking" value -> normal filter
      stock = table(PRODUCTS.filter(p => p.released && p.category === cat));
      if (stock === emptyTable) stock = emptyTable;
    } else if (/or\s+['"]?1['"]?\s*=\s*['"]?1/i.test(cat)) {
      // classic OR 1=1 -> all products incl. unreleased
      solved = true; msg = okMsg('SQLi succeeded — query returned ALL products including unreleased.');
      stock = table(PRODUCTS);
    } else if (/or\s+['"]?1['"]?\s*=\s*['"]?2/i.test(cat)) {
      msg = errMsg('Query ran (no error) but returned no rows.');
      stock = emptyTable;
    } else if (/-{2,}/.test(cat) || /or|union|select|and/i.test(cat)) {
      // some injected clause that doesn't match happy path
      msg = errMsg('Query syntax error: unterminated string literal.');
      stock = emptyTable;
    } else {
      msg = errMsg('Query syntax error: unterminated string literal.');
      stock = emptyTable;
    }
    return { body: html(sqli.shopPage({ id: 'sqli-1', msg, stock }), { title: 'Store' }), solved };
  },

  async sql3(req, url) { // UNION, single column -> retrieve username
    const cat = url.searchParams.get('category');
    let stock = '', msg = '', solved = false;
    if (cat === null) {
      stock = table(PRODUCTS.filter(p => p.released));
    } else if (/union\s+select\s+null\b/i.test(cat) && !/from\s+users/i.test(cat)) {
      msg = okMsg('UNION with 1 column worked. The category table has exactly 1 column.');
      stock = table(PRODUCTS.filter(p => p.released));
    } else if (/union\s+select\s+.*from\s+users/i.test(cat)) {
      // attacker pulled usernames -> returns them as extra rows
      const rows = Object.keys(USERS).map(u => [u]);
      solved = true; msg = okMsg('You retrieved the usernames table: ' + Object.keys(USERS).join(', '));
      stock = table(PRODUCTS.filter(p => p.released), rows);
    } else if (/['"]/.test(cat)) {
      msg = errMsg('Query syntax error: unterminated string literal.');
      stock = emptyTable;
    } else {
      stock = table(PRODUCTS.filter(p => p.released && p.category === cat));
    }
    return { body: html(sqli.shopPage({ id: 'sqli-3', msg, stock }), { title: 'Store' }), solved };
  },

  async sql4(req, url) { // UNION, 2 columns -> retrieve username+password
    const cat = url.searchParams.get('category');
    let stock = '', msg = '', solved = false;
    if (cat === null) {
      stock = table(PRODUCTS.filter(p => p.released));
    } else if (/union\s+select\s+null\s*,\s*null\b/i.test(cat)) {
      msg = okMsg('UNION with 2 columns worked. The category table has 2 columns.');
      stock = table(PRODUCTS.filter(p => p.released));
    } else if (/union\s+select\s+.*,\s*.*from\s+users/i.test(cat)) {
      const rows = Object.entries(USERS).map(([u, d]) => [u, d.password]);
      solved = true; msg = okMsg('You retrieved usernames + passwords: ' + Object.entries(USERS).map(([u,d])=>u+'/'+d.password).join(', '));
      stock = table(PRODUCTS.filter(p => p.released), rows);
    } else if (/['"]/.test(cat)) {
      msg = errMsg('Query syntax error: unterminated string literal.');
      stock = emptyTable;
    } else {
      stock = table(PRODUCTS.filter(p => p.released && p.category === cat));
    }
    return { body: html(sqli.shopPage({ id: 'sqli-4', msg, stock }), { title: 'Store' }), solved };
  },

  async login(req, url) { // sqli-2 login bypass
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const u = p.username || '', pw = p.password || '';
      // vulnerable: SELECT * FROM users WHERE username='$u' AND password='$pw'
      let solved = false;
      if (/'\s*--/.test(u) || /or\s+['"]?1['"]?\s*=\s*['"]?1/i.test(u) || /'\s*(or|or\s*'1'='1)/i.test(u)) {
        solved = true;
        return { body: html(`
          <h2>Logged in</h2>
          <div class="ok">Welcome, <strong>administrator</strong>! You bypassed the login with a SQL injection payload.</div>
          <a class="link" href="/lab/sqli-2">Back to login</a>`), solved };
      }
      if (USERS[u] && USERS[u].password === pw) {
        return { body: html(`
          <h2>Logged in</h2><div class="ok">Welcome back, ${htmlenc(USERS[u].name)}.</div>
          <a class="link" href="/lab/sqli-2">Back to login</a>`), solved };
      }
      return { body: html(`
        <h2>Login</h2><div class="err">Invalid username or password.</div>
        <a class="link" href="/lab/sqli-2">Try again</a>`) };
    }
    return { body: html(`
      <h2>Login</h2>
      <div class="banner">Vulnerability: SQL query built by string concatenation.</div>
      <form method="POST" class="card">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
      </form>`), contentType: 'text/html' };
  },

  async blindBool(req, url) { // sqli-5
    const tid = url.searchParams.get('trackingId') || '';
    let msg = '';
    let cond = false;
    if (tid) {
      // SELECT trackingId FROM tracking WHERE trackingId='$tid'
      if (tid.includes("'1'='1")) cond = true;
      else if (tid.includes("'1'='2")) cond = false;
      else if (tid.includes("'a'='a")) cond = true;
      else if (tid.includes("'a'='b")) cond = false;
      else if (/select/i.test(tid)) cond = /administrator/i.test(tid); // arbitrary condition -> true only if it mentions admin
      else cond = false;
    }
    let solved = false;
    // boolean blind: solve when a subquery confirms the administrator user exists
    if (tid && /administrator/i.test(tid) && /select\s/i.test(tid) && /'a'/.test(tid)) { cond = true; solved = true; }
    return { body: html(`
      <h2>Order lookup</h2>
      <div class="banner">Your tracking ID: <code>${htmlenc(tid)}</code></div>
      <p>This page reflects whether your tracking ID exists in the database.</p>
      <p><strong>${cond ? 'Welcome back!' : 'Tracking ID does not exist.'}</strong></p>
      <form method="GET"><input type="text" name="trackingId" placeholder="Enter tracking ID" value="${htmlenc(tid)}"><button>Submit</button></form>
      <p class="muted">Tip: the SQL runs <code>WHERE trackingId='...'</code>. A boolean condition controls the "Welcome back" message.</p>
      ${solved ? okMsg('You proved the administrator user exists via a blind boolean injection.') : ''}`), solved };
  },

  async blindTime(req, url) { // sqli-6 (simulated delay)
    const tid = url.searchParams.get('trackingId') || '';
    let delay = 0, solved = false;
    if (tid && /pg_sleep|sleep\s*\(/i.test(tid)) {
      const m = tid.match(/sleep\s*\(\s*(\d+)/i);
      delay = Math.min(parseInt(m ? m[1] : '3'), 10) * 1000;
      solved = /administrator/i.test(tid) ? false : true;
    }
    if (delay > 0) await new Promise(r => setTimeout(r, Math.min(delay, 3000))); // cap at 3s
    const welcome = !tid || /'1'='1/.test(tid) || (delay > 0 && /or/i.test(tid)) || (delay > 0 && /select/i.test(tid));
    let solvedFinal = false;
    // time-based: solve when pg_sleep is used in a CASE/conditional that references administrator
    if (tid && /pg_sleep/i.test(tid) && /administrator/i.test(tid) && /select\s/i.test(tid)) solvedFinal = true;
    if (tid && /pg_sleep/i.test(tid) && !/administrator/i.test(tid) && /or\s/i.test(tid)) solvedFinal = true;
    return { body: html(`
      <h2>Order lookup</h2>
      <div class="banner">Tracking ID: <code>${htmlenc(tid)}</code></div>
      <p>${delay > 0 ? `Response delayed ${delay/1000}s — time-based injection detected.` : 'Response returned immediately.'}</p>
      <p><strong>${welcome ? 'Welcome back!' : 'Tracking ID does not exist.'}</strong></p>
      <form method="GET"><input type="text" name="trackingId" placeholder="Enter tracking ID" value="${htmlenc(tid)}"><button>Submit</button></form>
      ${solvedFinal ? okMsg('You used a time-based blind injection to confirm data.') : ''}`), solved: solvedFinal };
  }
};

// ---------- XSS ----------
const xss = {
  async reflected(req, url) { // xss-1
    const q = url.searchParams.get('q') || '';
    let solved = false;
    if (/<script>/i.test(q) || /<img[^>]+onerror/i.test(q) || /onerror\s*=\s*alert/i.test(q)) solved = true;
    return { body: html(`
      <h2>Search</h2>
      <form method="GET"><div class="row"><input type="text" name="q" placeholder="Search the site" value="${htmlenc(q)}"><button>Search</button></div></form>
      <h3>Search results for: <span style="color:#b31d28">${q}</span></h3>
      <p class="muted">No results found for your query.</p>
      ${solved ? okMsg('Reflected XSS confirmed — your payload is echoed unencoded into the page.') : ''}`), solved };
  },

  async dom(req, url) { // xss-3 DOM XSS via location.hash
    return { body: html(`
      <h2>Blog search</h2>
      <div class="banner">The page reads the <code>location.hash</code> and writes it into the page with <code>innerHTML</code>.</div>
      <p>Search term (from URL hash): <span id="term"></span></p>
      <script>
        var hash = location.hash.slice(1);
        document.getElementById('term').innerHTML = hash;
        function win() { try { top.postMessage('academy-solved:xss-3', '*'); } catch (e) {} }
      </script>
      <p class="muted">Change the hash in the iframe's address to inject HTML that runs <code>win()</code>.</p>`), solved: false };
  },

  async reflectedAttr(req, url) { // xss-4
    const q = url.searchParams.get('q') || '';
    let solved = false;
    if (/"\s*on\w+\s*=/i.test(q) || /"><script>/i.test(q) || /onmouseover/i.test(q) || /onfocus/i.test(q)) solved = true;
    return { body: html(`
      <h2>Search</h2>
      <form method="GET"><div class="row"><input type="text" name="q" placeholder="Search the site" value="${htmlenc(q)}"><button>Search</button></div></form>
      <h3>Search results for ${q}</h3>
      <p class="muted">Input is reflected inside an HTML <code>h1</code> and an <code>input value</code> attribute.</p>
      ${solved ? okMsg('Reflected XSS confirmed via attribute breakout / event handler.') : ''}`), solved };
  },

  async reflectedFiltered(req, url) { // xss-6 angle brackets encoded
    const q = url.searchParams.get('q') || '';
    // angle brackets are HTML-encoded, but the value lands inside an <h1> with an attribute-like context
    let solved = false;
    if (/onmouseover|onfocus|onclick/i.test(q) && /"\s*on/i.test(q)) solved = true;
    const echoed = htmlenc(q);
    return { body: html(`
      <h2>Search</h2>
      <form method="GET"><div class="row"><input type="text" name="q" placeholder="Search" value="${htmlenc(q)}"><button>Search</button></div></form>
      <h3>Results for: <span id="term" onclick="document.title='results'">${echoed}</span></h3>
      <p class="muted">Angle brackets (<code>&lt;</code> / <code>&gt;</code>) are HTML-encoded. Try breaking out of the attribute.</p>
      ${solved ? okMsg('XSS confirmed via event-handler injection in an attribute context.') : ''}`), solved };
  },

  async reflectedJs(req, url) { // xss-7 into JS string
    const q = url.searchParams.get('q') || '';
    let solved = false;
    if (/<\/script>/i.test(q) || (/';/.test(q) && /alert|print/i.test(q)) || /[`;]\s*alert/i.test(q)) solved = true;
    return { body: html(`
      <h2>Search</h2>
      <form method="GET"><div class="row"><input type="text" name="q" placeholder="Search" value="${htmlenc(q)}"><button>Search</button></div></form>
      <h3>Results for your search</h3>
      <script>
        var searchTerms = '${q.replace(/'/g, "\\'")}';
        document.getElementById ? null : null;
        document.title = 'Search: ' + searchTerms;
      </script>
      <p class="muted">Your input is placed inside a JavaScript string. Backslashes are filtered, angle brackets are not.</p>
      ${solved ? okMsg('XSS confirmed — you escaped the JS string / closed the script block.') : ''}`), solved };
  },

  async stored(req, url) { // xss-2
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const author = p.author || 'anonymous', comment = p.comment || '';
      let solved = false;
      if (/<script>/i.test(comment) || /onerror\s*=/i.test(comment)) solved = true;
      const c = { author, comment, id: Date.now() };
      comments.push(c);
      return { body: html(storedPage(c), { title: 'Comments' }), solved };
    }
    return { body: html(storedPage(null), { title: 'Comments' }) };
  },

  async storedImg(req, url) { // xss-5 stored onerror in img
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const author = p.author || 'anonymous', comment = p.comment || '';
      let solved = false;
      // allows <img> tags but strips <script>
      const cleaned = comment.replace(/<script[\s\S]*?<\/script>/gi, '');
      if (/onerror\s*=/i.test(cleaned) && /<img/i.test(cleaned)) solved = true;
      comments.push({ author, comment: cleaned, id: Date.now() });
      return { body: html(storedPage(comments[comments.length - 1]), { title: 'Comments' }), solved };
    }
    return { body: html(storedPage(null), { title: 'Comments' }) };
  }
};

let comments = [];
function storedPage(last) {
  return `
  <h2>Comment section</h2>
  <div class="banner">Comments are stored and re-rendered. Check what HTML tags are allowed.</div>
  <form method="POST" class="card">
    <input type="text" name="author" placeholder="Your name">
    <textarea name="comment" placeholder="Your comment"></textarea>
    <button type="submit">Post comment</button>
  </form>
  <h3>Comments</h3>
  <div class="card">
    ${comments.length === 0 ? '<p class="muted">No comments yet.</p>' : ''}
    ${comments.slice(-20).reverse().map(c => `
      <div style="border-bottom:1px solid #eee;padding:8px 0">
        <strong>${htmlenc(c.author)}</strong>:
        <div>${c.comment}</div>
      </div>`).join('')}
    ${last ? okMsg('Comment posted. If it contains executable markup, it is stored XSS.') : ''}
  </div>`;
}

// ---------- CSRF ----------
const csrf = {
  changeEmailPage(req, url, { tokenRequired = false, tokenValid = true, methodRestrict = null, refererRequired = false } = {}) {
    const email = url.searchParams.get('email') || '';
    return html(`
      <h2>My Account</h2>
      <div class="banner">Update your email address. This is the state-changing action an attacker would target.</div>
      <div class="card">
        <p>Current email: <strong>${email || 'wiener@normal-user.net'}</strong></p>
        <form method="POST" action="/lab/${url.pathname.split('/')[2]}/email">
          ${tokenRequired ? '<input type="hidden" name="csrf" value="REAL_TOKEN_HERE">' : ''}
          <input type="email" name="email" placeholder="New email address">
          <button type="submit">Update email</button>
        </form>
      </div>
      <p class="muted">Tip: think about whether a CSRF token is present, checked, tied to the session, and tied to the method.</p>`);
  },

  async noToken(req, url) { // csrf-1
    if (req.method === 'POST' && url.pathname.endsWith('/email')) {
      const p = await bodyParams(req);
      const email = p.email || '';
      if (!email) return { body: html('<div class="err">Missing email</div><a class="link" href="/lab/csrf-1">Back</a>') };
      // NO CSRF token present on the form/server at all
      return { body: html(`
        <h2>My Account</h2>
        <div class="ok">Email updated to <strong>${htmlenc(email)}</strong>. No CSRF token was required.</div>
        <p class="muted">An attacker could host this form on their own site and auto-submit it against a victim — the browser would send the victim's session cookie.</p>
        <a class="link" href="/lab/csrf-1">Back</a>`), solved: true };
    }
    return { body: csrf.changeEmailPage(req, url, { tokenRequired: false }) };
  },

  async fakeToken(req, url) { // csrf-2 token present but NOT validated
    if (req.method === 'POST' && url.pathname.endsWith('/email')) {
      const p = await bodyParams(req);
      const email = p.email || '';
      if (!email) return { body: html('<div class="err">Missing email</div>') };
      // token is sent by the form but the server NEVER checks it
      return { body: html(`
        <h2>My Account</h2>
        <div class="ok">Email updated to <strong>${htmlenc(email)}</strong>.</div>
        <p class="muted">Notice: the form includes a <code>csrf</code> field, but the server accepted this request regardless of its value.</p>
        <a class="link" href="/lab/csrf-2">Back</a>`), solved: true };
    }
    return { body: csrf.changeEmailPage(req, url, { tokenRequired: true }) };
  },

  async getMethod(req, url) { // csrf-3 state change on GET
    const email = url.searchParams.get('email');
    if (email) {
      return { body: html(`
        <h2>My Account</h2>
        <div class="ok">Email updated to <strong>${htmlenc(email)}</strong>.</div>
        <p class="muted">The email change happened on a <strong>GET</strong> request — no CSRF token possible, trivially exploitable with <code>&lt;img src="/lab/csrf-3/email?email=evil@x.com"&gt;</code>.</p>
        <a class="link" href="/lab/csrf-3">Back</a>`), solved: true };
    }
    return { body: html(`
      <h2>My Account</h2>
      <div class="banner">The email update endpoint is reachable via GET.</div>
      <div class="card"><p>Current email: <strong>wiener@normal-user.net</strong></p>
      <form method="GET"><input type="email" name="email" placeholder="New email"><button>Update</button></form></div>
      <p class="muted">Try changing your email directly in the URL: <code>/lab/csrf-3?email=test@x.com</code></p>`), solved: false };
  },

  async referer(req, url) { // csrf-4 Referer validation (missing header = accepted)
    if (req.method === 'POST' && url.pathname.endsWith('/email')) {
      const p = await bodyParams(req);
      const email = p.email || '';
      const referer = req.headers.get('referer');
      // Vulnerable: only rejects when Referer present AND from a different origin.
      // When Referer header is missing entirely -> accepted.
      const missing = !referer;
      const sameOrigin = referer && referer.startsWith(url.origin);
      if (email && (missing || sameOrigin)) {
        return { body: html(`
          <h2>My Account</h2>
          <div class="ok">Email updated to <strong>${htmlenc(email)}</strong>.</div>
          <p class="muted">Referer check: header was ${missing ? 'MISSING (accepted!)' : 'present and matching'}. An attacker uses <code>&lt;meta name="referrer" content="no-referrer"&gt;</code> to strip the header.</p>
          <a class="link" href="/lab/csrf-4">Back</a>`), solved: true };
      }
      return { body: html(`<h2>My Account</h2><div class="err">Request rejected: cross-origin Referer.</div><a class="link" href="/lab/csrf-4">Back</a>`), solved: false };
    }
    return { body: csrf.changeEmailPage(req, url, { tokenRequired: true }) };
  },

  async methodRestricted(req, url) { // csrf-5 token only checked for POST + form content-type
    const isForm = (req.headers.get('content-type') || '').includes('application/x-www-form-urlencoded');
    if (url.pathname.endsWith('/email')) {
      const p = await bodyParams(req);
      const email = p.email || '';
      if (req.method === 'POST' && isForm) {
        // token checked here (absent/invalid -> reject)
        if (p.csrf !== 'REAL_TOKEN_HERE') {
          return { body: html(`<h2>My Account</h2><div class="err">Invalid CSRF token.</div><a class="link" href="/lab/csrf-5">Back</a>`), solved: false };
        }
        return { body: html(`<h2>My Account</h2><div class="ok">Email updated (token valid).</div>`) };
      }
      // POST with non-form content-type -> token NOT checked
      if (req.method === 'POST' && !isForm) {
        return { body: html(`
          <h2>My Account</h2>
          <div class="ok">Email updated to <strong>${htmlenc(email)}</strong>.</div>
          <p class="muted">Sent with <code>Content-Type: application/json</code> — the CSRF token check was skipped because it only runs for form-urlencoded requests.</p>
          <a class="link" href="/lab/csrf-5">Back</a>`), solved: true };
      }
    }
    return { body: csrf.changeEmailPage(req, url, { tokenRequired: true }) };
  }
};

// ---------- Clickjacking ----------
const cj = {
  iframePage(title, content, opts = {}) {
    return html(`
      <h2>${title}</h2>
      ${opts.banner || ''}
      <div class="card">${content}</div>
      <p class="muted">The lab page is designed to be loaded inside an iframe by an attacker's site.</p>`);
  },

  async basic(req, url) { // cj-1 no X-Frame-Options
    return { body: html(`
      <h2>My Account</h2>
      <div class="banner">This page has NO X-Frame-Options and no CSP frame-ancestors.</div>
      <div class="card">
        <p>Account: wiener</p>
        <form method="POST" action="/lab/cj-1/delete">
          <button style="background:#d73a49">Delete account</button>
        </form>
      </div>
      <p class="muted">Load this page in a <code>&lt;iframe&gt;</code> from another origin. It renders — that's clickjacking.</p>`), solved: false };
  },

  async deletePost(req, url) { // cj-1 confirm
    return { body: html(`<h2>Account deleted</h2><div class="ok">The 'Delete account' button was successfully triggered through a transparent overlay — classic clickjacking.</div>
      <script>try { top.postMessage('academy-solved:cj-1', '*'); } catch (e) {}</script>`), solved: false };
  },

  async frameBusting(req, url) { // cj-2 frame busting present -> bypass with sandbox
    return { body: html(`
      <h2>Admin</h2>
      <div class="banner">This page uses frame-busting JavaScript: <code>if (top != self) top.location = self.location</code>.</div>
      <div class="card">
        <p>Restricted admin action</p>
        <form method="POST" action="/lab/cj-2/approve"><button>Approve request</button></form>
      </div>
      <script>if (top != self) top.location = self.location;</script>
      <p class="muted">To defeat the frame-buster, load it in an iframe WITHOUT scripts: <code>&lt;iframe sandbox="allow-forms" src="...">&lt;/iframe&gt;</code></p>`), solved: false };
  },

  async approvePost(req, url) {
    return { body: html(`<h2>Request approved</h2><div class="ok">Action performed through a sandboxed iframe (frame-busting bypassed).</div>
      <script>try { top.postMessage('academy-solved:cj-2', '*'); } catch (e) {}</script>`), solved: false };
  },

  async prefill(req, url) { // cj-3 form pre-filling
    const email = url.searchParams.get('email') || 'wiener@normal-user.net';
    return { body: html(`
      <h2>Update email</h2>
      <div class="banner">The email field can be pre-filled via the <code>email</code> query parameter.</div>
      <div class="card">
        <form method="POST" action="/lab/cj-3/update">
          <input type="email" name="email" value="${htmlenc(email)}">
          <button>Save</button>
        </form>
      </div>
      <p class="muted">Combine a pre-filled value with an invisible overlay button to silently submit.</p>`), solved: false };
  },

  async updatePost(req, url) {
    const p = await bodyParams(req);
    return { body: html(`<h2>Saved</h2><div class="ok">Email updated to ${htmlenc(p.email || '')} — a prefilled clickjacking form can do this without the victim noticing.</div>
      <script>try { top.postMessage('academy-solved:cj-3', '*'); } catch (e) {}</script>`), solved: false };
  }
};

// ---------- Path traversal ----------
const pt = {
  notesPage(title, msg, note, opts = {}) {
    return html(`
      <h2>${title}</h2>
      <div class="banner">Files are served from <code>${opts.base || '/var/www/images/'}</code> using <code>?filename=...</code></div>
      <div class="card">
        <p>Available files: <a class="link" href="?filename=${opts.base || '/var/www/images/'}welcome.txt">welcome.txt</a> | <a class="link" href="?filename=${opts.base || '/var/www/images/'}secret.txt">secret.txt</a></p>
        <form method="GET"><input type="text" name="filename" placeholder="filename" value="${htmlenc(opts.value || '')}"><button>Read file</button></form>
        ${msg || ''}
        ${note ? `<div style="background:#f6f8fa;border:1px solid #e1e4e8;padding:10px;border-radius:4px;white-space:pre-wrap;font-family:monospace;font-size:12px">${note}</div>` : ''}
      </div>`);
  },

  async simple(req, url) { // pt-1
    const fn = url.searchParams.get('filename');
    let msg = '', note = '', solved = false;
    if (fn) {
      if (fn.includes('..')) {
        solved = true;
        msg = okMsg('Path traversal! You escaped the images directory.');
        note = FAKE_PASSWD;
      } else if (fn.includes('welcome.txt')) note = 'Welcome to the academy.';
      else if (fn.includes('secret.txt')) note = 'secret=academy-flag-{pt1}';
      else { msg = errMsg('File not found'); }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: fn })), solved };
  },

  async absolute(req, url) { // pt-2
    const fn = url.searchParams.get('filename');
    let msg = '', note = '', solved = false;
    if (fn) {
      if (/^\/(etc|var|home|windows)/i.test(fn)) {
        solved = true; msg = okMsg('Absolute path accepted — no traversal needed.'); note = FAKE_PASSWD;
      } else if (fn.includes('welcome.txt')) note = 'Welcome to the academy.';
      else { msg = errMsg('File not found'); }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: fn })), solved };
  },

  async stripOnce(req, url) { // pt-3 strips ../ once
    const raw = url.searchParams.get('filename');
    let fn = raw;
    let msg = '', note = '', solved = false;
    if (fn) {
      // app strips "../" once (non-recursively)
      fn = fn.replace(/\.\.\//g, '');
      if (fn.includes('..')) {
        // traversal still possible via nested: ....// -> ../ after one strip
        if (raw.includes('....//') && fn.includes('../')) {
          solved = true; msg = okMsg('Bypassed the "../" filter with nested traversal: <code>....//....//etc/passwd</code>.'); note = FAKE_PASSWD;
        } else {
          solved = true; msg = okMsg('Traversal succeeded.'); note = FAKE_PASSWD;
        }
      } else if (fn.includes('welcome.txt')) note = 'Welcome to the academy.';
      else { msg = errMsg('File not found'); }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: raw })), solved };
  },

  async doubleEncode(req, url) { // pt-4 double URL encoding
    const raw = url.searchParams.get('filename');
    let msg = '', note = '', solved = false;
    if (raw) {
      // server URL-decodes once; app decodes again -> %252e%252e%252f = ../ 
      const once = decodeURIComponent(raw);
      const twice = decodeURIComponent(once);
      if (twice.includes('..') && /%2e%2e%2f/i.test(raw)) {
        solved = true; msg = okMsg('Double-encoded traversal worked: <code>%252e%252e%252f</code>.'); note = FAKE_PASSWD;
      } else if (raw.includes('..')) {
        msg = errMsg('Blocked: traversal sequences are filtered (single-encoding was decoded and blocked).');
      } else if (raw.includes('welcome.txt')) note = 'Welcome to the academy.';
      else { msg = errMsg('File not found'); }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: raw })), solved };
  },

  async startOfPath(req, url) { // pt-5 requires /var/www/images/ prefix
    const raw = url.searchParams.get('filename');
    let msg = '', note = '', solved = false;
    if (raw) {
      if (raw.startsWith('/var/www/images/')) {
        const rest = raw.slice('/var/www/images/'.length);
        if (rest.includes('..')) {
          solved = true; msg = okMsg('You navigated up from the allowed base path.'); note = FAKE_PASSWD;
        } else if (rest.includes('welcome.txt')) note = 'Welcome to the academy.';
        else { msg = errMsg('File not found'); }
      } else {
        msg = errMsg('Path must start with /var/www/images/');
      }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: raw })), solved };
  },

  async nullByte(req, url) { // pt-6 null byte truncation
    const raw = url.searchParams.get('filename');
    let msg = '', note = '', solved = false;
    if (raw) {
      const truncated = raw.split('\x00')[0];
      if ((raw.includes('\x00') || raw.includes('%00')) && truncated.includes('..')) {
        solved = true; msg = okMsg('Null byte truncated the appended .png — traversal succeeded.'); note = FAKE_PASSWD;
      } else if (raw.includes('welcome.txt')) note = 'Welcome to the academy.';
      else { msg = errMsg('File not found'); }
    }
    return { body: html(pt.notesPage('View file', msg, note, { value: raw })), solved };
  }
};

// ---------- Authentication ----------
const auth = {
  loginPage(title, extra = '') {
    return html(`
      <h2>${title}</h2>
      ${extra}
      <form method="POST" class="card">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button>Login</button>
      </form>`);
  },

  async enumErr(req, url) { // auth-1 username enumeration
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const u = p.username || '', pw = p.password || '';
      if (USERS[u]) {
        if (USERS[u].password === pw) {
          return { body: html(`<h2>Logged in</h2><div class="ok">Welcome, ${htmlenc(USERS[u].name)}.</div><a class="link" href="/lab/auth-1">Back</a>`), solved: true };
        }
        return { body: html(`<h2>Login</h2><div class="err">Incorrect password.</div><a class="link" href="/lab/auth-1">Back</a>`), solved: false };
      }
      return { body: html(`<h2>Login</h2><div class="err">Invalid username.</div><a class="link" href="/lab/auth-1">Back</a>`), solved: false };
    }
    return { body: auth.loginPage('Login', '<div class="banner">The error message differs between "wrong username" and "wrong password".</div>') };
  },

  async bruteIP(req, url) { // auth-2 X-Forwarded-For bypass
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const u = p.username || '', pw = p.password || '';
      // IP taken from X-Forwarded-For (spoofable) — trust boundary error
      const ip = req.headers.get('x-forwarded-for') || req.headers.get('cf-connecting-ip') || 'unknown';
      const fails = bruteFail.byIp.get(ip) || 0;
      if (fails >= 3) {
        return { body: html(`<h2>Blocked</h2><div class="err">Too many attempts from IP ${htmlenc(ip)}.</div><p class="muted">Hint: the app trusts the <code>X-Forwarded-For</code> header to identify you.</p>`), solved: false };
      }
      if (USERS[u] && USERS[u].password === pw) {
        bruteFail.byIp.delete(ip);
        return { body: html(`<h2>Logged in</h2><div class="ok">Welcome, ${htmlenc(USERS[u].name)}.</div>`), solved: true };
      }
      bruteFail.byIp.set(ip, fails + 1);
      return { body: html(`<h2>Login</h2><div class="err">Invalid credentials. (${fails+1}/3)</div><a class="link" href="/lab/auth-2">Back</a>`), solved: false };
    }
    return { body: auth.loginPage('Login', '<div class="banner">3 failed attempts locks your IP. The lock is keyed on <code>X-Forwarded-For</code>.</div>') };
  },

  async lockout(req, url) { // auth-3 account lockout + reset via valid login
    if (req.method === 'POST') {
      const p = await bodyParams(req);
      const u = p.username || '', pw = p.password || '';
      let fails = bruteFail.byUser.get(u) || 0;
      if (fails >= 5) {
        return { body: html(`<h2>Locked</h2><div class="err">Account ${htmlenc(u)} locked for 1 minute.</div><p class="muted">Hint: a <em>successful</em> login anywhere resets every lockout counter.</p>`), solved: false };
      }
      if (USERS[u] && USERS[u].password === pw) {
        bruteFail.byUser.clear(); // broken: any success resets all counters
        return { body: html(`<h2>Logged in</h2><div class="ok">Welcome, ${htmlenc(USERS[u].name)}.</div>`), solved: true };
      }
      bruteFail.byUser.set(u, fails + 1);
      return { body: html(`<h2>Login</h2><div class="err">Invalid credentials. (${fails+1}/5 for ${htmlenc(u)})</div>`), solved: false };
    }
    return { body: auth.loginPage('Login', '<div class="banner">5 failed attempts locks the account. Every successful login resets ALL lockouts.</div>') };
  },

  async userIdCookie(req, url) { // auth-4
    const c = (req.headers.get('cookie') || '');
    const m = c.match(/userId=(\d+)/);
    const uid = m ? m[1] : '1';
    if (uid === '1') {
      return { body: html(`<h2>My Account</h2><div class="card">User ID 1 (you): wiener — email wiener@normal-user.net</div>
        <p class="muted">Your identity comes from the <code>userId</code> cookie.</p>
        <p class="muted">Use devtools → Application → Cookies, or send the header manually.</p>`), solved: false };
    }
    if (uid === '2') {
      return { body: html(`<h2>My Account</h2><div class="ok">User ID 2: carlos — email carlos@normal-user.net. You accessed another user's account (IDOR).</div>`), solved: true };
    }
    if (uid === '3') {
      return { body: html(`<h2>Admin panel</h2><div class="ok">User ID 3 is administrator. You escalated access.</div>`), solved: true };
    }
    return { body: html(`<h2>User ${htmlenc(uid)}</h2><p class="muted">No such user.</p>`), solved: false };
  },

  async stayLoggedIn(req, url) { // auth-5 forged stay-logged-in cookie
    const c = (req.headers.get('cookie') || '');
    let solved = false, body = '';
    const m = c.match(/stayLoggedIn=([A-Za-z0-9+/=]+)/);
    if (m) {
      try {
        const dec = atob(m[1]);
        const [user, hash] = dec.split(':');
        if (user && hash && USERS[user]) {
          const target = await md5Hex(USERS[user].password);
          if (hash === target) {
            solved = true;
            body = html(`<h2>Logged in via stay-logged-in cookie</h2><div class="ok">Welcome, ${htmlenc(USERS[user].name)}. You forged/validated the remember-me cookie.</div>`);
          } else {
            body = html(`<h2>Invalid cookie</h2><div class="err">Hash mismatch.</div>`);
          }
        }
      } catch (e) { body = html(`<h2>Invalid cookie</h2><div class="err">Could not decode.</div>`); }
    } else {
      const forged = c.includes('stayLoggedIn') ? 'present' : 'absent';
      body = html(`<h2>Home</h2><div class="banner">Cookie format: base64(<code>username:md5(password)</code>).</div>
        <p class="muted">Set a forged cookie: <code>stayLoggedIn=${btoa('carlos:') + 'HASH'}</code>. Compute the md5 of a password from the wordlist.</p>`);
    }
    return { body, solved };
  },

  async twoFA(req, url) { // auth-6
    if (url.pathname.endsWith('/my-account') ) {
      // 2FA check is ONLY on the code page, not the account page -> direct access bypass
      return { body: html(`<h2>My Account</h2><div class="ok">Welcome, carlos. You reached the account page <em>without</em> supplying a 2FA code.</div>
        <p class="muted">The 2FA gate only guards the /my-account URL after login via the code form — but the account page itself never checks it.</p>`), solved: true };
    }
    if (url.pathname.endsWith('/login')) {
      const p = await bodyParams(req);
      const u = p.username || '', pw = p.password || '';
      if (USERS[u] && USERS[u].password === pw) {
        return { body: html(`<h2>2FA</h2><div class="card">Enter the 6-digit code sent to your phone.</div>
          <form method="GET"><input type="text" name="code" placeholder="Code"><button>Verify</button></form>
          <p class="muted">After verifying (or not!), go straight to <a class="link" href="/lab/auth-6/my-account">/lab/auth-6/my-account</a>.</p>`), solved: false };
      }
      return { body: html(`<h2>Login</h2><div class="err">Invalid credentials.</div><a class="link" href="/lab/auth-6">Back</a>`) };
    }
    return { body: auth.loginPage('Login', '<div class="banner">Login normally, then the 2FA step follows. Question: is the account page itself protected?</div>') };
  }
};

// Pure-JS MD5 (WebCrypto does not support MD5 in Node or Workers; no Buffer dependency).
// Compact public-domain algorithm.
function md5Hex(input) {
  const str = unescape(encodeURIComponent(input));
  let i, j, k, aa, bb, cc, dd;
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391];
  let M = new Array(16).fill(0), a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const len = str.length;
  M = new Array(Math.ceil((len + 9) / 64) * 16).fill(0);
  for (i = 0; i < len; i++) M[i >> 2] |= (str.charCodeAt(i) << ((i % 4) * 8));
  M[len >> 2] |= 0x80 << ((len % 4) * 8);
  M[(((len + 8) >> 6) << 4) + 14] = (len * 8) & 0xffffffff;
  M[(((len + 8) >> 6) << 4) + 15] = Math.floor((len * 8) / 0x100000000);
  function rotl(x, c) { return (x << c) | (x >>> (32 - c)); }
  const F = (x, y, z) => (x & y) | (~x & z);
  const G = (x, y, z) => (x & z) | (y & ~z);
  const H = (x, y, z) => x ^ y ^ z;
  const I = (x, y, z) => y ^ (x | ~z);
  let a = a0, b = b0, c = c0, d = d0;
  const g = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
    5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
    0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9];
  for (i = 0; i < M.length; i += 16) {
    aa = a; bb = b; cc = c; dd = d;
    for (j = 0; j < 64; j++) {
      let f, gIdx;
      if (j < 16) { f = F(b, c, d); gIdx = j; }
      else if (j < 32) { f = G(b, c, d); gIdx = (5 * j + 1) % 16; }
      else if (j < 48) { f = H(b, c, d); gIdx = (3 * j + 5) % 16; }
      else { f = I(b, c, d); gIdx = (7 * j) % 16; }
      const tmp = d;
      d = c; c = b;
      b = (b + rotl((a + f + K[j] + (M[i + gIdx] >>> 0)) >>> 0, S[j])) >>> 0;
      a = tmp;
    }
    a = (a + aa) >>> 0; b = (b + bb) >>> 0; c = (c + cc) >>> 0; d = (d + dd) >>> 0;
  }
  const hex = (x) => [x, x >>> 8, x >>> 16, x >>> 24].map((b) => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
  return hex(a) + hex(b) + hex(c) + hex(d);
}

// ---------- Access control ----------
const access = {
  async unprotAdmin(req, url) { // ac-1
    if (url.pathname.endsWith('/admin')) {
      return { body: html(`
        <h2>Admin panel</h2>
        <div class="ok">You accessed the admin panel — there is no access control at all.</div>
        <table><tr><th>Action</th><th></th></tr><tr><td>Delete user carlos</td><td><button>Delete</button></td></tr></table>
        <p class="muted">Navigate to <code>/lab/ac-1/admin</code> — no authentication or authorization is enforced.</p>`), solved: true };
    }
    return { body: html(`<h2>Home</h2><p>Welcome to the shop.</p><p class="muted">Try <a class="link" href="/lab/ac-1/admin">/lab/ac-1/admin</a></p>`) };
  },

  async hiddenAdmin(req, url) { // ac-2
    if (url.pathname.endsWith('/administrator-panel')) {
      return { body: html(`<h2>Admin panel</h2><div class="ok">Hidden URL found and accessed.</div>
        <table><tr><th>User</th><th>Action</th></tr><tr><td>carlos</td><td><button>Delete</button></td></tr></table>`), solved: true };
    }
    if (url.pathname.endsWith('/robots.txt')) {
      return { body: 'User-agent: *\nDisallow: /administrator-panel', contentType: 'text/plain', solved: false };
    }
    return { body: html(`<h2>Home</h2><p>Welcome to the shop.</p><p class="muted">Admin functionality exists but its URL is hidden. Check <code>/robots.txt</code>.</p>`) };
  },

  async idorUid(req, url) { // ac-3
    const uid = url.searchParams.get('uid') || '1';
    if (uid === '1') return { body: html(`<h2>My Account</h2><div class="card">wiener — ID 1</div><p class="muted">Try <code>?uid=2</code>.</p>`) };
    if (uid === '2') return { body: html(`<h2>My Account</h2><div class="ok">carlos — ID 2. You accessed another user's account via IDOR.</div>`), solved: true };
    return { body: html(`<h2>User ${htmlenc(uid)}</h2><p class="muted">No such user.</p>`) };
  },

  async idorEmailApi(req, url) { // ac-4
    if (url.pathname.endsWith('/api/change-email')) {
      if (req.method === 'POST') {
        const ct = req.headers.get('content-type') || '';
        const isJson = ct.includes('application/json');
        const p = isJson ? await req.json().catch(() => ({})) : await bodyParams(req);
        const uid = p.uid || '1';
        const email = p.email || '';
        if (String(uid) === '1') {
          return { body: JSON.stringify({ message: 'email updated for wiener', email }), contentType: 'application/json', solved: false };
        }
        if (String(uid) === '2') {
          return { body: JSON.stringify({ message: 'email updated for carlos (IDOR!)', email }), contentType: 'application/json', solved: true };
        }
        return { body: JSON.stringify({ error: 'invalid uid' }), contentType: 'application/json' };
      }
    }
    return { body: html(`
      <h2>My Account</h2>
      <div class="banner">Change your email via the API.</div>
      <div class="card">
        <p>wiener@normal-user.net</p>
        <form method="POST" action="/lab/ac-4/api/change-email" enctype="text/plain">
          <input type="text" name="email" placeholder="New email">
          <button>Change email</button>
        </form>
      </div>
      <p class="muted">The API accepts a <code>uid</code> field you control: POST JSON <code>{"email":"x","uid":2}</code>.</p>`) };
  },

  async methodBased(req, url) { // ac-5
    if (url.pathname.endsWith('/admin')) {
      if (req.method === 'POST') {
        return { body: html(`<h2>Admin panel</h2><div class="ok">You accessed admin via POST — the access check only applies to GET.</div>`), solved: true };
      }
      return { body: html(`<h2>Access denied</h2><div class="err">Admin functions are for administrators only (checked on GET).</div>`), solved: false };
    }
    return { body: html(`<h2>Home</h2><p class="muted">Try <code>/lab/ac-5/admin</code> with GET (denied) and POST (allowed).</p>`) };
  },

  async refererBased(req, url) { // ac-6
    if (url.pathname.endsWith('/admin')) {
      const ref = req.headers.get('referer') || '';
      if (ref.includes('/admin')) {
        return { body: html(`<h2>Admin panel</h2><div class="ok">Access granted because the Referer header contained /admin.</div>`), solved: true };
      }
      return { body: html(`<h2>Access denied</h2><div class="err">This action requires an admin Referer. (sent Referer: ${htmlenc(ref)})</div>`), solved: false };
    }
    return { body: html(`<h2>Home</h2><p class="muted">Try <code>/lab/ac-6/admin</code> with a forged <code>Referer</code> header.</p>`) };
  }
};

// ---------- render helpers ----------
const emptyTable = '<p class="muted">No products found.</p>';
function table(rows, extraRows) {
  if (!rows.length) return emptyTable;
  const all = [...rows, ...(extraRows || [])];
  let h = '<table><tr><th>Name</th><th>Category</th><th>Status</th></tr>';
  all.forEach(r => { h += `<tr><td>${htmlenc(r.name)}</td><td>${htmlenc(r.category)}</td><td>${r.released ? 'released' : 'UNRELEASED'}</td></tr>`; });
  return h + '</table>';
}
function okMsg(s) { return `<div class="ok">${s}</div>`; }
function errMsg(s) { return `<div class="err">${s}</div>`; }

// ============================================================
//  ROUTER
// ============================================================

// Lab registry: id -> handler function
const routes = {
  'sqli-1': (r, u) => sqli.sql1(r, u),
  'sqli-2': (r, u) => sqli.login(r, u),
  'sqli-3': (r, u) => sqli.sql3(r, u),
  'sqli-4': (r, u) => sqli.sql4(r, u),
  'sqli-5': (r, u) => sqli.blindBool(r, u),
  'sqli-6': (r, u) => sqli.blindTime(r, u),
  'xss-1': (r, u) => xss.reflected(r, u),
  'xss-2': (r, u) => xss.stored(r, u),
  'xss-3': (r, u) => xss.dom(r, u),
  'xss-4': (r, u) => xss.reflectedAttr(r, u),
  'xss-5': (r, u) => xss.storedImg(r, u),
  'xss-6': (r, u) => xss.reflectedFiltered(r, u),
  'xss-7': (r, u) => xss.reflectedJs(r, u),
  'csrf-1': (r, u) => csrf.noToken(r, u),
  'csrf-2': (r, u) => csrf.fakeToken(r, u),
  'csrf-3': (r, u) => csrf.getMethod(r, u),
  'csrf-4': (r, u) => csrf.referer(r, u),
  'csrf-5': (r, u) => csrf.methodRestricted(r, u),
  'cj-1': (r, u) => cj.basic(r, u),
  'cj-2': (r, u) => cj.frameBusting(r, u),
  'cj-3': (r, u) => cj.prefill(r, u),
  'pt-1': (r, u) => pt.simple(r, u),
  'pt-2': (r, u) => pt.absolute(r, u),
  'pt-3': (r, u) => pt.stripOnce(r, u),
  'pt-4': (r, u) => pt.doubleEncode(r, u),
  'pt-5': (r, u) => pt.startOfPath(r, u),
  'pt-6': (r, u) => pt.nullByte(r, u),
  'auth-1': (r, u) => auth.enumErr(r, u),
  'auth-2': (r, u) => auth.bruteIP(r, u),
  'auth-3': (r, u) => auth.lockout(r, u),
  'auth-4': (r, u) => auth.userIdCookie(r, u),
  'auth-5': (r, u) => auth.stayLoggedIn(r, u),
  'auth-6': (r, u) => auth.twoFA(r, u),
  'ac-1': (r, u) => access.unprotAdmin(r, u),
  'ac-2': (r, u) => access.hiddenAdmin(r, u),
  'ac-3': (r, u) => access.idorUid(r, u),
  'ac-4': (r, u) => access.idorEmailApi(r, u),
  'ac-5': (r, u) => access.methodBased(r, u),
  'ac-6': (r, u) => access.refererBased(r, u)
};

Object.assign(routes, extraRoutes);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = url.origin;
    const reqOrigin = request.headers.get('Origin') || '';

    const cors = (extra = {}) => ({
      'Access-Control-Allow-Origin': reqOrigin || '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Cookie, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Scheme, Host, Origin, Referer, stayLoggedIn, userId, Authorization',
      'Access-Control-Expose-Headers': 'x-lab-solved, Set-Cookie, Location, Content-Type, Date, Server',
      'Cache-Control': 'no-store',
      ...extra
    });

    if (request.method === 'OPTIONS') {
      return new Response('', { status: 204, headers: cors() });
    }

    // ---- API: status check ----
    const st = url.pathname.match(/^\/api\/status\/([\w-]+)$/);
    if (st) {
      return new Response(JSON.stringify({ labId: st[1], solved: isSolved(request, st[1]) }), { headers: cors({ 'Content-Type': 'application/json' }) });
    }
    // ---- API: mark solved (client-side labs e.g. clickjacking/DOM) ----
    const mk = url.pathname.match(/^\/api\/mark\/([\w-]+)$/);
    if (mk) {
      const sid = markSolved(request, mk[1]);
      return new Response(JSON.stringify({ solved: true }), { headers: cors({ 'Content-Type': 'application/json', 'Set-Cookie': cookieSet(sid) }) });
    }
    // ---- API: request inspector (echo what the server actually received) ----
    if (url.pathname === '/api/reqinfo') {
      const hdrs = {};
      for (const [k, v] of request.headers.entries()) hdrs[k] = v;
      return new Response(JSON.stringify({
        method: request.method,
        path: url.pathname,
        query: url.search,
        ip: request.headers.get('CF-Connecting-IP') || '',
        headers: hdrs
      }), { headers: cors({ 'Content-Type': 'application/json' }) });
    }
    // ---- robots.txt ----
    if (url.pathname.endsWith('/robots.txt')) {
      return new Response('User-agent: *\nDisallow: /administrator-panel', { headers: cors({ 'Content-Type': 'text/plain' }) });
    }

    // ---- lab routes ----
    const m = url.pathname.match(/^\/lab\/([\w-]+)(\/.*)?$/);
    if (!m) {
      return new Response(html(`<h2>Academy lab backend</h2><p>This is the vulnerable lab app. Open a lab from the front-end platform.</p>
        <ul><li><a class="link" href="/lab/sqli-1">sqli-1</a></li><li><a class="link" href="/lab/xss-1">xss-1</a></li><li><a class="link" href="/lab/auth-1">auth-1</a></li><li><a class="link" href="/lab/ac-1/admin">ac-1 admin</a></li></ul>`), { headers: cors({ 'Content-Type': 'text/html' }) });
    }
    const id = m[1];
    const sub = m[2] || '';
    const handler = routes[id];
    if (!handler) {
      return new Response(html(`<h2>Unknown lab</h2><p>${htmlenc(id)} is not registered.</p>`), { headers: cors({ 'Content-Type': 'text/html' }) });
    }

    try {
      const res = await handler(request, url, sub);
      const headers = cors({ 'Content-Type': res.contentType || 'text/html' });
      if (res.location) {
        headers['Location'] = res.location;
      }
      if (res.solved) {
        const sid = markSolved(request, id);
        headers['x-lab-solved'] = 'true';
        headers['Set-Cookie'] = cookieSet(sid);
      }
      return new Response(res.body, { status: res.status || 200, headers });
    } catch (e) {
      return new Response(html(`<div class="err">Lab error: ${htmlenc(e.message)}</div>`), { headers: cors({ 'Content-Type': 'text/html' }) });
    }
  }
};