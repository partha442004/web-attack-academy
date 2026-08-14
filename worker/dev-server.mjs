// Local dev server — wraps the Worker's `fetch` handler in a Node http server.
// Run:  node worker/dev-server.mjs [port]
import http from 'node:http';
import { createHash } from 'node:crypto';
import worker from './index.js';

globalThis.crypto ??= globalThis.crypto;

const PORT = Number(process.argv[2]) || 8787;

// Make crypto.subtle available (Node 24 has it globally already).
const server = http.createServer(async (req, res) => {
  const host = req.headers.host || `localhost:${PORT}`;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const rawUrl = req.url || '/';
  const fullUrl = `${proto}://${host}${rawUrl}`;

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(', ') : v);
  }

  let body = null;
  const method = req.method || 'GET';
  if (method !== 'GET' && method !== 'HEAD') {
    body = await new Promise((resolve) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  const request = new Request(fullUrl, {
    method,
    headers,
    body: body ? body : undefined,
  });

  try {
    const response = await worker.fetch(request, {});
    res.writeHead(response.status, Object.fromEntries(response.headers));
    const buf = Buffer.from(await response.arrayBuffer());
    res.end(buf);
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Dev server error: ' + e.message);
  }
});

server.listen(PORT, () => {
  console.log(`Academy backend running at http://localhost:${PORT}`);
});