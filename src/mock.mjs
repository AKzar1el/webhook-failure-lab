import { createServer } from 'node:http';
import { verify } from './standard.mjs';

export async function startMock({ secret, dedupe = true, verifySignatures = true, verifyFreshness = true } = {}) {
  const seen = new Set();
  let processedCount = 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/state') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ processedCount }));
      return;
    }
    if (req.method !== 'POST' || url.pathname !== '/webhook') {
      res.writeHead(404); res.end(); return;
    }
    let body = '';
    for await (const chunk of req) {
      body += chunk.toString('utf8');
      if (body.length > 65536) { res.writeHead(413); res.end(); req.destroy(); return; }
    }
    const id = req.headers['webhook-id'];
    const ts = Number(req.headers['webhook-timestamp']);
    const accepted = verify({ secret, id, timestamp: ts, body, signature: req.headers['webhook-signature'],
      tolerance: verifyFreshness ? 300 : Number.POSITIVE_INFINITY });
    if (verifySignatures && !accepted) { res.writeHead(401); res.end(); return; }
    if (!dedupe || !seen.has(id)) { processedCount += 1; seen.add(id); }
    res.writeHead(200); res.end('accepted');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  return {
    config: { endpoint: `${base}/webhook`, observer: `${base}/state` },
    stop: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
