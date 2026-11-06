import { createServer } from 'node:http';
import { verify } from './standard.mjs';

export async function startMock({ secret, dedupe = true, verifySignatures = true,
  verifyFreshness = true, unsafeConcurrentDedupe = false, supportRetryFault = true,
  unsafeMarkFailedRetrySeen = false, supportLostAckFault = true,
  unsafeForgetLostAckDedupe = false } = {}) {
  const seen = new Set();
  const failedRetryIds = new Set();
  const lostAckIds = new Set();
  let processedCount = 0;
  const pendingRaces = new Map();
  function rendezvous(id) {
    return new Promise((resolve) => {
      let group = pendingRaces.get(id);
      if (!group) {
        group = { waiters: [], timer: null };
        pendingRaces.set(id, group);
        // Avoid leaving the local fixture hanging if fewer than four requests arrive.
        group.timer = setTimeout(() => release(), 1000);
      }
      function release() {
        if (pendingRaces.get(id) !== group) return;
        clearTimeout(group.timer);
        pendingRaces.delete(id);
        for (const waiter of group.waiters) waiter();
      }
      group.waiters.push(resolve);
      if (group.waiters.length === 4) release();
    });
  }
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
    if (supportRetryFault && req.headers['x-wfl-test-fault'] === 'reject-before-process-once' &&
        typeof id === 'string' && id.startsWith('wfl_retry_') && !failedRetryIds.has(id)) {
      failedRetryIds.add(id);
      // Broken fixture marks an event as handled even though it rejected the delivery.
      if (unsafeMarkFailedRetrySeen) seen.add(id);
      res.writeHead(503); res.end('synthetic pre-processing failure'); return;
    }
    if (supportLostAckFault && req.headers['x-wfl-test-fault'] === 'commit-then-drop-ack-once' &&
        typeof id === 'string' && id.startsWith('wfl_lostack_') && !lostAckIds.has(id)) {
      lostAckIds.add(id);
      if (!seen.has(id)) {
        processedCount += 1;
        // Broken fixture commits the effect but loses the corresponding dedupe record.
        if (!unsafeForgetLostAckDedupe) seen.add(id);
      }
      res.destroy();
      return;
    }
    const alreadySeen = seen.has(id);
    if (unsafeConcurrentDedupe && typeof id === 'string' && id.startsWith('wfl_race_')) {
      // Broken fixture: every concurrent request reads state before any write.
      await rendezvous(id);
    }
    if (!dedupe || !alreadySeen) { processedCount += 1; seen.add(id); }
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
