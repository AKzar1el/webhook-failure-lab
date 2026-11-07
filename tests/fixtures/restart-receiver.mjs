// A deliberately isolated, synthetic webhook receiver used only by local restart tests.
import { randomUUID } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { verify } from '../../src/standard.mjs';

const statePath = process.env.WFL_TEST_STATE_PATH;
const secret = process.env.WFL_TEST_SECRET;
if (!statePath || !secret || typeof process.send !== 'function') {
  throw new Error('Restart receiver requires a synthetic key, state file and test IPC');
}

let persisted;
try {
  persisted = JSON.parse(await readFile(statePath, 'utf8'));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  persisted = { processedCount: 0, seenIds: [] };
}
if (!Number.isSafeInteger(persisted.processedCount) || persisted.processedCount < 0 ||
    !Array.isArray(persisted.seenIds) ||
    persisted.seenIds.some((id) => typeof id !== 'string')) {
  throw new Error('Invalid durable test state');
}

let processedCount = persisted.processedCount;
// This intentionally broken mode models losing dedupe keys while keeping the count.
const seen = new Set(process.env.WFL_TEST_FORGET_DEDUPE === '1' ? [] : persisted.seenIds);
const receiverInstanceId = `${process.pid}:${randomUUID()}`;

async function persist({ omitSeenId, omitCount = false } = {}) {
  const staged = `${statePath}.${process.pid}.tmp`;
  await writeFile(staged, JSON.stringify({
    processedCount: processedCount - (omitCount ? 1 : 0),
    seenIds: [...seen].filter((id) => id !== omitSeenId),
  }), { flag: 'w' });
  await rename(staged, statePath);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/state') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ processedCount, receiverInstanceId }));
      return;
    }
    if (req.method !== 'POST' || url.pathname !== '/webhook') {
      res.writeHead(404); res.end(); return;
    }
    let body = '';
    for await (const chunk of req) {
      body += chunk.toString('utf8');
      if (body.length > 65536) {
        res.writeHead(413); res.end(); return;
      }
    }
    const id = req.headers['webhook-id'];
    const valid = verify({
      secret, id, timestamp: Number(req.headers['webhook-timestamp']), body,
      signature: req.headers['webhook-signature'], tolerance: 300,
    });
    if (!valid) { res.writeHead(401); res.end(); return; }
    if (req.headers['x-wfl-test-fault'] === 'persist-then-crash-before-ack' &&
        typeof id === 'string' && id.startsWith('wfl_crash_') &&
        process.env.WFL_TEST_IGNORE_CRASH !== '1') {
      if (!seen.has(id)) {
        seen.add(id);
        processedCount++;
        // Broken fixtures drop one half of the atomic count/dedupe record.
        await persist({
          omitSeenId: process.env.WFL_TEST_CRASH_LOSE_DEDUPE === '1' ? id : undefined,
          omitCount: process.env.WFL_TEST_CRASH_LOSE_COUNT === '1',
        });
      }
      process.exit(47);
    }
    if (!seen.has(id)) {
      seen.add(id);
      processedCount++;
      // Both the effect counter and dedupe key are durable before acknowledging.
      await persist();
    }
    res.writeHead(200); res.end('accepted');
  } catch {
    res.writeHead(500); res.end('local fixture error');
  }
});

await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const base = `http://127.0.0.1:${server.address().port}`;
const startupDelayMs = Number(process.env.WFL_TEST_STARTUP_DELAY_MS ?? 0);
if (!Number.isSafeInteger(startupDelayMs) || startupDelayMs < 0 || startupDelayMs > 9000) {
  throw new Error('Invalid test-only receiver startup delay');
}
if (startupDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, startupDelayMs));
if (process.env.WFL_TEST_SUPPRESS_READY !== '1') {
  process.send({ type: 'ready', config: { endpoint: `${base}/webhook`, observer: `${base}/state` },
    receiverInstanceId });
}
process.on('message', (message) => {
  if (message?.type === 'shutdown') server.close(() => process.disconnect());
});
