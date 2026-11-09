import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const secret = 'whsec_' + randomBytes(32).toString('base64');
const execFileAsync = promisify(execFile);

async function withReceiver(flags, fn) {
  const server = await startMock({ secret, ...flags });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('two signed IDs share one keep-alive socket; replay on a fresh socket stays deduplicated', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'keep_alive_connection_isolation');
    assert.deepEqual(probe.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3, 3, 3]);
    assert.equal(probe.sameSocketReused, true);
    assert.equal(probe.freshSocketUsed, true);
  });
});

test('detects receiver coalescing distinct signed requests on one keep-alive socket', async () => {
  await withReceiver({ unsafeCoalesceKeepAliveEvents: true }, async (config) => {
    const result = await runLab({ ...config, keepAliveConnectionIsolation: true }, { secret });
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.equal(result.success, false);
    assert.deepEqual(probe.observedCounts, [2, 2, 2, 3]);
  });
});

test('detects receiver rejecting a second independent event on one keep-alive socket', async () => {
  await withReceiver({ unsafeRejectNextKeepAliveEvent: true }, async (config) => {
    const result = await runLab({ ...config, keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 409, 200, 200]);
  });
});

test('detects receiver whose dedupe records exist only for the current TCP connection', async () => {
  await withReceiver({ unsafeConnectionScopedDedupe: true }, async (config) => {
    const result = await runLab({ ...config, keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3, 4]);
  });
});

test('detects receiver reprocessing signed replay on the reused connection', async () => {
  await withReceiver({ unsafeReprocessKeepAliveReplay: true }, async (config) => {
    const result = await runLab({ ...config, keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 4, 4]);
  });
});

test('invalid keep-alive option values fail before any HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const keepAliveConnectionIsolation of [null, 0, 1, 'true', [], {}]) {
      let sent = false;
      await assert.rejects(() => runLab({ ...config, keepAliveConnectionIsolation }, {
        secret, request: () => { sent = true; throw new Error('Unexpected HTTP'); },
      }), /keepAliveConnectionIsolation/);
      assert.equal(sent, false);
    }
  });
});

test('keep-alive connection isolation composes with HTTP method correction', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true,
      keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((s) => s.scenario),
      ['wrong_http_method_retry', 'keep_alive_connection_isolation']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 4, 4, 4]);
  });
});

test('CLI keep-alive report excludes synthetic IDs, HMAC and signing secret', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-keepalive-'));
    try {
      const file = join(directory, 'lab.json');
      await writeFile(file, JSON.stringify({ ...config, keepAliveConnectionIsolation: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).sameSocketReused, true);
      assert.equal(result.scenarios.at(-1).freshSocketUsed, true);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('wfl_keepalive_'));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
