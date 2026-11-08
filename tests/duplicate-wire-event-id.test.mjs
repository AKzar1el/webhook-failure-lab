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

const execFileAsync = promisify(execFile);
const secret = `whsec_${randomBytes(32).toString('base64')}`;

async function withReceiver(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('duplicate physical webhook-id fields are rejected before dedupe, then same-ID retry works', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireEventIdRetry: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_wire_event_id_retry');
    assert.deepEqual(report.httpStatuses, [400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects receiver choosing first authenticated webhook-id among duplicate wire fields', async () => {
  await withReceiver({ unsafeAcceptDuplicateWireEventId: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireEventIdRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects receiver poisoning ID cache after rejecting duplicate wire fields', async () => {
  await withReceiver({ unsafeCacheDuplicateWireEventId: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireEventIdRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects receiver committing effect before rejecting duplicate wire fields', async () => {
  await withReceiver({ unsafeCommitDuplicateWireEventIdBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireEventIdRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('duplicate wire event-ID option rejects non-boolean settings before requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateWireEventIdRetry of [0, 1, 'true', null, {}, []]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateWireEventIdRetry }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /rejectDuplicateWireEventIdRetry/);
      assert.equal(requested, false);
    }
  });
});

test('duplicate wire ID probe composes with missing-ID recovery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingEventIdRetry: true,
      rejectDuplicateWireEventIdRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['missing_event_id_retry', 'duplicate_wire_event_id_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3]);
  });
});

test('CLI reports duplicate physical wire IDs without exposing HMAC or signing secret', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-duplicate-wire-id-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, rejectDuplicateWireEventIdRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'duplicate_wire_event_id_retry');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
