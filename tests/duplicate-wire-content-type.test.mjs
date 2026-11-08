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
const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('conflicting physical Content-Type headers reject in both orders before dedupe and allow corrected retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_wire_content_type_retry');
    assert.deepEqual(report.httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects first-wins parser accepting conflicting physical Content-Type headers', async () => {
  await withReceiver({ unsafeAcceptFirstDuplicateContentType: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 415, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2, 2]);
  });
});

test('detects last-wins parser accepting conflicting physical Content-Type headers', async () => {
  await withReceiver({ unsafeAcceptLastDuplicateContentType: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [415, 200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2, 2]);
  });
});

test('detects rejected physical Content-Type headers that poison the deduplication cache', async () => {
  await withReceiver({ unsafeCacheDuplicateContentType: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1, 1]);
  });
});

test('detects a receiver that commits before rejecting duplicate Content-Type headers', async () => {
  await withReceiver({ unsafeCommitDuplicateContentTypeBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3, 3]);
  });
});

test('duplicate physical Content-Type option validates booleans before network requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateWireContentTypeRetry of [0, 1, 'true', null, {}, []]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateWireContentTypeRetry }, {
        secret, request: () => { requested = true; throw new Error('unexpected request'); },
      }), /rejectDuplicateWireContentTypeRetry/);
      assert.equal(requested, false);
    }
  });
});

test('physical Content-Type ambiguity check composes with duplicate signed signature headers', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config,
      rejectDuplicateWireSignatureRetry: true, rejectDuplicateWireContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['duplicate_wire_signature_retry', 'duplicate_wire_content_type_retry']);
    assert.deepEqual(result.scenarios.at(-2).observedCounts, [1, 1, 2, 2]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 3, 3]);
  });
});

test('CLI exposes duplicate physical Content-Type failure evidence without secrets or headers', async () => {
  await withReceiver({ unsafeAcceptFirstDuplicateContentType: true }, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-duplicate-ctype-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, rejectDuplicateWireContentTypeRetry: true }));
      await assert.rejects(() => execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } }),
      (error) => {
        assert.equal(error.code, 1);
        const result = JSON.parse(error.stdout);
        assert.equal(result.success, false);
        assert.equal(result.scenarios.at(-1).scenario, 'duplicate_wire_content_type_retry');
        assert.ok(!error.stdout.includes(secret));
        assert.ok(!error.stdout.includes('webhook-signature'));
        assert.ok(!error.stdout.includes('wfl_dupctype_'));
        return true;
      });
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
