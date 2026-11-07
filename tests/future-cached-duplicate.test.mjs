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
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('future-dated re-signature of a cached event is rejected without another effect', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectFutureDuplicateSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'future_cached_duplicate_signature');
    assert.deepEqual(report.httpStatuses, [200, 401]);
    assert.deepEqual(report.observedCounts, [2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects an unsafe receiver that acknowledges a cached ID before future freshness', async () => {
  await withReceiver({ unsafeAcknowledgeFutureDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, rejectFutureDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
  });
});

test('detects a receiver that returns 401 only after an extra effect', async () => {
  await withReceiver({ unsafeCommitFutureDuplicateBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectFutureDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3]);
  });
});

test('future cached-ID probe fails when local freshness verification is disabled', async () => {
  await withReceiver({ verifyFreshness: false }, async (config) => {
    const result = await runLab({ ...config, rejectFutureDuplicateSignature: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200]);
  });
});

test('future cached-ID flag validates before any HTTP request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectFutureDuplicateSignature of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectFutureDuplicateSignature }, {
        secret, request: () => { called = true; throw new Error('Unexpected HTTP request'); },
      }), /rejectFutureDuplicateSignature/);
      assert.equal(called, false);
    }
  });
});

test('future cached-ID check composes with future-new-ID and stale-cached-ID probes', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectFutureDuplicateSignature: true,
      rejectFutureSignedTimestamp: true, rejectStaleDuplicateSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-3).map((item) => item.scenario),
      ['future_signed_timestamp', 'stale_cached_duplicate_signature',
        'future_cached_duplicate_signature']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('CLI reports future cached-ID rejection without disclosing synthetic signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-future-cached-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectFutureDuplicateSignature: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'future_cached_duplicate_signature');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
