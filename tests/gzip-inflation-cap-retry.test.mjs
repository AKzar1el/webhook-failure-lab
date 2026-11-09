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

test('signed gzip inflation exceeding 1024 bytes is rejected before a corrected compressed retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'oversized_gzip_retry');
    assert.deepEqual(report.httpStatuses, [413, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
    assert.equal(report.compressedBodyBelowLimit, true);
    assert.equal(report.inflatedBodyExceedsLimit, true);
  });
});

test('detects a receiver that accepts a compressed payload exceeding its inflated limit', async () => {
  await withReceiver({ unsafeAcceptOversizedGzip: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects a rejected gzip delivery that poisons the idempotency record', async () => {
  await withReceiver({ unsafeCacheOversizedGzip: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [413, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects a receiver that records an effect before rejecting the inflated gzip body', async () => {
  await withReceiver({ unsafeCommitOversizedGzipBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [413, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('receiver missing the explicitly declared decompressed-size policy fails', async () => {
  await withReceiver({ supportGzipInflationCap: false }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('gzip inflation flag validates before contacting the local receiver', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectOversizedGzipRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectOversizedGzipRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectOversizedGzipRetry/);
      assert.equal(called, false);
    }
  });
});

test('gzip inflation cap composes with ordinary signed oversized-body rejection', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true,
      rejectOversizedGzipRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((x) => x.scenario),
      ['oversized_signed_payload_retry', 'oversized_gzip_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3]);
  });
});

test('CLI exposes gzip inflation cap verdict without leaking signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-gzip-cap-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectOversizedGzipRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'oversized_gzip_retry');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
