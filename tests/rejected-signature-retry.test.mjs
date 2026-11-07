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

test('rejected invalid-HMAC first attempt leaves event ID available for valid retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'retry_after_rejected_signature');
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects rejected invalid signature poisoning the ID cache', async () => {
  await withReceiver({ unsafeCacheRejectedSignature: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('detects invalid HMAC rejected after an unwanted observed effect', async () => {
  await withReceiver({ unsafeCommitRejectedSignature: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('detects invalid signature being accepted as the first attempt', async () => {
  await withReceiver({ unsafeAcceptRejectedSignature: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('retryAfterRejectedSignature requires boolean before any HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const retryAfterRejectedSignature of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, retryAfterRejectedSignature }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /retryAfterRejectedSignature/);
      assert.equal(called, false);
    }
  });
});

test('invalid-signature recovery composes with precommit 503 retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterRejectedSignature: true,
      retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    const report = result.scenarios.find((item) => item.scenario === 'retry_after_rejected_signature');
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.equal(result.scenarios.at(-1).scenario, 'retry_after_transient_failure');
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 3);
  });
});

test('CLI exposes recovery verdict but never outputs the signing key or HMAC', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-rejected-signature-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, retryAfterRejectedSignature: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'retry_after_rejected_signature');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
