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

const secret = `whsec_${randomBytes(32).toString('base64')}`;
const execFileAsync = promisify(execFile);

async function withReceiver(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('missing HMAC header rejects without reserving a valid retry ID', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'missing_signature_retry');
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects receiver that accepts an event without an HMAC header', async () => {
  await withReceiver({ unsafeAcceptMissingSignature: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('detects receiver poisoning dedupe after missing signature rejection', async () => {
  await withReceiver({ unsafeCacheMissingSignature: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects observed effect before missing signature rejection', async () => {
  await withReceiver({ unsafeCommitMissingSignatureBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing signature opt-in rejects non-boolean settings before network access', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectMissingSignatureRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectMissingSignatureRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectMissingSignatureRetry/);
      assert.equal(called, false);
    }
  });
});

test('missing signature recovery composes with invalid-HMAC retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true,
      retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'missing_signature_retry')
      .observedCounts, [1, 2, 2]);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'retry_after_rejected_signature')
      .observedCounts, [2, 3, 3]);
  });
});

test('CLI reports missing-signature retry verdict without leaking signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-missing-hmac-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectMissingSignatureRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'missing_signature_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
