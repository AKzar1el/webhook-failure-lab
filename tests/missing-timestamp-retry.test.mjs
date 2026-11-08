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

test('missing signed timestamp rejects without poisoning corrected same-ID delivery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'missing_timestamp_retry');
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects receiver that accepts missing timestamp with a valid HMAC header', async () => {
  await withReceiver({ unsafeAcceptMissingTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('detects rejected missing timestamp that still reserves event ID', async () => {
  await withReceiver({ unsafeCacheMissingTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects effect committed before missing timestamp rejection', async () => {
  await withReceiver({ unsafeCommitMissingTimestampBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing timestamp opt-in rejects non-boolean flags before HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectMissingTimestampRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectMissingTimestampRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected network request'); },
      }), /rejectMissingTimestampRetry/);
      assert.equal(called, false);
    }
  });
});

test('missing timestamp check composes with missing signature retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true,
      rejectMissingSignatureRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'missing_signature_retry')
      .observedCounts, [1, 2, 2]);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'missing_timestamp_retry')
      .observedCounts, [2, 3, 3]);
  });
});

test('CLI reports missing timestamp retry without leaking synthetic signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-missing-timestamp-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectMissingTimestampRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'missing_timestamp_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
