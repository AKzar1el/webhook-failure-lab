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
const scenario = 'distinct_ids_identical_signed_body';
const reportOf = (result) => result.scenarios.find((item) => item.scenario === scenario);

async function withReceiver(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('distinct authenticated event IDs with byte-identical bodies each commit once, then replay safely', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, distinctIdsIdenticalBody: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.deepEqual(reportOf(result), {
      scenario, passed: true, httpStatuses: [200, 200, 200, 200],
      observedCounts: [2, 3, 3, 3], expectedProcessedCount: 3,
    });
  });
});

test('detects a receiver that incorrectly deduplicates different signed IDs by payload hash', async () => {
  await withReceiver({ unsafeDedupeByBodyHash: true }, async (config) => {
    const result = await runLab({ ...config, distinctIdsIdenticalBody: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 2, 2, 2]);
    assert.equal(reportOf(result).passed, false);
  });
});

test('detects a receiver that rejects a distinct ID sharing already-seen body bytes', async () => {
  await withReceiver({ unsafeRejectIdenticalBodyAsCollision: true }, async (config) => {
    const result = await runLab({ ...config, distinctIdsIdenticalBody: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 409, 200, 409]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 2, 2, 2]);
  });
});

test('detects a receiver that accepts both IDs but reprocesses their exact signed retries', async () => {
  await withReceiver({ unsafeReprocessIdenticalBodyReplays: true }, async (config) => {
    const result = await runLab({ ...config, distinctIdsIdenticalBody: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 3, 4, 5]);
  });
});

test('identical-body option rejects invalid values before sending any request', async () => {
  await withReceiver({}, async (config) => {
    for (const distinctIdsIdenticalBody of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, distinctIdsIdenticalBody }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /distinctIdsIdenticalBody/);
      assert.equal(called, false);
    }
  });
});

test('identical-body and same-resource options compose using independent IDs and counters', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config,
      distinctEventsSameResource: true, distinctIdsIdenticalBody: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(reportOf(result).observedCounts, [4, 5, 5, 5]);
    assert.equal(reportOf(result).expectedProcessedCount, 5);
  });
});

test('CLI exposes identical-body probe without leaking keys, signatures, or body bytes', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-identical-body-'));
    try {
      const configPath = join(directory, 'lab.json');
      await writeFile(configPath, JSON.stringify({ ...config, distinctIdsIdenticalBody: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.deepEqual(reportOf(result).observedCounts, [2, 3, 3, 3]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('wfl_identical_payload_'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
