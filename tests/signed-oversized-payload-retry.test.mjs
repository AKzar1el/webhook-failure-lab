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

test('signed body over 1024 bytes returns 413 before corrected same-ID retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'oversized_signed_payload_retry');
    assert.deepEqual(report.httpStatuses, [413, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a receiver accepting a correctly signed oversized body', async () => {
  await withReceiver({ unsafeAcceptOversizedSignedPayload: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects HTTP 413 that poisons the ID before a corrected signed retry', async () => {
  await withReceiver({ unsafePoisonOversizedDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [413, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects HTTP 413 returned only after an oversized delivery committed', async () => {
  await withReceiver({ unsafeCommitOversizedBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [413, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing local body-size adapter fails this opt-in policy', async () => {
  await withReceiver({ supportPayloadSizeValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('oversized-body flag rejects nonboolean values before any network request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectOversizedSignedPayload of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectOversizedSignedPayload }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectOversizedSignedPayload/);
      assert.equal(called, false);
    }
  });
});

test('oversized signed retry composes with signed schema rejection', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true,
      rejectOversizedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((item) => item.scenario),
      ['invalid_signed_event_schema_retry', 'oversized_signed_payload_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3]);
  });
});

test('CLI reports oversized body rejection without exposing synthetic secrets', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-oversize-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectOversizedSignedPayload: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'oversized_signed_payload_retry');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
