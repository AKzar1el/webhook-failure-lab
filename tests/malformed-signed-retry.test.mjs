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

test('signed malformed JSON is rejected before dedupe; corrected same-ID retry commits once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'malformed_signed_payload_retry');
    assert.deepEqual(report.httpStatuses, [400, 200]);
    assert.deepEqual(report.observedCounts, [1, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('malformed signed JSON accepted and committed is detected', async () => {
  await withReceiver({ unsafeAcceptMalformedSignedPayload: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2]);
    assert.equal(report.passed, false);
  });
});

test('rejected malformed JSON must not poison the dedupe cache', async () => {
  await withReceiver({ unsafePoisonMalformedDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [400, 200]);
    assert.deepEqual(report.observedCounts, [1, 1]);
    assert.equal(report.passed, false);
  });
});

test('malformed rejection after committing a side effect is detected', async () => {
  await withReceiver({ unsafeCommitMalformedBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [400, 200]);
    assert.deepEqual(report.observedCounts, [2, 2]);
    assert.equal(report.passed, false);
  });
});

test('missing malformed payload validation fails closed', async () => {
  await withReceiver({ supportMalformedValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('malformed payload opt-in requires a boolean before HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectMalformedSignedPayload of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectMalformedSignedPayload }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectMalformedSignedPayload/);
      assert.equal(called, false);
    }
  });
});

test('malformed payload check composes with independent precommit retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true,
      rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios.at(-1).scenario, 'malformed_signed_payload_retry');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3]);
  });
});

test('CLI reports malformed signed payload proof without leaking signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-malformed-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectMalformedSignedPayload: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'malformed_signed_payload_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
