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

test('signed JSON with text/plain is rejected before dedupe, then corrected media type commits once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'wrong_content_type_retry');
    assert.deepEqual(report.httpStatuses, [415, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a receiver that accepts text/plain with a valid HMAC as JSON', async () => {
  await withReceiver({ unsafeAcceptWrongContentType: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('detects rejected media type that still reserves the signed ID', async () => {
  await withReceiver({ unsafePoisonWrongContentTypeDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [415, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('detects HTTP 415 returned after an unwanted observed commit', async () => {
  await withReceiver({ unsafeCommitWrongContentTypeBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [415, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('missing local media-type validation fails this opt-in contract', async () => {
  await withReceiver({ supportContentTypeValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('media-type retry flag must be boolean before local HTTP traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectWrongContentTypeRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectWrongContentTypeRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectWrongContentTypeRetry/);
      assert.equal(called, false);
    }
  });
});

test('media-type correction composes with independently signed malformed-body retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMalformedSignedPayload: true,
      rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios[4].scenario, 'malformed_signed_payload_retry');
    assert.equal(result.scenarios[5].scenario, 'wrong_content_type_retry');
    assert.deepEqual(result.scenarios[5].observedCounts, [2, 3, 3]);
  });
});

test('CLI reports media-type retry without disclosing signing keys or HMACs', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-media-type-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectWrongContentTypeRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'wrong_content_type_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
