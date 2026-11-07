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

test('valid pretty JSON signs exact wire bytes; cosmetic reformat with reused HMAC is rejected', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rawJsonSignatureBytes: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'raw_json_signature_bytes');
    assert.deepEqual(report.httpStatuses, [200, 401, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a receiver that reserializes JSON before verifying the HMAC', async () => {
  await withReceiver({ unsafeCanonicalizeRawJsonBeforeVerify: true }, async (config) => {
    const result = await runLab({ ...config, rawJsonSignatureBytes: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.passed, false);
    assert.equal(report.httpStatuses[0], 401);
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
  });
});

test('detects a receiver that acknowledges the cached ID before authenticating changed raw JSON', async () => {
  await withReceiver({ unsafeAcknowledgeRawJsonBeforeAuth: true }, async (config) => {
    const result = await runLab({ ...config, rawJsonSignatureBytes: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
  });
});

test('detects an effect committed before rejection of whitespace-tampered JSON', async () => {
  await withReceiver({ unsafeCommitRawJsonBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rawJsonSignatureBytes: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 401, 200]);
    assert.deepEqual(report.observedCounts, [2, 3, 3]);
  });
});

test('raw-body HMAC flag must be boolean before any network traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const rawJsonSignatureBytes of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rawJsonSignatureBytes }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rawJsonSignatureBytes/);
      assert.equal(called, false);
    }
  });
});

test('raw JSON byte integrity composes with the charset media-type probe', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, acceptJsonCharsetContentType: true,
      rawJsonSignatureBytes: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((item) => item.scenario),
      ['json_charset_content_type', 'raw_json_signature_bytes']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3, 3]);
  });
});

test('CLI reports exact raw-body HMAC verdict without disclosing synthetic secrets', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-raw-json-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rawJsonSignatureBytes: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'raw_json_signature_bytes');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [2, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
