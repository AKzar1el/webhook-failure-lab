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

async function withReceiver(flags, fn) {
  const server = await startMock({ secret, ...flags });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('unsupported v2 signature prefix rejects before valid v1 retry and replay', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedSignatureVersion: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'unsupported_signature_version_retry');
    assert.deepEqual(report.httpStatuses, [401, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects receiver that ignores the signature version and checks only the digest', async () => {
  await withReceiver({ unsafeIgnoreUnsupportedSignatureVersion: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedSignatureVersion: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('detects a rejected unsupported signature version poisoning the event-ID cache', async () => {
  await withReceiver({ unsafeCacheUnsupportedSignatureVersion: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedSignatureVersion: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects effect committed before rejecting an unsupported signature version', async () => {
  await withReceiver({ unsafeCommitUnsupportedSignatureVersionBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedSignatureVersion: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('signature-version opt-in rejects nonboolean config before loopback traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectUnsupportedSignatureVersion of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectUnsupportedSignatureVersion }, {
        secret, request: () => { called = true; throw new Error('unexpected request'); },
      }), /rejectUnsupportedSignatureVersion/);
      assert.equal(called, false);
    }
  });
});

test('unsupported version retry composes with missing signature retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true,
      rejectUnsupportedSignatureVersion: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'missing_signature_retry')
      .observedCounts, [1, 2, 2]);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'unsupported_signature_version_retry')
      .observedCounts, [2, 3, 3]);
  });
});

test('CLI reports unsupported signature-version verdict without secrets or raw signatures', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-unsupported-signature-version-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectUnsupportedSignatureVersion: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'unsupported_signature_version_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
