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

test('cached event ID still requires a signature, then accepts an exact signed replay', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectUnsignedCachedDuplicate: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'unsigned_cached_duplicate');
    assert.deepEqual(report.httpStatuses, [200, 401, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('exposes a cache-first receiver acknowledging an unsigned duplicate', async () => {
  await withReceiver({ unsafeAcknowledgeUnsignedCachedDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsignedCachedDuplicate: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('exposes a receiver returning 401 after committing an unsigned duplicate', async () => {
  await withReceiver({ unsafeCommitUnsignedCachedBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsignedCachedDuplicate: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 401, 200]);
    assert.deepEqual(report.observedCounts, [2, 3, 3]);
    assert.equal(report.passed, false);
  });
});

test('invalid opt-in values fail before any webhook traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectUnsignedCachedDuplicate of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectUnsignedCachedDuplicate }, {
        secret, request: () => { called = true; throw new Error('unexpected network request'); },
      }), /rejectUnsignedCachedDuplicate/);
      assert.equal(called, false);
    }
    const observer = await fetch(config.observer);
    assert.equal((await observer.json()).processedCount, 0);
  });
});

test('unsigned cached duplicate composes with missing and tampered signature checks', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingSignatureRetry: true,
      rejectTamperedDuplicateSignature: true, rejectUnsignedCachedDuplicate: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    const report = result.scenarios.find((entry) => entry.scenario === 'unsigned_cached_duplicate');
    assert.deepEqual(report.httpStatuses, [200, 401, 200]);
    assert.deepEqual(report.observedCounts, [4, 4, 4]);
  });
});

test('CLI reports unsigned cached replay rejection without signature or key disclosure', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-unsigned-cached-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectUnsignedCachedDuplicate: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      const report = result.scenarios.at(-1);
      assert.equal(report.scenario, 'unsigned_cached_duplicate');
      assert.deepEqual(report.httpStatuses, [200, 401, 200]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stderr.includes(secret));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});

test('CLI returns receiver-failure exit 1 for a cache-first unsigned acknowledgement', async () => {
  await withReceiver({ unsafeAcknowledgeUnsignedCachedDuplicate: true }, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-unsigned-cache-failure-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectUnsignedCachedDuplicate: true }));
      await assert.rejects(() => execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } }),
      (error) => {
        assert.equal(error.code, 1);
        const result = JSON.parse(error.stdout);
        assert.equal(result.success, false);
        assert.equal(result.scenarios.at(-1).scenario, 'unsigned_cached_duplicate');
        assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
        assert.ok(!error.stdout.includes(secret));
        assert.ok(!error.stderr.includes(secret));
        return true;
      });
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
