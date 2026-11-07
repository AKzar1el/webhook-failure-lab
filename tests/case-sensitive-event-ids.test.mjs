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

const caseReport = (result) => result.scenarios.find((item) => item.scenario === 'case_sensitive_event_ids');

test('two signed event IDs differing only by ASCII case both commit, and both retries dedupe', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, caseSensitiveEventIds: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = caseReport(result);
    assert.ok(report);
    assert.equal(report.passed, true);
    assert.deepEqual(report.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 3, 3, 3]);
    assert.equal(report.expectedProcessedCount, 3);
  });
});

test('detects a receiver that lowercases authenticated IDs in its deduplication key', async () => {
  await withReceiver({ unsafeCaseFoldEventIds: true }, async (config) => {
    const result = await runLab({ ...config, caseSensitiveEventIds: true }, { secret });
    assert.equal(result.success, false);
    const report = caseReport(result);
    assert.ok(report);
    assert.deepEqual(report.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('detects a receiver that returns 409 for an independent case-variant event', async () => {
  await withReceiver({ unsafeRejectCaseVariantEventId: true }, async (config) => {
    const result = await runLab({ ...config, caseSensitiveEventIds: true }, { secret });
    assert.equal(result.success, false);
    const report = caseReport(result);
    assert.ok(report);
    assert.deepEqual(report.httpStatuses, [200, 409, 200, 409]);
    assert.deepEqual(report.observedCounts, [2, 2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('case-sensitive event ID option fails closed on invalid values before loopback traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const caseSensitiveEventIds of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, caseSensitiveEventIds }, {
        secret, request: () => { called = true; throw new Error('Unexpected HTTP request'); },
      }), /caseSensitiveEventIds/);
      assert.equal(called, false);
    }
  });
});

test('case-sensitive event IDs compose with re-signed duplicate deliveries', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, caseSensitiveEventIds: true,
      resignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(caseReport(result).observedCounts, [2, 3, 3, 3]);
    assert.equal(result.scenarios.find((item) =>
      item.scenario === 'resigned_duplicate_delivery').expectedProcessedCount, 4);
  });
});

test('CLI exposes the case-sensitive event ID check without leaking synthetic signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-case-sensitive-'));
    try {
      const configPath = join(directory, 'lab.json');
      await writeFile(configPath, JSON.stringify({ ...config, caseSensitiveEventIds: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.deepEqual(caseReport(result).observedCounts, [2, 3, 3, 3]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
