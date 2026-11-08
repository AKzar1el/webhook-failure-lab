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
const reportFor = (result) =>
  result.scenarios.find((entry) => entry.scenario === 'prototype_property_event_ids');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('authenticates __proto__ and constructor as independent IDs and dedupes signed retries', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, prototypePropertyEventIds: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = reportFor(result);
    assert.ok(report);
    assert.equal(report.passed, true);
    assert.deepEqual(report.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 3, 3, 3]);
    assert.equal(report.expectedProcessedCount, 3);
  });
});

test('catches prototype-inherited cache entries incorrectly considered already delivered', async () => {
  await withReceiver({ unsafeInheritedEventIdCache: true }, async (config) => {
    const result = await runLab({ ...config, prototypePropertyEventIds: true }, { secret });
    assert.equal(result.success, false);
    const report = reportFor(result);
    assert.ok(report);
    assert.deepEqual(report.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('catches a __proto__ setter that fails to persist a dedupe key', async () => {
  await withReceiver({ unsafePrototypeSetterEventIdCache: true }, async (config) => {
    const result = await runLab({ ...config, prototypePropertyEventIds: true }, { secret });
    assert.equal(result.success, false);
    const report = reportFor(result);
    assert.ok(report);
    assert.deepEqual(report.httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(report.observedCounts, [2, 3, 4, 4]);
    assert.equal(report.passed, false);
  });
});

test('catches a receiver that refuses authenticated prototype-named event IDs', async () => {
  await withReceiver({ unsafeRejectPrototypeEventIds: true }, async (config) => {
    const result = await runLab({ ...config, prototypePropertyEventIds: true }, { secret });
    assert.equal(result.success, false);
    const report = reportFor(result);
    assert.ok(report);
    assert.deepEqual(report.httpStatuses, [409, 409, 409, 409]);
    assert.deepEqual(report.observedCounts, [1, 1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('prototype property ID option rejects invalid values without any HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const prototypePropertyEventIds of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, prototypePropertyEventIds }, {
        secret, request: () => { called = true; throw new Error('Unexpected network request'); },
      }), /prototypePropertyEventIds/);
      assert.equal(called, false);
    }
  });
});

test('prototype property ID probe composes with valid signed case variants', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, prototypePropertyEventIds: true,
      caseSensitiveEventIds: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(reportFor(result).observedCounts, [4, 5, 5, 5]);
    const second = result.scenarios.find((entry) => entry.scenario === 'case_sensitive_event_ids');
    assert.deepEqual(second.observedCounts, [2, 3, 3, 3]);
  });
});

test('CLI runs the probe and does not disclose signing keys or event IDs', async () => {
  await withReceiver({}, async (config) => {
    const dir = await mkdtemp(join(tmpdir(), 'wfl-prototype-event-ids-'));
    try {
      const configPath = join(dir, 'lab.json');
      await writeFile(configPath, JSON.stringify({ ...config, prototypePropertyEventIds: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.deepEqual(reportFor(result).observedCounts, [2, 3, 3, 3]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('__proto__'));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally { await rm(dir, { recursive: true }); }
  });
});
