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
const scenario = 'distinct_events_same_resource';
const reportOf = (result) => result.scenarios.find((item) => item.scenario === scenario);

async function withReceiver(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('two differently signed event IDs for one resource each commit, and exact retries dedupe', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, distinctEventsSameResource: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.deepEqual(reportOf(result), {
      scenario, passed: true,
      httpStatuses: [200, 200, 200, 200],
      observedCounts: [2, 3, 3, 3],
      expectedProcessedCount: 3,
    });
  });
});

test('catches a receiver that silently deduplicates independent events by resource ID', async () => {
  await withReceiver({ unsafeDedupeByResourceId: true }, async (config) => {
    const result = await runLab({ ...config, distinctEventsSameResource: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 2, 2, 2]);
    assert.equal(reportOf(result).passed, false);
  });
});

test('catches a receiver that mistakes a second resource event for an ID collision', async () => {
  await withReceiver({ unsafeRejectSecondResourceEvent: true }, async (config) => {
    const result = await runLab({ ...config, distinctEventsSameResource: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 409, 200, 409]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 2, 2, 2]);
  });
});

test('catches a receiver that processes each replay without retaining individual event IDs', async () => {
  await withReceiver({ unsafeReprocessSharedResourceReplays: true }, async (config) => {
    const result = await runLab({ ...config, distinctEventsSameResource: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(reportOf(result).httpStatuses, [200, 200, 200, 200]);
    assert.deepEqual(reportOf(result).observedCounts, [2, 3, 4, 5]);
  });
});

test('shared-resource probe rejects invalid option types before any request', async () => {
  await withReceiver({}, async (config) => {
    for (const distinctEventsSameResource of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, distinctEventsSameResource }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /distinctEventsSameResource/);
      assert.equal(called, false);
    }
  });
});

test('shared-resource and case-sensitive ID probes compose without counter resets', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config,
      distinctEventsSameResource: true, caseSensitiveEventIds: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(reportOf(result).observedCounts, [2, 3, 3, 3]);
    assert.equal(result.scenarios.find((item) =>
      item.scenario === 'case_sensitive_event_ids').expectedProcessedCount, 5);
  });
});

test('CLI exposes shared-resource probe without outputting signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-shared-resource-'));
    try {
      const configPath = join(directory, 'lab.json');
      await writeFile(configPath, JSON.stringify({ ...config, distinctEventsSameResource: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', configPath], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.deepEqual(reportOf(result).observedCounts, [2, 3, 3, 3]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
