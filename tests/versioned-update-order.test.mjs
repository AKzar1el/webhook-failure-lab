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

test('versioned updates reject a late older event without rolling back state', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, versionedOutOfOrderUpdates: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'versioned_out_of_order_update');
    assert.deepEqual(report.httpStatuses, [200, 200, 409]);
    assert.deepEqual(report.observedCounts, [2, 3, 3]);
    assert.deepEqual(report.observedResourceVersions, [1, 3, 3]);
    assert.equal(report.expectedProcessedCount, 3);
  });
});

test('versioned check detects a receiver accepting and applying a stale update', async () => {
  await withReceiver({ unsafeApplyStaleVersionedUpdate: true }, async (config) => {
    const result = await runLab({ ...config, versionedOutOfOrderUpdates: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 4]);
    assert.deepEqual(result.scenarios.at(-1).observedResourceVersions, [1, 3, 2]);
  });
});

test('versioned check detects reject-after-commit of a stale update', async () => {
  await withReceiver({ unsafeCommitStaleVersionBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, versionedOutOfOrderUpdates: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 409]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 4]);
    assert.deepEqual(result.scenarios.at(-1).observedResourceVersions, [1, 3, 2]);
  });
});

test('versioned check fails closed when observer or adapter lacks resource versions', async () => {
  await withReceiver({ supportVersionedUpdates: false }, async (config) => {
    const result = await runLab({ ...config, versionedOutOfOrderUpdates: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.passed, false);
    assert.deepEqual(report.observedResourceVersions, [null, null, null]);
  });
});

test('versioned opt-in rejects nonboolean config before making requests', async () => {
  await withReceiver({}, async (config) => {
    for (const versionedOutOfOrderUpdates of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, versionedOutOfOrderUpdates }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /versionedOutOfOrderUpdates/);
      assert.equal(called, false);
    }
  });
});

test('versioned check composes with the existing prerequisite ordering check', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, outOfOrderStateTransitions: true,
      versionedOutOfOrderUpdates: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios[4].scenario, 'out_of_order_state_transition');
    const report = result.scenarios[5];
    assert.deepEqual(report.httpStatuses, [200, 200, 409]);
    assert.deepEqual(report.observedCounts, [4, 5, 5]);
    assert.deepEqual(report.observedResourceVersions, [1, 3, 3]);
  });
});

test('CLI exposes versioned failure proof as JSON without synthetic signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-version-order-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, versionedOutOfOrderUpdates: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.length, 5);
      assert.deepEqual(result.scenarios.at(-1).observedResourceVersions, [1, 3, 3]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
