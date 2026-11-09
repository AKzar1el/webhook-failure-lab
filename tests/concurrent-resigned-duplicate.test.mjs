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
  const receiver = await startMock({ secret, ...flags });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('two concurrent valid re-signatures commit once and a third replay stays deduplicated', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, concurrentResignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'concurrent_resigned_duplicate_delivery');
    assert.deepEqual(probe.httpStatuses, [200, 200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
    assert.equal(probe.distinctSignatures, true);
  });
});

test('catches signature-keyed deduplication under concurrent re-signing', async () => {
  await withReceiver({ unsafeDedupeBySignature: true }, async (config) => {
    const result = await runLab({ ...config, concurrentResignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.ok(result.scenarios.at(-1).observedCounts[0] > 2);
  });
});

test('catches valid re-signature incorrectly rejected as a conflicting ID', async () => {
  await withReceiver({ unsafeRejectResignedDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, concurrentResignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.at(-1).httpStatuses.includes(409));
  });
});

test('catches two concurrent re-signatures both committing after an empty-cache read', async () => {
  await withReceiver({ unsafeRacyResignedDuplicate: true }, async (config) => {
    const result = await runLab({ ...config, concurrentResignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('invalid concurrent re-signing option fails before HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const concurrentResignedDuplicateDelivery of [null, 0, 1, 'true', [], {}]) {
      let contacted = false;
      await assert.rejects(() => runLab({ ...config, concurrentResignedDuplicateDelivery }, {
        secret, request: () => { contacted = true; throw new Error('Unexpected HTTP'); },
      }), /concurrentResignedDuplicateDelivery/);
      assert.equal(contacted, false);
    }
  });
});

test('concurrent re-signatures compose with existing sequential re-signing check', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, resignedDuplicateDelivery: true,
      concurrentResignedDuplicateDelivery: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((probe) => probe.scenario),
      ['resigned_duplicate_delivery', 'concurrent_resigned_duplicate_delivery']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('CLI exports a sanitized concurrent re-signature report', async () => {
  await withReceiver({}, async (config) => {
    const dir = await mkdtemp(join(tmpdir(), 'wfl-concurrent-resign-'));
    try {
      const file = join(dir, 'lab.json');
      await writeFile(file, JSON.stringify({ ...config, concurrentResignedDuplicateDelivery: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'concurrent_resigned_duplicate_delivery');
      assert.ok(!stdout.includes('wfl_resignrace_'));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
    } finally {
      await rm(dir, { recursive: true });
    }
  });
});
