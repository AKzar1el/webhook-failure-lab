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

const secret = 'whsec_' + randomBytes(32).toString('base64');
const execFileAsync = promisify(execFile);

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('strict receiver rejects two signed nested data.id keys then accepts corrected retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_nested_resource_id_retry');
    assert.deepEqual(report.httpStatuses, [422, 422, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 2, 2]);
  });
});

test('broken receiver silently accepts literal duplicate resource ID', async () => {
  await withReceiver({ unsafeAcceptDuplicateNestedId: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 422, 200, 200]);
  });
});

test('broken receiver accepts an escaped second data.id property', async () => {
  await withReceiver({ unsafeAcceptEscapedDuplicateNestedId: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 200, 200, 200]);
  });
});

test('rejected nested-ID collision cannot poison delivery deduplication', async () => {
  await withReceiver({ unsafePoisonNestedIdDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1, 1]);
  });
});

test('rejection after committing a duplicate resource ID exposes an unwanted effect', async () => {
  await withReceiver({ unsafeCommitNestedIdBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3, 3]);
  });
});

test('receiver without nested-key guard fails the strict opt-in contract', async () => {
  await withReceiver({ supportNestedResourceIdValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200, 200]);
  });
});

test('nested-key opt-in rejects nonbooleans before any loopback requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateNestedResourceId of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateNestedResourceId }, {
        secret, request: () => { called = true; throw new Error('unexpected request'); },
      }), /rejectDuplicateNestedResourceId/);
      assert.equal(called, false);
    }
  });
});

test('nested and top-level duplicate JSON key probes compose with independent counts', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true,
      rejectDuplicateNestedResourceId: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'duplicate_json_data_key_retry')
      .observedCounts, [1, 1, 2, 2]);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'duplicate_nested_resource_id_retry')
      .observedCounts, [2, 2, 3, 3]);
  });
});

test('CLI exposes a scoped nested-ID result without HMAC or raw payload disclosure', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-nested-resource-id-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectDuplicateNestedResourceId: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'duplicate_nested_resource_id_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('wfl_untrusted_resource_'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
