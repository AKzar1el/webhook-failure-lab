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

test('signed duplicate top-level data key is rejected before a corrected same-ID retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_json_data_key_retry');
    assert.deepEqual(report.httpStatuses, [422, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects silent last-key-wins processing of a signed ambiguous JSON payload', async () => {
  await withReceiver({ unsafeAcceptDuplicateDataKey: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('detects a rejected ambiguous JSON body that still reserves its signed ID', async () => {
  await withReceiver({ unsafePoisonDuplicateDataDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects an effect committed before rejecting a duplicate data key', async () => {
  await withReceiver({ unsafeCommitDuplicateDataBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing duplicate-key validation fails the opt-in receiver contract', async () => {
  await withReceiver({ supportDuplicateDataValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('duplicate-key opt-in validates booleans before local network requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateJsonDataKey of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateJsonDataKey }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectDuplicateJsonDataKey/);
      assert.equal(called, false);
    }
  });
});

test('duplicate-key opt-in composes with malformed signed JSON retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateJsonDataKey: true,
      rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'duplicate_json_data_key_retry')
      .observedCounts, [2, 3, 3]);
  });
});

test('CLI reports a scoped duplicate-key result without leaking the HMAC secret', async () => {
  await withReceiver({}, async (config) => {
    const dir = await mkdtemp(join(tmpdir(), 'wfl-dup-data-'));
    try {
      const path = join(dir, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectDuplicateJsonDataKey: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'duplicate_json_data_key_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(dir, { recursive: true });
    }
  });
});
