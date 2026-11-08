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

test('two physical webhook-timestamp fields are rejected before dedupe, then corrected retry succeeds', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_wire_timestamp_retry');
    assert.deepEqual(report.httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 2, 2]);
  });
});

test('detects first-wins authentication of ambiguous physical timestamp fields', async () => {
  await withReceiver({ unsafeAcceptDuplicateWireTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2, 2]);
  });
});

test('detects last-wins authentication of ambiguous physical timestamp fields', async () => {
  await withReceiver({ unsafeAcceptLastDuplicateWireTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2, 2]);
  });
});

test('detects rejected duplicate timestamp fields that reserve the delivery ID', async () => {
  await withReceiver({ unsafeCacheDuplicateWireTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1, 1]);
  });
});

test('detects effect committed before duplicate timestamp header rejection', async () => {
  await withReceiver({ unsafeCommitDuplicateWireTimestampBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3, 3]);
  });
});

test('duplicate wire timestamp option fails closed on non-boolean values before HTTP', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateWireTimestampRetry of [0, 1, 'true', null, {}, []]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateWireTimestampRetry }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /rejectDuplicateWireTimestampRetry/);
      assert.equal(requested, false);
    }
  });
});

test('duplicate physical timestamp check composes with missing timestamp recovery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMissingTimestampRetry: true,
      rejectDuplicateWireTimestampRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['missing_timestamp_retry', 'duplicate_wire_timestamp_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 3, 3]);
  });
});

test('CLI emits duplicate physical timestamp verdict without signing keys or headers', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-duplicate-wire-timestamp-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, rejectDuplicateWireTimestampRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'duplicate_wire_timestamp_retry');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-timestamp'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
