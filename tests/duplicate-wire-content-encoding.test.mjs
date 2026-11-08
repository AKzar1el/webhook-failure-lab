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
const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('conflicting physical Content-Encoding fields reject in both orders before dedupe', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, true);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'duplicate_wire_content_encoding_retry');
    assert.deepEqual(report.httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects first-wins receiver accepting ambiguous Content-Encoding fields', async () => {
  await withReceiver({ unsafeAcceptFirstDuplicateContentEncoding: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 415, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2, 2]);
  });
});

test('detects last-wins receiver accepting ambiguous Content-Encoding fields', async () => {
  await withReceiver({ unsafeAcceptLastDuplicateContentEncoding: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [415, 200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2, 2]);
  });
});

test('detects dedupe poisoning after rejecting ambiguous Content-Encoding', async () => {
  await withReceiver({ unsafeCacheDuplicateContentEncoding: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1, 1]);
  });
});

test('detects effects committed before rejecting ambiguous Content-Encoding', async () => {
  await withReceiver({ unsafeCommitDuplicateContentEncodingBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3, 3]);
  });
});

test('physical Content-Encoding option rejects non-boolean values before any request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectDuplicateWireContentEncodingRetry of [0, 1, 'true', null, {}, []]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, rejectDuplicateWireContentEncodingRetry }, {
        secret, request: () => { requested = true; throw new Error('unexpected request'); },
      }), /rejectDuplicateWireContentEncodingRetry/);
      assert.equal(requested, false);
    }
  });
});

test('physical Content-Encoding ambiguity composes with unsupported encoding recovery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true,
      rejectDuplicateWireContentEncodingRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['unsupported_content_encoding_retry', 'duplicate_wire_content_encoding_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 3, 3]);
  });
});

test('CLI reports physical Content-Encoding violations without leaking headers or keys', async () => {
  await withReceiver({ unsafeAcceptFirstDuplicateContentEncoding: true }, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-duplicate-cencoding-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, rejectDuplicateWireContentEncodingRetry: true }));
      await assert.rejects(() => execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } }),
      (error) => {
        assert.equal(error.code, 1);
        const result = JSON.parse(error.stdout);
        assert.equal(result.success, false);
        assert.equal(result.scenarios.at(-1).scenario, 'duplicate_wire_content_encoding_retry');
        assert.ok(!error.stdout.includes(secret));
        assert.ok(!error.stdout.includes('webhook-signature'));
        assert.ok(!error.stdout.includes('wfl_dupencoding_'));
        return true;
      });
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
