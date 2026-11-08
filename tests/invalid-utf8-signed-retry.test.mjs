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
import { sign, verify } from '../src/standard.mjs';

const secret = `whsec_${randomBytes(32).toString('base64')}`;
const execFileAsync = promisify(execFile);

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('Standard Webhooks signs exact bytes rather than a lossy UTF-8 decoding', () => {
  const bytes = Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
  const timestamp = 1700000000;
  const signature = sign({ secret, id: 'wfl_utf8_bytes', timestamp, body: bytes });
  assert.equal(verify({ secret, id: 'wfl_utf8_bytes', timestamp, body: bytes,
    signature, now: timestamp }), true);
  assert.equal(verify({ secret, id: 'wfl_utf8_bytes', timestamp, body: bytes.toString('utf8'),
    signature, now: timestamp }), false);
});

test('invalid UTF-8 with a valid raw-byte HMAC rejects before dedupe, then accepts corrected retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'invalid_utf8_signed_retry');
    assert.deepEqual(report.httpStatuses, [400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
  });
});

test('detects a receiver that replaces invalid UTF-8 instead of rejecting it', async () => {
  await withReceiver({ unsafeAcceptInvalidUtf8: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('detects rejected invalid UTF-8 that reserves the signed event ID', async () => {
  await withReceiver({ unsafeCacheInvalidUtf8: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects a side effect committed before invalid UTF-8 rejection', async () => {
  await withReceiver({ unsafeCommitInvalidUtf8BeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing local UTF-8 validation fails the opt-in contract', async () => {
  await withReceiver({ supportUtf8Validation: false }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('invalid UTF-8 opt-in validates boolean before sending HTTP', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectInvalidUtf8Retry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectInvalidUtf8Retry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectInvalidUtf8Retry/);
      assert.equal(called, false);
    }
  });
});

test('invalid UTF-8 retry composes with other signed JSON validation', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectInvalidUtf8Retry: true,
      rejectMalformedSignedPayload: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.find((s) => s.scenario === 'invalid_utf8_signed_retry')
      .observedCounts, [2, 3, 3]);
  });
});

test('CLI reports invalid UTF-8 verdict without raw bytes or synthetic HMAC', async () => {
  await withReceiver({}, async (config) => {
    const dir = await mkdtemp(join(tmpdir(), 'wfl-invalid-utf8-'));
    try {
      const path = join(dir, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectInvalidUtf8Retry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'invalid_utf8_signed_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(dir, { recursive: true });
    }
  });
});
