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
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('two authenticated malformed gzip streams reject before corrected same-ID retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'malformed_gzip_retry');
    assert.deepEqual(report.httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
    assert.equal(report.corruptWireBodiesBelowLimit, true);
  });
});

test('detects receiver that commits invalid gzip payloads as events', async () => {
  await withReceiver({ unsafeAcceptMalformedGzip: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('detects rejected malformed gzip reserving an event ID before correction', async () => {
  await withReceiver({ unsafeCacheMalformedGzip: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1, 1]);
  });
});

test('detects effects committed before HTTP 400 on malformed signed gzip', async () => {
  await withReceiver({ unsafeCommitMalformedGzipBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.ok(result.scenarios.at(-1).observedCounts[0] > 1);
  });
});

test('missing declared gzip validation policy fails the negative contract', async () => {
  await withReceiver({ supportMalformedGzipValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('malformed gzip option validates before sending any request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectMalformedGzipRetry of [0, 1, 'true', null, [], {}]) {
      let contacted = false;
      await assert.rejects(() => runLab({ ...config, rejectMalformedGzipRetry }, {
        secret, request: () => { contacted = true; throw new Error('Unexpected request'); },
      }), /rejectMalformedGzipRetry/);
      assert.equal(contacted, false);
    }
  });
});

test('malformed gzip rejection composes with the gzip inflation-size cap', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectOversizedGzipRetry: true,
      rejectMalformedGzipRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((x) => x.scenario),
      ['oversized_gzip_retry', 'malformed_gzip_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 3, 3]);
  });
});

test('CLI reports malformed gzip verdict without exposing signatures or raw bytes', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-gzip-invalid-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectMalformedGzipRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'malformed_gzip_retry');
      assert.deepEqual(report.scenarios.at(-1).httpStatuses, [400, 400, 200, 200]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
