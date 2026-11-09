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

test('aborted chunked signed upload does not reserve its ID; full retry commits once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, abortedChunkedUploadRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'aborted_chunked_upload_retry');
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.deepEqual(report.httpStatuses, [200, 200]);
  });
});

test('detects receiver reserving signed ID after chunked upload abort', async () => {
  await withReceiver({ unsafeReserveAbortedChunkId: true }, async (config) => {
    const result = await runLab({ ...config, abortedChunkedUploadRetry: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'aborted_chunked_upload_retry');
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('detects receiver committing an effect from an incomplete HTTP chunked stream', async () => {
  await withReceiver({ unsafeCommitAbortedChunk: true }, async (config) => {
    const result = await runLab({ ...config, abortedChunkedUploadRetry: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('chunked-abort flag rejects nonboolean input before making any request', async () => {
  await withReceiver({}, async (config) => {
    for (const abortedChunkedUploadRetry of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, abortedChunkedUploadRetry }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /abortedChunkedUploadRetry/);
      assert.equal(requested, false);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('chunked and Content-Length abort probes use independent authenticated IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, partialBodyUploadAbort: true,
      abortedChunkedUploadRetry: true }, { secret });
    assert.equal(result.success, true);
    const fixed = result.scenarios.find(({ scenario }) =>
      scenario === 'partial_body_upload_abort_retry');
    const chunked = result.scenarios.at(-1);
    assert.deepEqual(fixed.observedCounts, [1, 2, 2]);
    assert.equal(chunked.scenario, 'aborted_chunked_upload_retry');
    assert.deepEqual(chunked.observedCounts, [2, 3, 3]);
  });
});

test('aborted chunked upload and keep-alive replay probes preserve independent effect counts', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, abortedChunkedUploadRetry: true,
      keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['aborted_chunked_upload_retry', 'keep_alive_connection_isolation']);
    assert.deepEqual(result.scenarios.at(-2).observedCounts, [1, 2, 2]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 4, 4, 4]);
    assert.equal(result.scenarios.at(-1).sameSocketReused, true);
    assert.equal(result.scenarios.at(-1).freshSocketUsed, true);
  });
});

test('connection-scoped dedupe still fails after a successful aborted-chunked retry', async () => {
  await withReceiver({ unsafeConnectionScopedDedupe: true }, async (config) => {
    const result = await runLab({ ...config, abortedChunkedUploadRetry: true,
      keepAliveConnectionIsolation: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-2).passed, true);
    assert.equal(result.scenarios.at(-1).passed, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 4, 4, 5]);
  });
});

test('CLI outputs chunked-abort result without secret or signed raw body', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-abort-chunk-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, abortedChunkedUploadRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'aborted_chunked_upload_retry');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('test.created'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
