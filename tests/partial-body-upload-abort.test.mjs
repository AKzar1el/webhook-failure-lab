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

test('aborted partial signed upload leaves ID retryable; complete retry commits once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, partialBodyUploadAbort: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'partial_body_upload_abort_retry');
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.deepEqual(report.httpStatuses, [200, 200]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects receiver reserving an ID from an incomplete abandoned body', async () => {
  await withReceiver({ unsafeReserveTruncatedUploadId: true }, async (config) => {
    const result = await runLab({ ...config, partialBodyUploadAbort: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'partial_body_upload_abort_retry');
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('detects receiver committing an effect while a partial upload is abandoned', async () => {
  await withReceiver({ unsafeCommitTruncatedUpload: true }, async (config) => {
    const result = await runLab({ ...config, partialBodyUploadAbort: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.equal(report.firstAttemptOutcome, 'transport_error');
    assert.deepEqual(report.observedCounts, [2, 2, 2]);
    assert.equal(report.passed, false);
  });
});

test('partial-body upload option fails closed on nonboolean values before traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const partialBodyUploadAbort of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, partialBodyUploadAbort }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /partialBodyUploadAbort/);
      assert.equal(requested, false);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('partial upload abort and precommit 503 retry use separate signed event IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true,
      partialBodyUploadAbort: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'partial_body_upload_abort_retry');
    assert.deepEqual(report.observedCounts, [2, 3, 3]);
  });
});

test('CLI exports partial upload report without raw payload or signing key', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-partial-upload-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, partialBodyUploadAbort: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'partial_body_upload_abort_retry');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('test.created'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
