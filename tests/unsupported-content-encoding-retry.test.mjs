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

test('unsupported Content-Encoding is rejected before dedupe; unchanged signed retry commits once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'unsupported_content_encoding_retry');
    assert.deepEqual(report.httpStatuses, [415, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a receiver that ignores an unsupported gzip Content-Encoding declaration', async () => {
  await withReceiver({ unsafeAcceptUnsupportedContentEncoding: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects a rejected encoding that incorrectly reserves the signed event ID', async () => {
  await withReceiver({ unsafePoisonUnsupportedEncodingDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [415, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects an HTTP 415 returned after an unsupported-encoding event committed', async () => {
  await withReceiver({ unsafeCommitUnsupportedEncodingBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [415, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('receiver lacking the declared content-encoding policy fails closed', async () => {
  await withReceiver({ supportContentEncodingValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('content-encoding retry flag validates as boolean before any loopback request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectUnsupportedContentEncodingRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectUnsupportedContentEncodingRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectUnsupportedContentEncodingRetry/);
      assert.equal(called, false);
    }
  });
});

test('content-encoding recovery composes with wrong media-type recovery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true,
      rejectUnsupportedContentEncodingRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['wrong_content_type_retry', 'unsupported_content_encoding_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3]);
  });
});

test('CLI exposes content-encoding recovery without leaking signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-content-encoding-'));
    try {
      const path = join(directory, 'local.json');
      await writeFile(path, JSON.stringify({ ...config, rejectUnsupportedContentEncodingRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'unsupported_content_encoding_retry');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
