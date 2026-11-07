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

test('signed JSON with UTF-8 charset parameter is accepted and plain JSON retry dedupes', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, acceptJsonCharsetContentType: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'json_charset_content_type');
    assert.deepEqual(report.httpStatuses, [200, 200]);
    assert.deepEqual(report.observedCounts, [2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects exact-string media-type comparison rejecting valid JSON with charset', async () => {
  await withReceiver({ unsafeRejectJsonCharset: true }, async (config) => {
    const result = await runLab({ ...config, acceptJsonCharsetContentType: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [415, 200]);
    assert.deepEqual(report.observedCounts, [1, 2]);
    assert.equal(report.passed, false);
  });
});

test('detects reprocessing a signed duplicate when only unsigned media type changes', async () => {
  await withReceiver({ unsafeDedupeByContentType: true }, async (config) => {
    const result = await runLab({ ...config, acceptJsonCharsetContentType: true }, { secret });
    assert.equal(result.success, false);
    const report = result.scenarios.at(-1);
    assert.deepEqual(report.httpStatuses, [200, 200]);
    assert.deepEqual(report.observedCounts, [2, 3]);
    assert.equal(report.passed, false);
  });
});

test('charset media-type opt-in must be a boolean before network requests', async () => {
  await withReceiver({}, async (config) => {
    for (const acceptJsonCharsetContentType of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, acceptJsonCharsetContentType }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /acceptJsonCharsetContentType/);
      assert.equal(called, false);
    }
  });
});

test('valid JSON charset and invalid text/plain media-type retry checks compose', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true,
      acceptJsonCharsetContentType: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map((item) => item.scenario),
      ['wrong_content_type_retry', 'json_charset_content_type']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('CLI reports JSON charset probe without disclosing signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-json-charset-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, acceptJsonCharsetContentType: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'json_charset_content_type');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
