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

test('valid signed PUT is rejected with 405 and Allow before same-ID POST succeeds once', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'wrong_http_method_retry');
    assert.deepEqual(probe.httpStatuses, [405, 200, 200]);
    assert.equal(probe.allowPost, true);
    assert.deepEqual(probe.observedCounts, [1, 2, 2]);
  });
});

test('detects a receiver that processes signed PUT as if it were POST', async () => {
  await withReceiver({ unsafeAcceptWrongHttpMethod: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects rejected PUT that still reserves webhook event ID', async () => {
  await withReceiver({ unsafePoisonWrongMethodDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [405, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects receiver returning 405 after committing an unwanted effect', async () => {
  await withReceiver({ unsafeCommitWrongMethodBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [405, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects HTTP 405 response missing required Allow: POST', async () => {
  await withReceiver({ unsafeOmitWrongMethodAllow: true }, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [405, 200, 200]);
    assert.equal(probe.allowPost, false);
    assert.deepEqual(probe.observedCounts, [1, 2, 2]);
  });
});

test('missing method validation fails the explicit opt-in POST-only contract', async () => {
  await withReceiver({ supportHttpMethodValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
  });
});

test('method probe flag rejects non-booleans before any HTTP traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectWrongHttpMethodRetry of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectWrongHttpMethodRetry }, {
        secret, request: () => { called = true; throw new Error('Unexpected request'); },
      }), /rejectWrongHttpMethodRetry/);
      assert.equal(called, false);
    }
  });
});

test('wrong-method retry composes with independent content-type retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true,
      rejectWrongHttpMethodRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.deepEqual(result.scenarios.slice(-2).map(({ scenario }) => scenario),
      ['wrong_content_type_retry', 'wrong_http_method_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 3, 3]);
  });
});

test('CLI method verdict does not print signing keys or untrusted headers', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-method-'));
    try {
      const path = join(directory, 'local.json');
      await writeFile(path, JSON.stringify({ ...config, rejectWrongHttpMethodRetry: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'wrong_http_method_retry');
      assert.deepEqual(result.scenarios.at(-1).httpStatuses, [405, 200, 200]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('wfl_method_'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
