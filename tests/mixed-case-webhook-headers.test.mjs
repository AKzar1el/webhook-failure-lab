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

test('mixed-case wire header names authenticate and lowercase signed replay dedupes', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, mixedCaseWebhookHeaders: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'mixed_case_header_replay');
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
  });
});

test('detects receiver treating physically mixed-case webhook header names as missing', async () => {
  await withReceiver({ unsafeRejectMixedCaseWebhookHeaders: true }, async (config) => {
    const result = await runLab({ ...config, mixedCaseWebhookHeaders: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'mixed_case_header_replay');
    assert.deepEqual(probe.httpStatuses, [401, 200]);
    assert.deepEqual(probe.observedCounts, [1, 2]);
  });
});

test('detects broken dedupe keyed to physical HTTP header-name spelling', async () => {
  await withReceiver({ unsafeDedupeByHeaderSpelling: true }, async (config) => {
    const result = await runLab({ ...config, mixedCaseWebhookHeaders: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
  });
});

test('detects receiver rejecting a valid differently-cased replay as a conflict', async () => {
  await withReceiver({ unsafeRejectLowercaseHeaderReplay: true }, async (config) => {
    const result = await runLab({ ...config, mixedCaseWebhookHeaders: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 409]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
  });
});

test('mixed-case wire-header opt-in rejects non-boolean values before HTTP traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const mixedCaseWebhookHeaders of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, mixedCaseWebhookHeaders }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /mixedCaseWebhookHeaders/);
      assert.equal(requested, false);
    }
  });
});

test('mixed-case wire probe composes with a separate signed media-type check', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, mixedCaseWebhookHeaders: true,
      rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    const mixed = result.scenarios.find((s) => s.scenario === 'mixed_case_header_replay');
    const media = result.scenarios.find((s) => s.scenario === 'wrong_content_type_retry');
    assert.deepEqual(mixed.observedCounts, [2, 2]);
    assert.deepEqual(media.observedCounts, [2, 3, 3]);
  });
});

test('CLI emits only a redacted mixed-case-header verdict', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-headercase-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, mixedCaseWebhookHeaders: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'mixed_case_header_replay');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('wfl_headercase_'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
