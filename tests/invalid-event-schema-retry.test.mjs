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

test('valid JSON with missing required event field is rejected before same-ID corrected retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'invalid_signed_event_schema_retry');
    assert.deepEqual(report.httpStatuses, [422, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects schema-invalid signed JSON that receiver nevertheless accepts', async () => {
  await withReceiver({ unsafeAcceptInvalidEventSchema: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('detects a rejected invalid schema poisoning the event-ID cache', async () => {
  await withReceiver({ unsafePoisonInvalidSchemaDedupe: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1, 1]);
  });
});

test('detects HTTP 422 rejection after a schema-invalid event has committed', async () => {
  await withReceiver({ unsafeCommitInvalidSchemaBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [422, 200, 200]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('missing local schema adapter does not pass by silently processing invalid JSON', async () => {
  await withReceiver({ supportEventSchemaValidation: false }, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).passed, false);
  });
});

test('schema validation flag fails closed for nonboolean values before HTTP requests', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectInvalidSignedEventSchema of [0, 1, 'true', null, [], {}]) {
      let called = false;
      await assert.rejects(() => runLab({ ...config, rejectInvalidSignedEventSchema }, {
        secret, request: () => { called = true; throw new Error('Unexpected HTTP request'); },
      }), /rejectInvalidSignedEventSchema/);
      assert.equal(called, false);
    }
  });
});

test('invalid signed schema check composes with malformed JSON and media-type checks', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectInvalidSignedEventSchema: true,
      rejectMalformedSignedPayload: true, rejectWrongContentTypeRetry: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.deepEqual(result.scenarios.map((report) => report.scenario).slice(-3),
      ['malformed_signed_payload_retry', 'wrong_content_type_retry',
        'invalid_signed_event_schema_retry']);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 4, 4]);
  });
});

test('CLI reports schema rejection and corrected retry without exposing signing material', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-schema-retry-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, rejectInvalidSignedEventSchema: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const report = JSON.parse(stdout);
      assert.equal(report.success, true);
      assert.equal(report.scenarios.at(-1).scenario, 'invalid_signed_event_schema_retry');
      assert.deepEqual(report.scenarios.at(-1).observedCounts, [1, 2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
