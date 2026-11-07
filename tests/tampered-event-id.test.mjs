import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const execFileAsync = promisify(execFile);
const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('opt-in changed webhook-id rejects reused HMAC with unchanged signed body', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectTamperedEventId: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'tampered_webhook_id_header');
    assert.deepEqual(probe.httpStatuses, [200, 401]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
    assert.equal(probe.expectedProcessedCount, 2);
    assert.equal(probe.passed, true);
  });
});

test('changed ID probe catches receiver verifying payload ID instead of webhook-id header', async () => {
  await withReceiver({ unsafeVerifyBodyIdInsteadOfHeader: true }, async (config) => {
    const result = await runLab({ ...config, rejectTamperedEventId: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'tampered_webhook_id_header');
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
    assert.equal(probe.passed, false);
  });
});

test('changed ID probe catches receiver committing before rejecting forged header', async () => {
  await withReceiver({ unsafeCommitTamperedIdBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectTamperedEventId: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 401]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
    assert.equal(probe.expectedProcessedCount, 2);
    assert.equal(probe.passed, false);
  });
});

test('changed ID opt-in rejects invalid flags before any webhook request', async () => {
  await withReceiver({}, async (config) => {
    for (const rejectTamperedEventId of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectTamperedEventId }, { secret }),
        /rejectTamperedEventId/);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('changed ID scenario composes with duplicate auth and concurrent delivery', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectTamperedEventId: true,
      rejectTamperedDuplicateSignature: true, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'tampered_webhook_id_header');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [4, 4]);
  });
});

test('CLI includes changed ID failure probe without leaking synthetic signing material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-tampered-id-'));
  const receiver = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...receiver.config, rejectTamperedEventId: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'tampered_webhook_id_header');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await receiver.stop();
    await rm(directory, { recursive: true });
  }
});
