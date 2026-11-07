import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';
import { sign, verify } from '../src/standard.mjs';

const execFileAsync = promisify(execFile);
const secret = `whsec_${randomBytes(32).toString('base64')}`;

async function withServer(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('signed timestamp bytes must not be normalized before HMAC verification', () => {
  const id = 'evt_timestamp_bytes';
  const timestamp = 1760000000;
  const body = '{"synthetic":true}';
  const signature = sign({ secret, id, timestamp, body });
  const check = (value) => verify({ secret, id, timestamp: value, body,
    signature, now: timestamp });
  assert.equal(check(String(timestamp)), true);
  assert.equal(check(timestamp), true);
  for (const value of [`0${timestamp}`, `${timestamp}.0`, `+${timestamp}`,
    ` ${timestamp}`, `${timestamp} `, `1.76e9`, '']) {
    assert.equal(check(value), false, `unexpected acceptance of ${JSON.stringify(value)}`);
  }
});

test('opt-in malformed signed timestamps are rejected without committed effects', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectNoncanonicalTimestamp: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'noncanonical_signed_timestamp');
    assert.equal(probe.passed, true);
    assert.deepEqual(probe.httpStatuses, [401, 401]);
    assert.deepEqual(probe.observedCounts, [1, 1]);
    assert.equal(probe.expectedProcessedCount, 1);
  });
});

test('malformed timestamp probe catches receiver normalizing unauthenticated header text', async () => {
  await withServer({ unsafeNormalizeTimestamp: true }, async (config) => {
    const result = await runLab({ ...config, rejectNoncanonicalTimestamp: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
  });
});

test('malformed timestamp probe catches a receiver that rejects after committing', async () => {
  await withServer({ unsafeCommitNoncanonicalBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, rejectNoncanonicalTimestamp: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.passed, false);
    assert.deepEqual(probe.httpStatuses, [401, 401]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
  });
});

test('malformed timestamp opt-in validates type before any loopback requests', async () => {
  await withServer({}, async (config) => {
    for (const rejectNoncanonicalTimestamp of [0, 1, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, rejectNoncanonicalTimestamp }, { secret }),
        /rejectNoncanonicalTimestamp/);
    }
    assert.equal((await (await fetch(config.observer)).json()).processedCount, 0);
  });
});

test('malformed timestamp probe composes with signed-future and multi-signature checks', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, rejectNoncanonicalTimestamp: true,
      rejectFutureSignedTimestamp: true, multiSignatureHeader: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 7);
    assert.equal(result.scenarios.at(-1).scenario, 'noncanonical_signed_timestamp');
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
  });
});

test('CLI reports malformed timestamp probe without leaking the synthetic signing key', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wfl-timestamp-'));
  const server = await startMock({ secret });
  try {
    const configPath = join(directory, 'lab.json');
    await writeFile(configPath, JSON.stringify({ ...server.config, rejectNoncanonicalTimestamp: true }));
    const { stdout } = await execFileAsync(process.execPath,
      [fileURLToPath(new URL('../bin/wfl.mjs', import.meta.url)), 'run', configPath],
      { env: { ...process.env, WFL_SECRET: secret } });
    const result = JSON.parse(stdout);
    assert.equal(result.success, true);
    assert.equal(result.scenarios.at(-1).scenario, 'noncanonical_signed_timestamp');
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [401, 401]);
    assert.ok(!stdout.includes(secret));
    assert.ok(!stdout.includes(secret.slice(6)));
    assert.ok(!stdout.includes('webhook-signature'));
  } finally {
    await server.stop();
    await rm(directory, { recursive: true });
  }
});
