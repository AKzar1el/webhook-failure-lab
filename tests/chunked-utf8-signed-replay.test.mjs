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
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('valid signed JSON with UTF-8 split across HTTP chunks commits once and fixed-body replay dedupes', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, chunkedSignedUtf8Replay: true }, { secret });
    assert.equal(result.success, true);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'chunked_utf8_signed_replay');
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
  });
});

test('detects a broken receiver that decodes each HTTP chunk separately before verifying HMAC', async () => {
  await withReceiver({ unsafeDecodeChunkSeparately: true }, async (config) => {
    const result = await runLab({ ...config, chunkedSignedUtf8Replay: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'chunked_utf8_signed_replay');
    assert.deepEqual(probe.httpStatuses, [401, 200]);
    assert.deepEqual(probe.observedCounts, [1, 2]);
  });
});

test('detects a receiver that rejects otherwise valid chunked signed bodies', async () => {
  await withReceiver({ unsafeRejectChunkedTransfer: true }, async (config) => {
    const result = await runLab({ ...config, chunkedSignedUtf8Replay: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [415, 200]);
    assert.deepEqual(probe.observedCounts, [1, 2]);
  });
});

test('detects a receiver deduplicating by HTTP transfer framing instead of authenticated event ID', async () => {
  await withReceiver({ unsafeDedupeByTransferFraming: true }, async (config) => {
    const result = await runLab({ ...config, chunkedSignedUtf8Replay: true }, { secret });
    assert.equal(result.success, false);
    const probe = result.scenarios.at(-1);
    assert.deepEqual(probe.httpStatuses, [200, 200]);
    assert.deepEqual(probe.observedCounts, [2, 3]);
  });
});

test('chunked UTF-8 option fails closed on invalid values before any request', async () => {
  await withReceiver({}, async (config) => {
    for (const chunkedSignedUtf8Replay of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, chunkedSignedUtf8Replay }, {
        secret, request: () => { requested = true; throw new Error('Unexpected request'); },
      }), /chunkedSignedUtf8Replay/);
      assert.equal(requested, false);
    }
  });
});

test('chunked UTF-8 probe composes with signed media-type validation using independent IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, rejectWrongContentTypeRetry: true,
      chunkedSignedUtf8Replay: true }, { secret });
    assert.equal(result.success, true);
    const chunked = result.scenarios.find(({ scenario }) => scenario === 'chunked_utf8_signed_replay');
    const media = result.scenarios.find(({ scenario }) => scenario === 'wrong_content_type_retry');
    assert.deepEqual(chunked.observedCounts, [2, 2]);
    assert.deepEqual(media.observedCounts, [2, 3, 3]);
  });
});

test('CLI reports chunked UTF-8 check without signing key or raw event body', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-chunked-utf8-'));
    try {
      const file = join(directory, 'local.json');
      await writeFile(file, JSON.stringify({ ...config, chunkedSignedUtf8Replay: true }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', file], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'chunked_utf8_signed_replay');
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('€'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
