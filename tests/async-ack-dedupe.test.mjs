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
const option = { asyncAckDelivery: true, asyncAckWaitMs: 250 };

async function withReceiver(flags, fn) {
  const server = await startMock({ secret, ...flags });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('202 accepted duplicate deliveries result in one delayed observed effect', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, ...option }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'async_ack_dedupe');
    assert.deepEqual(probe.httpStatuses, [202, 202, 202]);
    assert.deepEqual(probe.observedCounts, [2, 2]);
  });
});

test('detects receiver acknowledging 202 but losing the queued work', async () => {
  await withReceiver({ unsafeAsyncAckDropJob: true }, async (config) => {
    const result = await runLab({ ...config, ...option }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [202, 202, 202]);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [1, 1]);
  });
});

test('detects receiver committing two effects for one queued delivery', async () => {
  await withReceiver({ unsafeAsyncAckDoubleCommit: true }, async (config) => {
    const result = await runLab({ ...config, ...option }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('detects receiver queuing the same signed event twice before worker completion', async () => {
  await withReceiver({ unsafeAsyncAckNoReservation: true }, async (config) => {
    const result = await runLab({ ...config, ...option }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.at(-1).observedCounts[0] > 2);
  });
});

test('receiver without opt-in async adapter cannot claim a 202 contract', async () => {
  await withReceiver({ supportAsyncAck: false }, async (config) => {
    const result = await runLab({ ...config, ...option }, { secret });
    assert.equal(result.success, false);
    assert.equal(result.scenarios.at(-1).httpStatuses[0], 200);
  });
});

test('invalid async option values fail before loopback traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const asyncAckDelivery of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, asyncAckDelivery }, {
        secret, request: () => { requested = true; throw new Error('unexpected request'); },
      }), /asyncAckDelivery/);
      assert.equal(requested, false);
    }
    for (const asyncAckWaitMs of [99, 5001, 250.5, '250', null, -1]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, asyncAckDelivery: true, asyncAckWaitMs }, {
        secret, request: () => { requested = true; throw new Error('unexpected request'); },
      }), /asyncAckWaitMs/);
      assert.equal(requested, false);
    }
  });
});

test('async acknowledgement composes with an independent rejected-signature retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, ...option, retryAfterRejectedSignature: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [3, 3]);
  });
});

test('CLI reports asynchronous acceptance without keys, bodies, or the raw ID', async () => {
  await withReceiver({}, async (config) => {
    const directory = await mkdtemp(join(tmpdir(), 'wfl-async-ack-'));
    try {
      const path = join(directory, 'lab.json');
      await writeFile(path, JSON.stringify({ ...config, ...option }));
      const { stdout, stderr } = await execFileAsync(process.execPath,
        ['bin/wfl.mjs', 'run', path], { env: { ...process.env, WFL_SECRET: secret } });
      const result = JSON.parse(stdout);
      assert.equal(result.success, true);
      assert.equal(result.scenarios.at(-1).scenario, 'async_ack_dedupe');
      assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2]);
      assert.ok(!stdout.includes(secret));
      assert.ok(!stderr.includes(secret));
      assert.ok(!stdout.includes('webhook-signature'));
      assert.ok(!stdout.includes('wfl_asyncack_'));
    } finally {
      await rm(directory, { recursive: true });
    }
  });
});
