import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('client timeout after a signed commit permits an idempotent retry', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, timeoutAfterCommit: true, timeoutMs: 800 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'client_timeout_after_commit');
    assert.equal(report.firstAttemptOutcome, 'client_timeout');
    assert.equal(report.observedCountAfterTimeout, 2);
    assert.equal(report.retryHttpStatus, 200);
    assert.equal(report.observedProcessedCount, 2);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a broken local receiver that commits before timeout but forgets the dedupe key', async () => {
  await withReceiver({ unsafeForgetTimeoutDedupe: true }, async (config) => {
    const result = await runLab({ ...config, timeoutAfterCommit: true, timeoutMs: 800 }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'client_timeout_after_commit');
    assert.equal(report.firstAttemptOutcome, 'client_timeout');
    assert.equal(report.observedCountAfterTimeout, 2);
    assert.equal(report.observedProcessedCount, 3);
    assert.equal(report.expectedProcessedCount, 2);
    assert.equal(report.passed, false);
  });
});

test('does not accept a receiver that ignores the timeout fault header', async () => {
  await withReceiver({ supportTimeoutFault: false }, async (config) => {
    const result = await runLab({ ...config, timeoutAfterCommit: true, timeoutMs: 800 }, { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.equal(report.firstAttemptOutcome, 'http_200');
    assert.equal(report.observedCountAfterTimeout, 2);
    assert.equal(report.passed, false);
  });
});

test('timeout-after-commit option fails closed on invalid values before any requests', async () => {
  await withReceiver({}, async (config) => {
    for (const timeoutAfterCommit of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, timeoutAfterCommit }, { secret }),
        /timeoutAfterCommit/);
    }
    const state = await fetch(config.observer).then((response) => response.json());
    assert.equal(state.processedCount, 0);
  });
});

test('client-timeout and dropped-ack probes use independent event IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({
      ...config, timeoutAfterCommit: true, lostAckAfterCommit: true, timeoutMs: 800,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios.at(-2).scenario, 'lost_ack_after_commit');
    assert.equal(result.scenarios.at(-1).scenario, 'client_timeout_after_commit');
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 3);
    assert.equal(result.scenarios.at(-1).expectedProcessedCount, 3);
  });
});
