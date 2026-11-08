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

test('client timeout before commit leaves the signed ID retryable and dedupes replay', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, timeoutBeforeCommit: true, timeoutMs: 800 },
      { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'client_timeout_before_commit');
    assert.equal(report.firstAttemptOutcome, 'client_timeout');
    assert.equal(report.observedCountAfterTimeout, 1);
    assert.equal(report.retryHttpStatus, 200);
    assert.equal(report.observedCountAfterRetry, 2);
    assert.equal(report.replayHttpStatus, 200);
    assert.equal(report.observedProcessedCount, 2);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('detects a precommit timeout receiver that reserves the ID without a committed effect', async () => {
  await withReceiver({ unsafeReservePrecommitTimeoutDedupe: true }, async (config) => {
    const result = await runLab({ ...config, timeoutBeforeCommit: true, timeoutMs: 800 },
      { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.equal(report.scenario, 'client_timeout_before_commit');
    assert.equal(report.firstAttemptOutcome, 'client_timeout');
    assert.equal(report.observedCountAfterTimeout, 1);
    assert.equal(report.observedProcessedCount, 1);
    assert.equal(report.expectedProcessedCount, 2);
    assert.equal(report.passed, false);
  });
});

test('detects a receiver that commits during the declared precommit timeout', async () => {
  await withReceiver({ unsafeCommitBeforePrecommitTimeout: true }, async (config) => {
    const result = await runLab({ ...config, timeoutBeforeCommit: true, timeoutMs: 800 },
      { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.equal(report.firstAttemptOutcome, 'client_timeout');
    assert.equal(report.observedCountAfterTimeout, 2);
    assert.equal(report.passed, false);
  });
});

test('detects a receiver that ignores the precommit timeout fault', async () => {
  await withReceiver({ supportPrecommitTimeoutFault: false }, async (config) => {
    const result = await runLab({ ...config, timeoutBeforeCommit: true, timeoutMs: 800 },
      { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.equal(report.firstAttemptOutcome, 'http_200');
    assert.equal(report.passed, false);
  });
});

test('timeout-before-commit option rejects malformed values before traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const timeoutBeforeCommit of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, timeoutBeforeCommit }, { secret }),
        /timeoutBeforeCommit/);
    }
    const response = await fetch(config.observer);
    assert.equal((await response.json()).processedCount, 0);
  });
});

test('precommit and postcommit timeouts use independent event IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({
      ...config, timeoutAfterCommit: true, timeoutBeforeCommit: true, timeoutMs: 800,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    assert.equal(result.scenarios.at(-2).scenario, 'client_timeout_after_commit');
    assert.equal(result.scenarios.at(-1).scenario, 'client_timeout_before_commit');
    assert.equal(result.scenarios.at(-1).observedCountAfterTimeout, 2);
    assert.equal(result.scenarios.at(-1).observedProcessedCount, 3);
  });
});
