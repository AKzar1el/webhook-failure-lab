import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';
import { toSarif } from '../src/sarif.mjs';

const secret = 'whsec_' + randomBytes(32).toString('base64');

async function withReceiver(options, fn) {
  const receiver = await startMock({ secret, ...options });
  try { return await fn(receiver.config); }
  finally { await receiver.stop(); }
}

test('429 Retry-After: 0 leaves signed event retryable and exact replay idempotent', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterRateLimit: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    assert.ok(result.scenarios.slice(0, 4).every((report) => report.passed));
    const report = result.scenarios.at(-1);
    assert.equal(report.scenario, 'retry_after_rate_limit');
    assert.deepEqual(report.httpStatuses, [429, 200, 200]);
    assert.equal(report.retryAfterZero, true);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    assert.equal(report.expectedProcessedCount, 2);
  });
});

test('429 reservation poisons deduplication and is detected on same-ID retry', async () => {
  await withReceiver({ unsafeReserveRateLimitedId: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRateLimit: true }, { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.deepEqual(report.httpStatuses, [429, 200, 200]);
    assert.deepEqual(report.observedCounts, [1, 1, 1]);
    assert.equal(report.passed, false);
  });
});

test('429 must not conceal an effect committed before throttling', async () => {
  await withReceiver({ unsafeCommitRateLimitedBeforeReject: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRateLimit: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).observedCounts, [2, 2, 2]);
  });
});

test('ignored explicit rate-limit adapter does not count as rate-limit coverage', async () => {
  await withReceiver({ supportRateLimitFault: false }, async (config) => {
    const result = await runLab({ ...config, retryAfterRateLimit: true }, { secret });
    assert.equal(result.success, false);
    assert.deepEqual(result.scenarios.at(-1).httpStatuses, [200, 200, 200]);
  });
});

test('429 without declared Retry-After fails the opt-in local throttle contract', async () => {
  await withReceiver({ unsafeOmitRateLimitRetryAfter: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterRateLimit: true }, { secret });
    const report = result.scenarios.at(-1);
    assert.equal(result.success, false);
    assert.equal(report.retryAfterZero, false);
    assert.deepEqual(report.observedCounts, [1, 2, 2]);
    const findings = toSarif(result).runs[0].results;
    assert.equal(findings.length, 1);
    assert.match(findings[0].message.text, /"retryAfterZero":false/);
    assert.ok(!findings[0].message.text.includes('webhook-signature'));
  });
});

test('rate-limit option rejects nonboolean values before loopback traffic', async () => {
  await withReceiver({}, async (config) => {
    for (const retryAfterRateLimit of [0, 1, 'true', null, [], {}]) {
      let requested = false;
      await assert.rejects(() => runLab({ ...config, retryAfterRateLimit }, {
        secret, request: () => { requested = true; throw new Error('unexpected request'); },
      }), /retryAfterRateLimit/);
      assert.equal(requested, false);
    }
  });
});

test('rate-limit retry composes with precommit 503 using separate signed IDs', async () => {
  await withReceiver({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true,
      retryAfterRateLimit: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    const probe = result.scenarios.at(-1);
    assert.equal(probe.scenario, 'retry_after_rate_limit');
    assert.deepEqual(probe.observedCounts, [2, 3, 3]);
  });
});
