import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

const secret = `whsec_${randomBytes(32).toString('base64')}`;

async function withServer(options, fn) {
  const server = await startMock({ secret, ...options });
  try { return await fn(server.config); }
  finally { await server.stop(); }
}

test('four scenarios pass with secure idempotent receiver', async () => {
  await withServer({}, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 4);
    assert.ok(result.scenarios.every((r) => r.passed));
  });
});
test('detects duplicate processing', async () => {
  await withServer({ dedupe: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'duplicate_delivery' && !r.passed));
  });
});
test('detects receiver accepting invalid signatures', async () => {
  await withServer({ verifySignatures: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'tampered_body' && !r.passed));
  });
});
test('rejects remote endpoints even when supplied via config', async () => {
  await assert.rejects(() => runLab({ endpoint: 'https://example.com/', observer: 'http://localhost:3000/state' }, { secret }));
});
test('rejects status misconfiguration', async () => {
  await withServer({}, async (config) => {
    await assert.rejects(() => runLab({ ...config, timeoutMs: 60000 }, { secret }));
    await assert.rejects(() => runLab({ ...config, rejectionStatuses: [] }, { secret }));
  });
});
test('detects receiver accepting stale signed timestamps', async () => {
  await withServer({ verifyFreshness: false }, async (config) => {
    const result = await runLab(config, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.some((r) => r.scenario === 'stale_timestamp' && !r.passed));
  });
});

test('opt-in concurrent duplicate deliveries preserve a single observable effect', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const race = result.scenarios.find((r) => r.scenario === 'concurrent_duplicate_delivery');
    assert.equal(race.passed, true);
    assert.deepEqual(race.httpStatuses, [200, 200, 200, 200]);
    assert.equal(race.expectedProcessedCount, 2);
    assert.equal(race.observedProcessedCount, 2);
  });
});

test('concurrent duplicate check exposes non-atomic deduplication missed by sequential tests', async () => {
  await withServer({ unsafeConcurrentDedupe: true }, async (config) => {
    const result = await runLab({ ...config, concurrentDuplicateDeliveries: 4 }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const race = result.scenarios.find((r) => r.scenario === 'concurrent_duplicate_delivery');
    assert.equal(race.passed, false);
    assert.equal(race.expectedProcessedCount, 2);
    assert.equal(race.observedProcessedCount, 5);
  });
});

test('concurrent duplicate delivery count must be an integer between two and eight', async () => {
  await withServer({}, async (config) => {
    for (const concurrentDuplicateDeliveries of [-1, 0, 1, 9, 2.5, '4', true]) {
      await assert.rejects(() => runLab({ ...config, concurrentDuplicateDeliveries }, { secret }),
        /concurrentDuplicateDeliveries/);
    }
  });
});

test('opt-in transient failure retries the same signed delivery once and commits only on success', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 5);
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, true);
    assert.deepEqual(retry.httpStatuses, [503, 200]);
    assert.equal(retry.observedCountAfterFailure, 1);
    assert.equal(retry.observedProcessedCount, 2);
    assert.equal(retry.expectedProcessedCount, 2);
  });
});

test('retry check catches a receiver that marks a failed delivery as already processed', async () => {
  await withServer({ unsafeMarkFailedRetrySeen: true }, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, false);
    assert.deepEqual(retry.httpStatuses, [503, 200]);
    assert.equal(retry.observedCountAfterFailure, 1);
    assert.equal(retry.observedProcessedCount, 1);
    assert.equal(retry.expectedProcessedCount, 2);
  });
});

test('retry check rejects a receiver that ignores the explicit local fault injection', async () => {
  await withServer({ supportRetryFault: false }, async (config) => {
    const result = await runLab({ ...config, retryAfterTransientFailure: true }, { secret });
    assert.equal(result.success, false);
    assert.ok(result.scenarios.slice(0, 4).every((r) => r.passed));
    const retry = result.scenarios.find((r) => r.scenario === 'retry_after_transient_failure');
    assert.equal(retry.passed, false);
    assert.deepEqual(retry.httpStatuses, [200, 200]);
    assert.equal(retry.observedProcessedCount, 2);
  });
});

test('retry scenario requires a boolean opt-in before sending any request', async () => {
  await withServer({}, async (config) => {
    for (const retryAfterTransientFailure of [1, 0, 'true', null, [], {}]) {
      await assert.rejects(() => runLab({ ...config, retryAfterTransientFailure }, { secret }),
        /retryAfterTransientFailure/);
    }
  });
});

test('retry check composes with concurrent duplicates without reusing an event ID', async () => {
  await withServer({}, async (config) => {
    const result = await runLab({
      ...config, concurrentDuplicateDeliveries: 4, retryAfterTransientFailure: true,
    }, { secret });
    assert.equal(result.success, true);
    assert.equal(result.scenarios.length, 6);
    const retry = result.scenarios.at(-1);
    assert.equal(retry.scenario, 'retry_after_transient_failure');
    assert.equal(retry.expectedCountAfterFailure, 2);
    assert.equal(retry.observedCountAfterFailure, 2);
    assert.equal(retry.expectedProcessedCount, 3);
    assert.equal(retry.observedProcessedCount, 3);
  });
});
