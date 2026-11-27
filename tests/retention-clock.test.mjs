import test from 'node:test';
import assert from 'node:assert/strict';
import { sign } from '../src/standard.mjs';
import { startMock } from '../src/mock.mjs';

const secret = `whsec_${Buffer.alloc(32, 8).toString('base64')}`;
const base = 1700000000;
const body = '{"x":1}';

for (const verifySignatures of [true, false]) {
  for (const invalidClock of [Infinity, String(base + 1000), NaN, undefined]) {
    test(`invalid retention clock ${String(invalidClock)} preserves independent TTLs (verify=${verifySignatures})`, async () => {
      let now = base;
      const receiver = await startMock({ secret, verifySignatures,
        clock: () => now, dedupeRetentionSeconds: 600 });
      const send = async (id, timestamp) => {
        const response = await fetch(receiver.config.endpoint, {
          method: 'POST', headers: {
            'content-type': 'application/json', 'webhook-id': id,
            'webhook-timestamp': String(timestamp),
            'webhook-signature': sign({ secret, id, timestamp, body }),
          }, body,
        });
        await response.text();
        const state = await fetch(receiver.config.observer).then(r => r.json());
        return [response.status, state.processedCount];
      };
      try {
        assert.deepEqual(await send('evt_retention_a', base), [200, 1]);
        now = base + 1;
        assert.deepEqual(await send('evt_retention_b', now), [200, 2]);
        now = invalidClock;
        assert.deepEqual(await send('evt_retention_a', base + 1), [401, 2]);
        now = base + 599;
        assert.deepEqual(await send('evt_retention_a', now), [200, 2]);
        assert.deepEqual(await send('evt_retention_b', now), [200, 2]);
        now = base + 600;
        assert.deepEqual(await send('evt_retention_a', now), [200, 3]);
        assert.deepEqual(await send('evt_retention_b', now), [200, 3]);
        now = base + 601;
        assert.deepEqual(await send('evt_retention_b', now), [200, 4]);
      } finally {
        await receiver.stop();
      }
    });
  }
}
