import test from 'node:test';
import assert from 'node:assert/strict';
import { startMock } from '../src/mock.mjs';
import { sign } from '../src/standard.mjs';

const secret = `whsec_${Buffer.alloc(32, 8).toString('base64')}`;

for (const [label, value] of [
  ['negative', -1], ['null', null], ['NaN', NaN], ['string', '60'],
  ['infinite', Infinity], ['negative infinite', -Infinity], ['boolean', false],
]) {
  test(`mock rejects ${label} retention before starting`, async () => {
    let receiver;
    try {
      await assert.rejects(async () => {
        receiver = await startMock({ secret, dedupeRetentionSeconds: value });
      }, { name: 'TypeError', message: /dedupeRetentionSeconds/ });
    } finally {
      if (receiver) await receiver.stop();
    }
  });
}

for (const [label, retention, expected] of [
  ['omitted', undefined, [1, 1, 1]], ['zero', 0, [1, 2, 3]],
  ['positive', 60, [1, 1, 2]],
]) {
  test(`mock preserves ${label} retention behavior`, async () => {
    const base = 1700000000;
    let now = base;
    const receiver = await startMock({ secret, clock: () => now,
      dedupeRetentionSeconds: retention });
    const id = 'evt_retention_config';
    const body = '{"x":1}';
    try {
      for (const [i, offset] of [0, 59, 60].entries()) {
        now = base + offset;
        const response = await fetch(receiver.config.endpoint, {
          method: 'POST', body, headers: {
            'content-type': 'application/json', 'webhook-id': id,
            'webhook-timestamp': String(now),
            'webhook-signature': sign({ secret, id, timestamp: now, body }),
          },
        });
        assert.equal(response.status, 200);
        await response.text();
        const state = await fetch(receiver.config.observer).then(r => r.json());
        assert.equal(state.processedCount, expected[i]);
      }
    } finally {
      await receiver.stop();
    }
  });
}
