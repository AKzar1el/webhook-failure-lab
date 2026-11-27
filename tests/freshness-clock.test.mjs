import test from 'node:test';
import assert from 'node:assert/strict';
import { sign, verify } from '../src/standard.mjs';
import { startMock } from '../src/mock.mjs';

const secret = `whsec_${Buffer.alloc(32, 7).toString('base64')}`;
const timestamp = 1700000000;
const sample = { secret, id: 'evt_clock', timestamp, body: '{"x":1}' };
const signature = sign(sample);

test('invalid clock values fail closed without coercion', () => {
  for (const now of [NaN, Infinity, -Infinity, null, '1700000000', {}, Symbol('clock')]) {
    assert.equal(verify({ ...sample, signature, now }), false, String(now));
  }
});

test('invalid tolerances fail closed without coercion', () => {
  for (const tolerance of [NaN, -Infinity, -1, null, '300', {}, Symbol('tolerance')]) {
    assert.equal(verify({ ...sample, signature, now: timestamp, tolerance }), false, String(tolerance));
  }
});

test('freshness boundaries and deliberate fixture opt-out remain intact', () => {
  for (const delta of [-300, 0, 300]) {
    assert.equal(verify({ ...sample, signature, now: timestamp + delta }), true);
  }
  for (const delta of [-301, 301]) {
    assert.equal(verify({ ...sample, signature, now: timestamp + delta }), false);
  }
  assert.equal(verify({ ...sample, signature, now: timestamp, tolerance: 0 }), true);
  assert.equal(verify({ ...sample, signature, now: timestamp + 3600, tolerance: Infinity }), true);
  assert.equal(verify({ ...sample, signature, now: NaN, tolerance: Infinity }), false);
});

test('invalid receiver clock rejects stale signature before effects; recovered same-ID retry dedupes', async () => {
  let now = NaN;
  const receiver = await startMock({ secret, clock: () => now });
  try {
    const send = async (ts) => {
      const response = await fetch(receiver.config.endpoint, {
        method: 'POST', headers: {
          'content-type': 'application/json', 'webhook-id': sample.id,
          'webhook-timestamp': String(ts),
          'webhook-signature': sign({ ...sample, timestamp: ts }),
        }, body: sample.body,
      });
      await response.text();
      const state = await fetch(receiver.config.observer).then(r => r.json());
      return [response.status, state.processedCount];
    };
    assert.deepEqual(await send(timestamp - 3600), [401, 0]);
    now = timestamp;
    assert.deepEqual(await send(timestamp), [200, 1]);
    assert.deepEqual(await send(timestamp), [200, 1]);
  } finally {
    await receiver.stop();
  }
});
