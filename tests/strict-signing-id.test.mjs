import test from 'node:test';
import assert from 'node:assert/strict';
import { sign, verify } from '../src/standard.mjs';

const sample = {
  secret: `whsec_${Buffer.alloc(32, 7).toString('base64')}`,
  timestamp: 1760000000,
  body: '{"synthetic":true}',
};

for (const [label, id, wireId] of [
  ['number', 42, '42'],
  ['boolean', true, 'true'],
  ['array', ['evt_42'], 'evt_42'],
  ['bigint', 42n, '42'],
  ['boxed string', new String('evt_42'), 'evt_42'],
  ['object', { toString: () => 'evt_42' }, 'evt_42'],
]) {
  test(`sign rejects ${label} event IDs`, () => {
    assert.throws(() => sign({ ...sample, id }), TypeError);
  });
  test(`verify rejects ${label} even with matching coerced signature`, () => {
    const signature = sign({ ...sample, id: wireId });
    assert.equal(verify({ ...sample, id, signature, now: sample.timestamp }), false);
  });
}

test('stateful event ID coercion is never invoked by sign or verify', () => {
  let calls = 0;
  const id = { toString() { return ++calls === 1 ? 'evt_42' : 'invalid.id'; } };
  const signature = sign({ ...sample, id: 'evt_42' });
  assert.throws(() => sign({ ...sample, id }), TypeError);
  assert.equal(verify({ ...sample, id, signature, now: sample.timestamp }), false);
  assert.equal(calls, 0);
});

test('valid string identifiers retain their exact signing identity', () => {
  for (const id of ['42', 'true', 'evt_42', 'a-B_0']) {
    const signature = sign({ ...sample, id });
    assert.equal(verify({ ...sample, id, signature, now: sample.timestamp }), true);
    assert.equal(verify({ ...sample, id: `${id}x`, signature, now: sample.timestamp }), false);
  }
});
