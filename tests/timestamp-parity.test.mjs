import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { sign, verify } from '../src/standard.mjs';

const key = Buffer.alloc(32, 11);
const sample = { secret: `whsec_${key.toString('base64')}`, id: 'evt_timestamp', body: '{}' };

for (const timestamp of [-1, -60, Number.MIN_SAFE_INTEGER]) {
  test(`sign rejects negative timestamp ${timestamp}`, () => {
    assert.throws(() => sign({ ...sample, timestamp }), TypeError);
  });

  test(`verify rejects negative timestamp ${timestamp} in both representations`, () => {
    const signature = `v1,${createHmac('sha256', key).update(`${sample.id}.${timestamp}.${sample.body}`).digest('base64')}`;
    for (const value of [timestamp, String(timestamp)]) {
      assert.equal(verify({ ...sample, timestamp: value, signature, now: timestamp }), false);
    }
  });
}

for (const timestamp of [0, 1, 1760000000, Number.MAX_SAFE_INTEGER]) {
  test(`canonical timestamp ${timestamp} has numeric/wire verification parity`, () => {
    const signature = sign({ ...sample, timestamp });
    for (const value of [timestamp, String(timestamp)]) {
      assert.equal(verify({ ...sample, timestamp: value, signature, now: timestamp }), true);
    }
    for (const value of [`0${timestamp}`, `${timestamp}.0`, `+${timestamp}`]) {
      assert.equal(verify({ ...sample, timestamp: value, signature, now: timestamp }), false);
    }
  });
}
