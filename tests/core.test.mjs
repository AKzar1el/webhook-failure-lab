import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { keyFromSecret, sign, verify } from '../src/standard.mjs';
import { requireLoopbackUrl } from '../src/loopback.mjs';

const secret = `whsec_${randomBytes(32).toString('base64')}`;
const sample = { secret, id: 'evt_001', timestamp: 1700000000, body: '{"x":1}' };

test('signs in Standard Webhooks v1 format', () => {
  const signature = sign(sample);
  assert.match(signature, /^v1,[A-Za-z0-9+/]+=*$/);
  assert.equal(verify({ ...sample, signature, now: sample.timestamp }), true);
});
test('multi-signature header accepts any authentic v1 entry, not just the first', () => {
  const valid = sign(sample);
  const invalid = valid.slice(0, 3) + (valid[3] === 'A' ? 'B' : 'A') + valid.slice(4);
  const check = (signature) => verify({ ...sample, signature, now: sample.timestamp });
  assert.equal(check(`${invalid} ${valid}`), true);
  assert.equal(check(`${valid} ${invalid}`), true);
  assert.equal(check(`${invalid} ${invalid}`), false);
  assert.equal(check(`v2,ignored ${invalid}`), false);
  assert.equal(check(''), false);
});
test('tampered payload is rejected', () => {
  const signature = sign(sample);
  assert.equal(verify({ ...sample, body: '{"x":2}', signature, now: sample.timestamp }), false);
});
test('stale signed timestamp is rejected', () => {
  assert.equal(verify({ ...sample, signature: sign(sample), now: sample.timestamp + 3600 }), false);
});
test('bad signature and malformed secret fail closed', () => {
  assert.equal(verify({ ...sample, signature: 'v1,forged', now: sample.timestamp }), false);
  assert.throws(() => keyFromSecret('production-secret'));
  assert.throws(() => keyFromSecret('whsec_Zm9v'));
});
test('secret key length and base64 are validated', () => {
  assert.equal(keyFromSecret(secret).length, 32);
  assert.throws(() => keyFromSecret(secret + 'nope'));
});
test('allows only local HTTP loopback', () => {
  assert.equal(requireLoopbackUrl('http://127.0.0.1:3123/webhook'), 'http://127.0.0.1:3123/webhook');
  for (const url of ['https://example.com/', 'http://example.com/', 'http://127.0.0.2:3000/', 'file:///etc/passwd', 'http://user:pw@localhost:3000/', 'http://localhost:8080/#fragment']) {
    assert.throws(() => requireLoopbackUrl(url));
  }
});
