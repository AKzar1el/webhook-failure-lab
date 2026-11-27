import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Isolate the receiver so an uncaught async callback failure cannot kill the
// test runner or be mistaken for a successful rejection.
for (const verifySignatures of [true, false]) {
  test(`throwing receiver clock rejects safely (verify=${verifySignatures})`, () => {
    const script = `
      import assert from 'node:assert/strict';
      import { sign } from './src/standard.mjs';
      import { startMock } from './src/mock.mjs';
      const secret = 'whsec_' + Buffer.alloc(32, 8).toString('base64');
      const now = 1700000000;
      const body = '{"x":1}';
      let failing = false;
      const receiver = await startMock({ secret, verifySignatures: ${verifySignatures},
        dedupeRetentionSeconds: 600, clock: () => {
          if (failing) throw new Error('synthetic private clock detail');
          return now;
        } });
      const send = async id => {
        const response = await fetch(receiver.config.endpoint, {
          method: 'POST', headers: {
            'content-type': 'application/json', 'webhook-id': id,
            'webhook-timestamp': String(now),
            'webhook-signature': sign({ secret, id, timestamp: now, body }),
          }, body, signal: AbortSignal.timeout(2000),
        });
        const responseBody = await response.text();
        assert.ok(!responseBody.includes('synthetic private clock detail'));
        const state = await fetch(receiver.config.observer, {
          signal: AbortSignal.timeout(2000),
        }).then(r => r.json());
        return [response.status, state.processedCount];
      };
      try {
        assert.deepEqual(await send('evt_clock_existing'), [200, 1]);
        failing = true;
        assert.deepEqual(await send('evt_clock_existing'), [401, 1]);
        assert.deepEqual(await send('evt_clock_new'), [401, 1]);
        failing = false;
        assert.deepEqual(await send('evt_clock_existing'), [200, 1]);
        assert.deepEqual(await send('evt_clock_new'), [200, 2]);
        assert.deepEqual(await send('evt_clock_new'), [200, 2]);
      } finally {
        await receiver.stop();
      }
    `;
    const child = spawnSync(process.execPath,
      ['--unhandled-rejections=strict', '--input-type=module', '--eval', script], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        encoding: 'utf8', timeout: 10000,
      });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.signal, null);
  });
}
