import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('invalid HTTP request targets receive a bounded sanitized rejection without killing receiver', () => {
  const script = `
    import assert from 'node:assert/strict';
    import { createConnection } from 'node:net';
    import { sign } from './src/standard.mjs';
    import { startMock } from './src/mock.mjs';
    const secret = 'whsec_' + Buffer.alloc(32, 9).toString('base64');
    const now = 1700000000;
    const receiver = await startMock({ secret, clock: () => now });
    const port = Number(new URL(receiver.config.endpoint).port);
    const raw = (method, target) => new Promise((resolve, reject) => {
      let response = '';
      const socket = createConnection({ host: '127.0.0.1', port });
      socket.setEncoding('utf8');
      socket.setTimeout(2000, () => socket.destroy(new Error('response timeout')));
      socket.once('error', reject);
      socket.on('data', chunk => { response += chunk; });
      socket.once('end', () => resolve(response));
      socket.once('connect', () => socket.write(method + ' ' + target +
        ' HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\nContent-Length: 0\\r\\n\\r\\n'));
    });
    const count = async () => (await fetch(receiver.config.observer,
      { signal: AbortSignal.timeout(2000) }).then(r => r.json())).processedCount;
    try {
      for (const [method, target] of [['GET', '//['], ['POST', 'http://[']]) {
        const response = await raw(method, target);
        assert.match(response, /^HTTP\\/1\\.1 400 /);
        assert.ok(!response.includes('ERR_INVALID_URL'));
        assert.ok(!response.includes(target));
        assert.equal(await count(), 0);
      }
      const id = 'evt_target_recovery', body = '{"x":1}';
      const send = () => fetch(receiver.config.endpoint, {
        method: 'POST', headers: {
          'content-type': 'application/json', 'webhook-id': id,
          'webhook-timestamp': String(now),
          'webhook-signature': sign({ secret, id, timestamp: now, body }),
        }, body, signal: AbortSignal.timeout(2000),
      });
      for (let i = 0; i < 2; i++) {
        const response = await send();
        assert.equal(response.status, 200);
        await response.text();
        assert.equal(await count(), 1);
      }
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
