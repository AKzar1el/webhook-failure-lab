import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runLab } from '../src/run.mjs';
import { startMock } from '../src/mock.mjs';

test('opt-in probes use the validated config snapshot throughout an async run', async () => {
  const secret = 'whsec_' + randomBytes(32).toString('base64');
  const baseline = ['valid_delivery', 'duplicate_delivery', 'tampered_body', 'stale_timestamp'];
  const optional = ['malformed_signed_payload_retry', 'versioned_out_of_order_update'];

  for (const initiallyEnabled of [false, true]) {
    const receiver = await startMock({ secret });
    try {
      const config = { ...receiver.config,
        rejectMalformedSignedPayload: initiallyEnabled,
        versionedOutOfOrderUpdates: initiallyEnabled };
      let changed = false;
      const result = await runLab(config, { secret, request: (url, init) => {
        if (!changed) {
          changed = true;
          // A caller can reuse or update config while the first observer awaits.
          config.rejectMalformedSignedPayload = !initiallyEnabled;
          config.versionedOutOfOrderUpdates = !initiallyEnabled;
        }
        return fetch(url, init);
      } });

      assert.equal(changed, true);
      assert.equal(result.success, true);
      assert.deepEqual(result.scenarios.map(({ scenario }) => scenario),
        initiallyEnabled ? [...baseline, ...optional] : baseline);
    } finally {
      await receiver.stop();
    }
  }
});
