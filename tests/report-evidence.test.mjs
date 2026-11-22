import test from 'node:test';
import assert from 'node:assert/strict';
import { evidenceFor } from '../src/report-evidence.mjs';

test('sparse observation arrays are not exported as null-valued evidence', () => {
  const report = { httpStatuses: [200, , 503], observedCounts: [1, 2] };
  assert.deepEqual(evidenceFor(report), { observedCounts: [1, 2] });
});

test('dense bounded observations remain in evidence', () => {
  const report = { httpStatuses: [200, 503], observedResourceState: 'created' };
  assert.deepEqual(evidenceFor(report), report);
});
