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

test('CI evidence never exports a field with the wrong primitive type', () => {
  const report = {
    httpStatus: true,
    httpStatuses: [200, 'created'],
    retryAfterZero: 0,
    observedProcessedCount: false,
    expectedProcessedCount: 'missing',
    observedCounts: [1, true],
    observedResourceState: 200,
    expectedResourceState: false,
    observedResourceStates: ['created', 2],
    expectedResourceStates: ['activated', true],
    observedResourceVersion: true,
    expectedResourceVersion: 'created',
    observedResourceVersions: [1, 'missing'],
    expectedResourceVersions: [1, false],
  };
  assert.deepEqual(evidenceFor(report), {});
});

test('valid typed CI evidence remains unchanged', () => {
  const report = {
    httpStatus: 200, httpStatuses: [429, 200], retryAfterZero: false,
    observedProcessedCount: 2, expectedProcessedCount: 2, observedCounts: [1, 2],
    observedResourceState: 'activated', expectedResourceState: 'created',
    observedResourceStates: ['missing', 'created'], expectedResourceStates: ['created'],
    observedResourceVersion: 3, expectedResourceVersion: 3,
    observedResourceVersions: [1, 3], expectedResourceVersions: [3],
  };
  assert.deepEqual(evidenceFor(report), report);
});
