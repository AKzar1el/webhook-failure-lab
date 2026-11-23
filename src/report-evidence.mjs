// Allowlist receiver-reported observations before exporting CI artifacts.
const evidenceFields = [
  'httpStatus', 'httpStatuses',
  'retryAfterZero',
  'observedProcessedCount', 'observedCounts', 'expectedProcessedCount',
  'observedResourceState', 'expectedResourceState',
  'observedResourceStates', 'expectedResourceStates',
  'observedResourceVersion', 'expectedResourceVersion',
  'observedResourceVersions', 'expectedResourceVersions',
];
const syntheticStates = new Set(['missing', 'created', 'activated']);
const stateFields = new Set([
  'observedResourceState', 'expectedResourceState',
  'observedResourceStates', 'expectedResourceStates',
]);
const listFields = new Set([
  'httpStatuses', 'observedCounts',
  'observedResourceStates', 'expectedResourceStates',
  'observedResourceVersions', 'expectedResourceVersions',
]);

export function evidenceFor(report) {
  const safeScalar = (field, value) => field === 'retryAfterZero'
    ? typeof value === 'boolean'
    : stateFields.has(field)
      ? typeof value === 'string' && syntheticStates.has(value)
      : Number.isSafeInteger(value);
  // findIndex visits missing array entries; every would allow null holes in exported JSON.
  const safeValue = (field, value) => listFields.has(field)
    ? Array.isArray(value) && value.length <= 16 &&
      value.findIndex((item) => !safeScalar(field, item)) === -1
    : safeScalar(field, value);
  return Object.fromEntries(evidenceFields
    .filter((field) => Object.hasOwn(report, field) && safeValue(field, report[field]))
    .map((field) => [field, report[field]]));
}
