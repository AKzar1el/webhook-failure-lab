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

export function evidenceFor(report) {
  const safeScalar = (value) => typeof value === 'boolean' || Number.isSafeInteger(value) ||
    (typeof value === 'string' && syntheticStates.has(value));
  const safeValue = (value) => safeScalar(value) ||
    (Array.isArray(value) && value.length <= 16 && value.every(safeScalar));
  return Object.fromEntries(evidenceFields
    .filter((field) => Object.hasOwn(report, field) && safeValue(report[field]))
    .map((field) => [field, report[field]]));
}
