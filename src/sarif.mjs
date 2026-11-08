// SARIF 2.1.0 export of completed local receiver-contract checks.
// Emit only allowlisted numeric and synthetic-state observations; never payloads or keys.
const evidenceFields = [
  'httpStatus', 'httpStatuses',
  'observedProcessedCount', 'observedCounts', 'expectedProcessedCount',
  'observedResourceState', 'expectedResourceState',
  'observedResourceStates', 'expectedResourceStates',
  'observedResourceVersion', 'expectedResourceVersion',
  'observedResourceVersions', 'expectedResourceVersions',
];
const syntheticStates = new Set(['missing', 'created', 'activated']);

function ruleId(scenario) {
  return 'WFL_' + scenario.replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase();
}

function evidenceFor(report) {
  const safeScalar = (value) => Number.isSafeInteger(value) ||
    (typeof value === 'string' && syntheticStates.has(value));
  const safeValue = (value) => safeScalar(value) ||
    (Array.isArray(value) && value.length <= 16 && value.every(safeScalar));
  return Object.fromEntries(evidenceFields
    .filter((field) => Object.hasOwn(report, field) && safeValue(report[field]))
    .map((field) => [field, report[field]]));
}

export function toSarif(result) {
  if (!result || !Array.isArray(result.scenarios) ||
      typeof result.success !== 'boolean' ||
      result.scenarios.some((item) => typeof item?.scenario !== 'string' ||
        typeof item.passed !== 'boolean')) {
    throw new TypeError('SARIF export requires a completed webhook lab result');
  }

  const scenarios = [...new Set(result.scenarios.map((item) => item.scenario))];
  const rules = scenarios.map((scenario) => ({
    id: ruleId(scenario),
    shortDescription: { text: `Webhook receiver contract: ${scenario}` },
  }));
  const results = result.scenarios.filter((report) => !report.passed).map((report) => ({
    ruleId: ruleId(report.scenario),
    level: 'error',
    message: { text: `Local webhook receiver failed ${report.scenario}. ` +
      `Observed receiver-reported values: ${JSON.stringify(evidenceFor(report))}. ` +
      'The observer does not prove external exactly-once business effects.' },
  }));

  return {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Webhook Failure Lab', rules } },
      invocations: [{ executionSuccessful: true }],
      results,
      properties: {
        coverage: scenarios,
        caveat: result.caveat,
      },
    }],
  };
}
