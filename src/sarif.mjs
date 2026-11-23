// SARIF 2.1.0 export of completed local receiver-contract checks.
// Emit only allowlisted numeric and synthetic-state observations; never payloads or keys.
import { evidenceFor } from './report-evidence.mjs';

function ruleId(scenario) {
  return 'WFL_' + scenario.replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase();
}

export function toSarif(result) {
  if (!result || !Array.isArray(result.scenarios) || result.scenarios.length === 0 ||
      typeof result.success !== 'boolean' ||
      // findIndex visits sparse holes; some skips them.
      result.scenarios.findIndex((item) => typeof item?.scenario !== 'string' ||
        typeof item.passed !== 'boolean') !== -1 ||
      result.success !== result.scenarios.every((item) => item.passed)) {
    throw new TypeError('SARIF export requires a completed webhook lab result');
  }

  const scenarios = [...new Set(result.scenarios.map((item) => item.scenario))];
  const rules = scenarios.map((scenario) => ({
    id: ruleId(scenario),
    shortDescription: { text: `Webhook receiver contract: ${scenario}` },
  }));
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length) {
    throw new TypeError('SARIF export requires unique scenario rule IDs');
  }
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

// A run that stopped before completing cannot claim any receiver contract results.
// Do not interpolate exception text: it may contain local URLs or secret-bearing input.
export function toSarifExecutionError() {
  return {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Webhook Failure Lab', rules: [] } },
      invocations: [{
        executionSuccessful: false,
        toolExecutionNotifications: [{
          level: 'error',
          message: { text: 'Webhook Failure Lab could not complete. Check local configuration and receiver availability; no contract outcome was established.' },
        }],
      }],
      results: [],
      properties: {
        coverage: [],
        caveat: 'The run did not complete; no receiver side-effect guarantee or scenario result is asserted.',
      },
    }],
  };
}
