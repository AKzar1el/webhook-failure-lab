import { evidenceFor } from './report-evidence.mjs';

// JUnit XML intentionally exports only synthetic scenario IDs and allowlisted observations.
const declaration = '<?xml version="1.0" encoding="UTF-8"?>';
const caveat = 'Receiver-reported observations are not proof of external exactly-once business effects.';

function escapeXml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function safeScenario(value) {
  return /^[a-z][a-z0-9_]{0,95}$/.test(value) ? value : 'redacted_invalid_scenario';
}

function wrapSuite(tests, failures, errors, testCases) {
  return [
    declaration,
    `<testsuites tests="${tests}" failures="${failures}" errors="${errors}">`,
    `  <testsuite name="Webhook Failure Lab" tests="${tests}" failures="${failures}" errors="${errors}">`,
    ...testCases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}

export function toJunit(result) {
  if (!result || !Array.isArray(result.scenarios) ||
      typeof result.success !== 'boolean' ||
      result.scenarios.some((item) => typeof item?.scenario !== 'string' ||
        typeof item.passed !== 'boolean')) {
    throw new TypeError('JUnit export requires a completed webhook lab result');
  }

  const cases = result.scenarios.flatMap((report) => {
    const name = safeScenario(report.scenario);
    if (report.passed) {
      return [`    <testcase classname="WebhookFailureLab" name="${name}" />`];
    }
    const evidence = escapeXml(JSON.stringify(evidenceFor(report)));
    return [
      `    <testcase classname="WebhookFailureLab" name="${name}">`,
      `      <failure type="receiver-contract">Observed: ${evidence}. ${caveat}</failure>`,
      '    </testcase>',
    ];
  });
  const failures = result.scenarios.filter((report) => !report.passed).length;
  return wrapSuite(result.scenarios.length, failures, 0, cases);
}

// An incomplete run is a tool error, never evidence of an incorrect receiver.
export function toJunitExecutionError() {
  return wrapSuite(1, 0, 1, [
    '    <testcase classname="WebhookFailureLab" name="execution">',
    '      <error type="execution">Could not complete local webhook verification. Check configuration and receiver availability; no contract verdict established.</error>',
    '    </testcase>',
  ]);
}
