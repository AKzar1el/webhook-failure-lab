import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const demo = (args = []) => execFileAsync(process.execPath,
  ['scripts/demo.mjs', ...args], { timeout: 15000 });

test('demo runs the actual CLI against a healthy synthetic receiver', async () => {
  const { stdout, stderr } = await demo();
  const report = JSON.parse(stdout);
  assert.equal(report.success, true);
  assert.equal(report.scenarios.length, 4);
  assert.ok(report.scenarios.every(({ passed }) => passed));
  assert.doesNotMatch(stdout + stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
});

test('demo exposes duplicate processing and preserves CLI exit 1', async () => {
  await assert.rejects(demo(['--broken']), (error) => {
    assert.equal(error.code, 1);
    const report = JSON.parse(error.stdout);
    assert.equal(report.success, false);
    const duplicate = report.scenarios.find(({ scenario }) => scenario === 'duplicate_delivery');
    assert.equal(duplicate.passed, false);
    assert.equal(duplicate.expectedProcessedCount, 1);
    assert.equal(duplicate.observedProcessedCount, 2);
    assert.doesNotMatch(error.stdout + error.stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
    return true;
  });
});

test('demo rejects unknown arguments with exit 2 before starting', async () => {
  await assert.rejects(demo(['--unknown']), (error) => {
    assert.equal(error.code, 2);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /Usage:/);
    return true;
  });
});

test('demo produces a healthy JUnit report through the actual CLI', async () => {
  const { stdout, stderr } = await demo(['--format', 'junit']);
  assert.match(stdout, /<testsuites tests="4" failures="0" errors="0">/);
  assert.doesNotMatch(stdout + stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
});

test('demo preserves the broken receiver verdict in JUnit', async () => {
  await assert.rejects(demo(['--broken', '--format', 'junit']), (error) => {
    assert.equal(error.code, 1);
    assert.match(error.stdout, /name="duplicate_delivery">\s*<failure type="receiver-contract">/);
    assert.doesNotMatch(error.stdout + error.stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
    return true;
  });
});

test('demo produces healthy and broken SARIF reports with matching verdicts', async () => {
  const healthy = await demo(['--format', 'sarif']);
  const report = JSON.parse(healthy.stdout);
  assert.equal(report.version, '2.1.0');
  assert.equal(report.runs[0].invocations[0].executionSuccessful, true);
  assert.deepEqual(report.runs[0].results, []);
  await assert.rejects(demo(['--format', 'sarif', '--broken']), (error) => {
    assert.equal(error.code, 1);
    const run = JSON.parse(error.stdout).runs[0];
    assert.equal(run.invocations[0].executionSuccessful, true);
    assert.ok(run.results.some(({ ruleId, level }) => ruleId === 'WFL_DUPLICATE_DELIVERY' && level === 'error'));
    assert.doesNotMatch(healthy.stdout + healthy.stderr + error.stdout + error.stderr,
      /whsec_|webhook-signature|127\.0\.0\.1/);
    return true;
  });
});

test('demo explicit JSON format preserves default behavior', async () => {
  const { stdout } = await demo(['--format', 'json']);
  assert.equal(JSON.parse(stdout).success, true);
});

test('demo rejects missing, invalid and duplicate format options', async () => {
  for (const args of [['--format'], ['--format', 'xml'], ['--format', 'json', '--format', 'json'],
    ['--broken', '--broken'], ['--format', 'junit', '--unknown']]) {
    await assert.rejects(demo(args), (error) => {
      assert.equal(error.code, 2);
      assert.equal(error.stdout, '');
      assert.match(error.stderr, /Usage:/);
      return true;
    });
  }
});

test('lost-ack demo observes a committed effect before retry and no repeat effect', async () => {
  const { stdout, stderr } = await demo(['--lost-ack']);
  const report = JSON.parse(stdout);
  assert.equal(report.success, true);
  assert.equal(report.scenarios.length, 5);
  const lost = report.scenarios.find(({ scenario }) => scenario === 'lost_ack_after_commit');
  assert.equal(lost.passed, true);
  assert.equal(lost.firstAttemptOutcome, 'transport_error');
  assert.equal(lost.observedCountAfterLostAck, lost.expectedProcessedCount);
  assert.equal(lost.observedProcessedCount, lost.expectedProcessedCount);
  assert.doesNotMatch(stdout + stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
});

test('broken lost-ack demo isolates the lost dedupe record from baseline checks', async () => {
  await assert.rejects(demo(['--broken', '--lost-ack']), (error) => {
    assert.equal(error.code, 1);
    const report = JSON.parse(error.stdout);
    assert.equal(report.success, false);
    assert.equal(report.scenarios.length, 5);
    const failed = report.scenarios.filter(({ passed }) => !passed);
    assert.equal(failed.length, 1);
    assert.equal(failed[0].scenario, 'lost_ack_after_commit');
    assert.equal(failed[0].firstAttemptOutcome, 'transport_error');
    assert.equal(failed[0].observedCountAfterLostAck, failed[0].expectedProcessedCount);
    assert.equal(failed[0].observedProcessedCount, failed[0].expectedProcessedCount + 1);
    return true;
  });
});

test('lost-ack demo reports the isolated failure in JUnit and rejects duplicate flags', async () => {
  await assert.rejects(demo(['--lost-ack', '--broken', '--format', 'junit']), (error) => {
    assert.equal(error.code, 1);
    assert.match(error.stdout, /<testsuites tests="5" failures="1" errors="0">/);
    assert.match(error.stdout, /name="lost_ack_after_commit">\s*<failure type="receiver-contract">/);
    assert.doesNotMatch(error.stdout + error.stderr, /whsec_|webhook-signature|127\.0\.0\.1/);
    return true;
  });
  await assert.rejects(demo(['--lost-ack', '--lost-ack']), (error) => {
    assert.equal(error.code, 2);
    assert.equal(error.stdout, '');
    assert.match(error.stderr, /Usage:/);
    return true;
  });
});
