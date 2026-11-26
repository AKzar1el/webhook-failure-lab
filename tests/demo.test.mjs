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
